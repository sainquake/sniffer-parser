"""Momentarily overlay the cabin horn input in a live CANopen TPDO1 stream.

This is an active CAN tool. It must only be used on equipment where the user is
authorized to transmit and where sounding the horn is safe.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Sequence


DEFAULT_NODE_ID = 6  # D552
DEFAULT_BITRATE = 500_000
HORN_PIN = 10
HORN_MASK = 1 << (HORN_PIN - 1)
GS_USB_ALIASES = {"canable": "gs_usb", "candlelight": "gs_usb"}


def node_id_value(value: str) -> int:
    try:
        node_id = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("node ID must be an integer") from error
    if not 1 <= node_id <= 127:
        raise argparse.ArgumentTypeError("node ID must be in the range 1..127")
    return node_id


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def normalize_interface(interface: str) -> str:
    normalized = interface.strip().lower()
    return GS_USB_ALIASES.get(normalized, normalized)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Emulate a momentary press of cabin horn switch S186-A3 by "
            "overlaying pin 10 in a CANopen TPDO1 payload."
        ),
        epilog=(
            "The tool transmits on a live CAN bus. Do not run it alongside a "
            "separate process that owns the same CAN adapter."
        ),
    )
    parser.add_argument(
        "--node-id",
        "--source-node-id",
        dest="node_id",
        type=node_id_value,
        default=DEFAULT_NODE_ID,
        help="emulated CANopen TPDO1 source node (default: 6 / D552)",
    )
    parser.add_argument(
        "--duration",
        type=positive_float,
        default=0.6,
        help="requested horn press duration in seconds (default: 0.6)",
    )
    parser.add_argument(
        "--interface",
        default="gs_usb",
        help="python-can interface; canable/candlelight are aliases for gs_usb",
    )
    parser.add_argument(
        "--channel",
        default="0",
        help="adapter channel/index, e.g. 0 for gs_usb or COM5 for slcan",
    )
    parser.add_argument(
        "--bitrate",
        type=int,
        default=DEFAULT_BITRATE,
        help="CAN bitrate in bit/s (default: 500000)",
    )
    parser.add_argument(
        "--wait-timeout",
        type=positive_float,
        default=2.0,
        help="maximum wait for the first TPDO1 frame (default: 2.0)",
    )
    parser.add_argument(
        "--transmit",
        action="store_true",
        help="required acknowledgement that this command actively transmits",
    )
    return parser


def normalize_channel(interface: str, channel: str) -> int | str:
    if interface == "gs_usb":
        try:
            return int(channel, 0)
        except ValueError as error:
            raise ValueError("gs_usb channel must be an integer index") from error
    return channel


def configure_gs_usb_discovery() -> int:
    """Make gs-usb use the bundled libusb backend available on Windows."""
    try:
        import libusb_package
        from gs_usb.gs_usb import GsUsb
    except ImportError as error:
        raise RuntimeError(
            "GS-USB dependencies are missing; install requirements.txt"
        ) from error

    def scan(cls):
        raw_devices = libusb_package.find(
            find_all=True,
            custom_match=cls.is_gs_usb_device,
        )
        return [cls(device) for device in raw_devices]

    # python-can imports this same class and calls GsUsb.scan() internally.
    GsUsb.scan = classmethod(scan)
    return len(GsUsb.scan())


def is_target_tpdo(message, cob_id: int) -> bool:
    return (
        message.arbitration_id == cob_id
        and not message.is_extended_id
        and not message.is_remote_frame
        and not message.is_error_frame
        and message.dlc >= 2
        and message.is_rx
    )


def pressed_payload(data: bytes) -> bytes:
    if len(data) < 2:
        raise ValueError("TPDO1 payload must contain at least two bytes")
    payload = bytearray(data)
    digital_inputs = int.from_bytes(payload[:2], byteorder="little")
    payload[:2] = (digital_inputs | HORN_MASK).to_bytes(2, byteorder="little")
    return bytes(payload)


def emulate_horn(bus, node_id: int, duration: float, wait_timeout: float) -> int:
    try:
        import can
    except ImportError as error:
        raise RuntimeError("python-can is not installed") from error

    cob_id = 0x180 + node_id
    first_deadline = time.monotonic() + wait_timeout
    first_frame = None
    while first_frame is None:
        remaining = first_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"no TPDO1 frame received on COB-ID 0x{cob_id:03X}")
        message = bus.recv(timeout=min(0.1, remaining))
        if message is not None and is_target_tpdo(message, cob_id):
            first_frame = message

    started = time.monotonic()
    deadline = started + duration
    sent = 0
    current = first_frame

    while True:
        overlay = can.Message(
            arbitration_id=cob_id,
            is_extended_id=False,
            data=pressed_payload(bytes(current.data)),
        )
        bus.send(overlay, timeout=0.1)
        sent += 1

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        current = None
        while current is None and remaining > 0:
            message = bus.recv(timeout=min(0.1, remaining))
            if message is not None and is_target_tpdo(message, cob_id):
                current = message
                break
            remaining = deadline - time.monotonic()
        if current is None:
            break

    # Do not forge a release frame: the real producer remains authoritative.
    # Its next TPDO1 restores the actual switch state without clearing a real press.
    return sent


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.transmit:
        parser.error("active transmission requires --transmit")

    try:
        import can
    except ImportError:
        print("error: python-can is not installed", file=sys.stderr)
        return 2

    try:
        interface = normalize_interface(args.interface)
        channel = normalize_channel(interface, args.channel)
        if interface == "gs_usb":
            devices_found = configure_gs_usb_discovery()
            if not isinstance(channel, int) or channel >= devices_found:
                raise ValueError(
                    f"Cannot find GS-USB device index {channel}. Devices found: {devices_found}"
                )
        cob_id = 0x180 + args.node_id
        print(
            f"Active CAN transmission: interface={interface} channel={channel} "
            f"bitrate={args.bitrate} source-node={args.node_id} COB-ID=0x{cob_id:03X}",
            file=sys.stderr,
        )
        with can.Bus(
            interface=interface,
            channel=channel,
            bitrate=args.bitrate,
            receive_own_messages=False,
        ) as bus:
            sent = emulate_horn(
                bus,
                node_id=args.node_id,
                duration=args.duration,
                wait_timeout=args.wait_timeout,
            )
        print(f"Horn overlay complete: sent {sent} pressed TPDO1 frame(s)")
        return 0
    except (ValueError, RuntimeError, TimeoutError, can.CanError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
