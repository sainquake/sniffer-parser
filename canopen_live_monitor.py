"""Live CANopen monitor with raw JSONL logging and a stable console dashboard."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from can_dump import (
    InitializationError,
    bitrate_list,
    bitrate_value,
    btr_value,
    non_negative_float,
    open_reader,
    positive_float,
    positive_int,
)
from can_log import DetectingStderr, frame_to_record, make_log_path, safe_log_name, write_jsonl
from canopen_decode import HEARTBEAT_STATES, decode_frame


NODE_NAMES = {
    1: "D550",
    4: "D551",
    5: "D553",
    6: "D552",
    7: "D554",
    16: "CPU1",
    17: "CPU3",
    19: "CPU2",
}

IO_TPDO1_SIGNALS = {
    1: {
        1: "B379 OPERATOR IN CHAIR",
        2: "GND",
        3: "S139-50 SWITCH IGNITION KEY START",
        4: "S139-15 SWITCH IGNITION KEY IGNITION",
        5: "GND",
        6: "GND",
        7: "Y179A HOLD MAGNET DRILL LEVER ROTATION",
        8: "Y179B HOLD MAGNET DRILL LEVER FEED",
        9: "S446A SWITCH IMPACT PRESSURE LOW",
        10: "S446B SWITCH IMPACT PRESSURE HIGH",
        11: "S452 SWITCH RAPID FEED THREADING",
        12: "S453 SWITCH MAGNETS OFF DRILL LEVER",
        13: "GND",
        14: "GND",
        15: "H452 LED GREEN RAPID/DRILL FEED",
        16: "H446 LED YELLOW IMPACT PRESSURE",
    },
    4: {
        1: "S100-A3 SWITCH FLUSH AIR",
        2: "S111-64 MANIPULATOR RHS ARM TO CAROUSEL",
        3: "S111-24 MANIPULATOR RHS ARM TO DRILL CENTER",
        4: "S111-54 MANIPULATOR RHS CAROUSEL ROT. CW",
        5: "S111-34 MANIPULATOR RHS CAROUSEL ROT. CCW",
        6: "S111-4 MANIPULATOR RHS OPEN GRIPPER",
        7: "S119-A1 SWITCH DRILL SUPPORT UPPER OPEN",
        8: "S119-A3 SWITCH DRILL SUPPORT UPPER CLOSE",
        9: "S113-A3 SWITCH TAKE UP ROD STRING",
        10: "S167-A1 SWITCH HOOD UP",
        11: "S167-A3 SWITCH HOOD DOWN",
        12: "S181-A3 SWITCH OPEN DCT HATCH",
        13: "S182-A3 SWITCH SLEEVE RETAINER",
        14: "S187-A1 SWITCH DRILL SUPPORT LOWER OPEN",
        15: "S187-A3 SWITCH DRILL SUPPORT LOWER CLOSE",
        16: "S257A3 SWITCH ROC DRILL LOCK ROTATION",
    },
    5: {
        1: "S258-A1 SWITCH WRENCH CCW",
        2: "S258-A3 SWITCH WRENCH CW",
        3: "S259-A3 SWITCH BRAKE LOWER OPEN/CLOSE",
        4: "S260-A3 SWITCH BRAKE UPPER OPEN/CLOSE",
        5: "GND",
        6: "GND",
        7: "S400-A3 SWITCH STROKE POSITION IMPACT",
        8: "GND",
        9: "GND",
        10: "GND",
        11: "GND",
        12: "GND",
        13: "S174A JOYSTICK TRAMMING LEFT",
        14: "S175A JOYSTICK TRAMMING RIGHT",
        15: "GND",
        16: "GND",
    },
    6: {
        1: "S130-1 SWITCH DRILL MODE",
        2: "S130-3 SWITCH TRAMMING LOW SPEED",
        3: "S130-5 SWITCH TRAMMING HIGH SPEED",
        4: "S130-7 SWITCH PREHEATING POSITION",
        5: "S176-A1 SWITCH TRACK OSCILLATION TILT LEFT FW",
        6: "S176-A3 SWITCH TRACK OSCILLATION TILT LEFT BW",
        7: "S177-A1 SWITCH TRACK OSCILLATION TILT RIGHT FW",
        8: "S177-A3 SWITCH TRACK OSCILLATION TILT RIGHT BW",
        9: "S180-A3 SWITCH COMPRESSOR LOAD",
        10: "S186-A3 SWITCH WARNING SIGNAL CABIN",
        11: "S209-A1 SWITCH HYDRAULIC JACK IN",
        12: "S209-A3 SWITCH HYDRAULIC JACK OUT",
        13: "GND",
        14: "GND",
        15: "GND",
        16: "GND",
    },
    7: {
        1: "GND",
        2: "S445-A3 SWITCH TRACK OSCILLATION FLOATING",
        3: "S448-A1 SWITCH WATERMIST MAN",
        4: "S448-43 SWITCH WATERMIST AUTO",
        5: "GND",
        6: "GND",
        7: "GND",
        8: "GND",
        9: "S449-A3 SWITCH BRUSH GREASING MAN",
        10: "S449-A3 SWITCH BRUSH GREASING AUTO",
        11: "S189-A3 SWITCH ENGINE SPEED INC",
        12: "S189-A1 SWITCH ENGINE SPEED DEC",
        13: "GND",
        14: "GND",
        15: "DELAYED ENGINE SHUTDOWN (DES), K303 IN A1",
        16: "GND",
    },
}


@dataclass
class PdoState:
    service: str
    number: int
    data: bytes = b""
    count: int = 0
    changed_count: int = 0
    last_seen: float = 0.0


@dataclass
class NodeState:
    node_id: int
    name: str
    heartbeat: str = "-"
    heartbeat_seen: float = 0.0
    pdo: dict[tuple[str, int], PdoState] = field(default_factory=dict)


@dataclass
class MonitorState:
    started: float = field(default_factory=time.time)
    frames: int = 0
    comments: int = 0
    services: Counter[str] = field(default_factory=Counter)
    nodes: dict[int, NodeState] = field(default_factory=dict)
    last_frame: str = "-"
    last_error: str = ""

    def node(self, node_id: int) -> NodeState:
        if node_id not in self.nodes:
            self.nodes[node_id] = NodeState(node_id=node_id, name=NODE_NAMES.get(node_id, f"node {node_id}"))
        return self.nodes[node_id]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Log raw CAN frames and show a stable live CANopen signal dashboard."
    )
    parser.add_argument("log_name", nargs="?", type=safe_log_name, default="canopen_live")
    parser.add_argument("--logs-dir", type=Path, default=Path("logs"))
    parser.add_argument(
        "--device",
        "--adapter",
        dest="device",
        choices=("zubax", "raccoonlab", "slcan", "candlelight", "canable", "gs_usb"),
        help="same adapter selector as can_log.py",
    )
    parser.add_argument("--channel", help="COM port or GS-USB index; default: 0")
    speed_group = parser.add_mutually_exclusive_group()
    speed_group.add_argument("--bitrate", type=bitrate_value, default="auto")
    speed_group.add_argument("--btr", type=btr_value)
    parser.add_argument(
        "--bitrates",
        type=bitrate_list,
        default=(1_000_000, 800_000, 500_000, 250_000, 125_000, 100_000, 50_000, 20_000, 10_000),
    )
    parser.add_argument("--autodetect-window", type=positive_float, default=0.5)
    parser.add_argument("--tty-baudrate", type=positive_int, default=None)
    parser.add_argument("--recv-timeout", type=non_negative_float, default=0.1)
    parser.add_argument("--flush-every", type=positive_int, default=100)
    parser.add_argument("--refresh", type=positive_float, default=0.2)
    parser.add_argument("--playback-log", type=Path, help="read an existing can_log.py JSONL file instead of CAN hardware")
    parser.add_argument("--playback-speed", type=positive_float, default=0.0, help="seconds between playback frames; 0 is as fast as possible")
    parser.add_argument("--no-screen", action="store_true", help="log/decode without drawing the dashboard")
    return parser


def parse_data(record: dict[str, Any]) -> bytes:
    raw = record.get("data")
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return b""
    data_bytes = record.get("data_bytes")
    if isinstance(data_bytes, list):
        try:
            return bytes(int(item) & 0xFF for item in data_bytes)
        except (TypeError, ValueError):
            return b""
    return b""


def frame_label(record: dict[str, Any]) -> str:
    data = parse_data(record)
    can_id = record.get("id", "?")
    return f"{can_id} DLC={record.get('dlc', len(data))} DATA={data.hex(' ').upper()}"


def update_state(state: MonitorState, record: dict[str, Any]) -> None:
    state.frames += 1
    state.last_frame = frame_label(record)
    try:
        event = decode_frame(record)
    except Exception as error:
        state.last_error = f"decode error: {error}"
        return

    service = str(event.get("service", "unknown"))
    state.services[service] += 1
    node_id = event.get("node_id")
    if not isinstance(node_id, int):
        return

    node = state.node(node_id)
    now = time.time()

    if service == "heartbeat":
        state_byte = event.get("state")
        if isinstance(state_byte, int):
            node.heartbeat = HEARTBEAT_STATES.get(state_byte, f"0x{state_byte:02X}")
        else:
            node.heartbeat = str(event.get("state_name") or "?")
        node.heartbeat_seen = now
        return

    if service not in ("TPDO", "RPDO"):
        return

    number = event.get("pdo_number")
    if not isinstance(number, int):
        return
    key = (service, number)
    payload = parse_data(record)
    pdo = node.pdo.get(key)
    if pdo is None:
        pdo = PdoState(service=service, number=number)
        node.pdo[key] = pdo
    if pdo.data != payload and pdo.count:
        pdo.changed_count += 1
    pdo.data = payload
    pdo.count += 1
    pdo.last_seen = now


def bit_state(data: bytes, bit_index: int) -> bool:
    byte_index = bit_index // 8
    if byte_index >= len(data):
        return False
    return bool(data[byte_index] & (1 << (bit_index % 8)))


def age_text(last_seen: float, now: float) -> str:
    if not last_seen:
        return "-"
    age = max(0.0, now - last_seen)
    if age < 10:
        return f"{age:4.1f}s"
    return f"{age:4.0f}s"


def short(text: str, width: int) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "~"


def render_dashboard(state: MonitorState, log_path: Path, width: int, height: int) -> str:
    now = time.time()
    uptime = now - state.started
    lines = [
        "CANopen live monitor | Ctrl+C stop",
        f"Log: {log_path.resolve()}",
        f"Frames: {state.frames} | uptime: {uptime:0.1f}s | services: "
        + " ".join(f"{name}={count}" for name, count in sorted(state.services.items())),
        f"Last: {state.last_frame}",
    ]
    if state.last_error:
        lines.append(f"Error: {state.last_error}")
    lines.append("")
    lines.extend(render_known_io_table(state, width))

    remaining = height - len(lines) - 1 if height > 0 else 20
    if remaining > 4:
        lines.append("")
        lines.append("Nodes")
        lines.append("ID   Name  Heartbeat       TPDO/RPDO last values")
        for node_id in sorted(state.nodes):
            if len(lines) >= height - 1:
                break
            node = state.nodes[node_id]
            pdo_parts = []
            for key in sorted(node.pdo):
                pdo = node.pdo[key]
                pdo_parts.append(
                    f"{pdo.service}{pdo.number}={pdo.data.hex(' ').upper() or '-'} "
                    f"chg={pdo.changed_count} age={age_text(pdo.last_seen, now)}"
                )
            lines.append(
                f"{node_id:>3}  {node.name:<5} {short(node.heartbeat, 14):<14} "
                + short(" | ".join(pdo_parts), max(20, width - 28))
            )

    if height > 0:
        lines = lines[: max(1, height - 1)]
    return "\n".join(short(line, width) for line in lines)


def render_known_io_table(state: MonitorState, width: int) -> list[str]:
    node_ids = sorted(IO_TPDO1_SIGNALS)
    prefix_width = 4
    gap = " "
    column_width = max(12, (width - prefix_width - len(gap) * (len(node_ids) - 1)) // len(node_ids))
    lines = ["Known IO TPDO1 signals"]
    header = "Pin " + gap.join(short(NODE_NAMES[node_id], column_width).ljust(column_width) for node_id in node_ids)
    lines.append(header)
    for pin in range(1, 17):
        cells = []
        for node_id in node_ids:
            node = state.nodes.get(node_id)
            pdo = node.pdo.get(("TPDO", 1)) if node else None
            data = pdo.data if pdo else b""
            on = bit_state(data, pin - 1)
            state_text = "ON " if on else "off"
            name = IO_TPDO1_SIGNALS[node_id].get(pin, f"pin {pin}")
            cells.append(short(f"{state_text} {name}", column_width).ljust(column_width))
        lines.append(f"{pin:>2}  " + gap.join(cells))
    return lines


def enable_virtual_terminal() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        return


def draw(text: str, first: bool) -> None:
    if first:
        sys.stdout.write("\x1b[?25l\x1b[2J\x1b[H")
    else:
        sys.stdout.write("\x1b[H")
    sys.stdout.write(text)
    sys.stdout.write("\x1b[J")
    sys.stdout.flush()


def terminal_size() -> os.terminal_size:
    try:
        return os.get_terminal_size()
    except OSError:
        return os.terminal_size((120, 40))


def playback_records(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("type") == "frame":
                yield record


def run_playback(args: argparse.Namespace) -> int:
    state = MonitorState()
    log_path = args.playback_log
    assert log_path is not None
    next_draw = 0.0
    first_draw = True
    enable_virtual_terminal()
    try:
        for record in playback_records(log_path):
            update_state(state, record)
            if args.playback_speed:
                time.sleep(args.playback_speed)
            now = time.monotonic()
            if not args.no_screen and now >= next_draw:
                size = terminal_size()
                draw(render_dashboard(state, log_path, size.columns, size.lines), first_draw)
                first_draw = False
                next_draw = now + args.refresh
        if not args.no_screen:
            size = terminal_size()
            draw(render_dashboard(state, log_path, size.columns, size.lines), first_draw)
            sys.stdout.write("\x1b[?25h\n")
        return 0
    except KeyboardInterrupt:
        if not args.no_screen:
            sys.stdout.write("\x1b[?25h\n")
        return 0


def run_live(args: argparse.Namespace) -> int:
    if not args.device:
        print("error: --device/--adapter is required unless --playback-log is used", file=sys.stderr)
        return 2

    args.logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = make_log_path(args.logs_dir, args.log_name)

    detecting_stderr = DetectingStderr(sys.stderr)
    original_stderr = sys.stderr
    try:
        sys.stderr = detecting_stderr
        reader = open_reader(args)
    except InitializationError as error:
        print(f"Could not safely open CAN adapter: {error}", file=sys.stderr)
        return 2
    finally:
        sys.stderr = original_stderr

    state = MonitorState()
    next_draw = 0.0
    first_draw = True
    enable_virtual_terminal()
    print(f"Log: {log_path.resolve()}", file=sys.stderr)
    print("Stop: Ctrl+C", file=sys.stderr)

    try:
        with log_path.open("w", encoding="utf-8", newline="\n") as log_file:
            write_jsonl(
                log_file,
                {
                    "type": "metadata",
                    "started_at": datetime.fromtimestamp(state.started).astimezone().isoformat(timespec="seconds"),
                    "device": args.device,
                    "channel": args.channel if args.channel is not None else "0",
                    "bitrate_request": args.bitrate,
                    "detected_bitrate": detecting_stderr.detected_bitrate,
                    "btr": args.btr,
                    "listen_only": True,
                    "live_monitor": True,
                },
            )
            while True:
                frame = reader.recv(args.recv_timeout)
                if frame is not None:
                    record = frame_to_record(frame, state.frames + 1)
                    write_jsonl(log_file, record)
                    update_state(state, record)
                    if state.frames % args.flush_every == 0:
                        log_file.flush()

                now = time.monotonic()
                if not args.no_screen and now >= next_draw:
                    size = terminal_size()
                    draw(render_dashboard(state, log_path, size.columns, size.lines), first_draw)
                    first_draw = False
                    next_draw = now + args.refresh
    except KeyboardInterrupt:
        if not args.no_screen:
            sys.stdout.write("\x1b[?25h\n")
        print(f"Stopped. Frames written: {state.frames}", file=sys.stderr)
        return 0
    except Exception as error:
        if not args.no_screen:
            sys.stdout.write("\x1b[?25h\n")
        print(f"CAN live monitor error: {error}", file=sys.stderr)
        return 2
    finally:
        reader.close()


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.playback_log is not None:
        return run_playback(args)
    return run_live(args)


if __name__ == "__main__":
    raise SystemExit(run())
