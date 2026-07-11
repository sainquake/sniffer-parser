"""Read Classical CAN frames on Windows in hardware listen-only mode."""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Sequence


class InitializationError(RuntimeError):
    """The adapter cannot be opened safely."""


@dataclass(frozen=True, slots=True)
class Frame:
    timestamp: float
    arbitration_id: int
    is_extended_id: bool
    is_remote_frame: bool
    is_error_frame: bool
    data: bytes
    dlc: int
    channel: str


class Reader(Protocol):
    def recv(self, timeout: float) -> Frame | None: ...

    def close(self) -> None: ...


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("значение должно быть больше нуля")
    return number


def bitrate_value(value: str) -> int | str:
    if value.lower() == "auto":
        return "auto"
    return positive_int(value)


def bitrate_list(value: str) -> tuple[int, ...]:
    try:
        result = tuple(positive_int(item.strip()) for item in value.split(","))
    except (ValueError, argparse.ArgumentTypeError) as error:
        raise argparse.ArgumentTypeError("ожидается список скоростей через запятую") from error
    if not result:
        raise argparse.ArgumentTypeError("список скоростей не может быть пустым")
    return result


def btr_value(value: str) -> str:
    if len(value) != 4:
        raise argparse.ArgumentTypeError("BTR должен содержать ровно 4 hex-символа")
    try:
        int(value, 16)
    except ValueError as error:
        raise argparse.ArgumentTypeError("BTR должен быть hex-значением BTR0/BTR1") from error
    return value.upper()


def non_negative_float(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("значение не может быть отрицательным")
    return number


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("значение должно быть больше нуля")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Прочитать CAN-кадры на Windows в аппаратном listen-only режиме. "
            "Программа не содержит операций передачи CAN-кадров."
        )
    )
    parser.add_argument(
        "--device",
        "--adapter",
        dest="device",
        required=True,
        choices=(
            "zubax",
            "raccoonlab",
            "slcan",
            "candlelight",
            "canable",
            "gs_usb",
        ),
        help=(
            "zubax/raccoonlab/slcan используют COM-порт; "
            "candlelight/canable/gs_usb используют GS-USB"
        ),
    )
    parser.add_argument(
        "--channel",
        help="COM-порт для SLCAN или индекс GS-USB (по умолчанию: 0)",
    )
    speed_group = parser.add_mutually_exclusive_group(required=True)
    speed_group.add_argument(
        "--bitrate",
        type=bitrate_value,
        help="скорость CAN в бит/с либо auto",
    )
    speed_group.add_argument(
        "--btr",
        type=btr_value,
        help="нестандартные BTR0/BTR1 для SLCAN, например 031C",
    )
    parser.add_argument(
        "--bitrates",
        type=bitrate_list,
        default=(1_000_000, 800_000, 500_000, 250_000, 125_000, 100_000, 50_000, 20_000, 10_000),
        help="кандидаты для auto через запятую",
    )
    parser.add_argument(
        "--autodetect-window",
        type=positive_float,
        default=0.5,
        help="время прослушивания каждой скорости при auto (по умолчанию: 0.5 с)",
    )
    parser.add_argument(
        "--tty-baudrate",
        type=positive_int,
        default=None,
        help=(
            "скорость COM-порта; по умолчанию 1000000 для RaccoonLab "
            "и 115200 для остальных SLCAN"
        ),
    )
    parser.add_argument(
        "--count",
        type=positive_int,
        default=1,
        help="число кадров (по умолчанию: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=non_negative_float,
        default=30.0,
        help="тайм-аут ожидания каждого кадра в секундах (по умолчанию: 30)",
    )
    return parser


class SlcanReader:
    """SLCAN reader that opens the controller with the listen-only `L` command."""

    _BITRATE_COMMANDS = {
        10_000: "S0",
        20_000: "S1",
        50_000: "S2",
        100_000: "S3",
        125_000: "S4",
        250_000: "S5",
        500_000: "S6",
        800_000: "S7",
        1_000_000: "S8",
    }

    def __init__(
        self,
        channel: str,
        bitrate: int | None,
        tty_baudrate: int,
        btr: str | None = None,
    ) -> None:
        try:
            import serial
        except ImportError as error:
            raise InitializationError(
                "не установлена библиотека pyserial"
            ) from error

        self._serial = None
        bitrate_command = f"s{btr}" if btr is not None else self._BITRATE_COMMANDS.get(bitrate)
        if bitrate_command is None:
            supported = ", ".join(str(value) for value in self._BITRATE_COMMANDS)
            raise InitializationError(
                f"SLCAN не поддерживает bitrate {bitrate}; доступны: {supported}"
            )

        try:
            self._serial = serial.Serial(
                port=channel,
                baudrate=tty_baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
                write_timeout=1.0,
                rtscts=False,
                dsrdtr=False,
            )
            self._serial.dtr = False
            self._serial.rts = False
            time.sleep(0.3)
            self._serial.reset_input_buffer()

            self._synchronize()
            self.version = self._query("V", "V", allow_bell=True)
            self._command("C", allow_bell=True)
            self._command(bitrate_command)
            self._command("L")
        except InitializationError:
            self.close()
            raise
        except (ValueError, TypeError, OSError, serial.SerialException) as error:
            self.close()
            raise InitializationError(str(error)) from error

    def _synchronize(self) -> None:
        # LAWICEL recommends 2-3 empty CR commands at session start to clear
        # stale data. CR or BELL are both valid synchronization responses.
        for _ in range(3):
            self._command("", allow_bell=True)

    def _query(
        self,
        command: str,
        prefix: str,
        *,
        allow_bell: bool = False,
    ) -> str | None:
        return self._command(command, prefix=prefix, allow_bell=allow_bell)

    def _command(
        self,
        command: str,
        *,
        prefix: str | None = None,
        allow_bell: bool = False,
    ) -> str | None:
        self._serial.write(command.encode("ascii") + b"\r")
        self._serial.flush()
        deadline = time.monotonic() + 1.0
        response = bytearray()
        while time.monotonic() < deadline:
            byte = self._serial.read(1)
            if not byte:
                continue
            if byte == b"\a":
                if allow_bell:
                    return None
                raise InitializationError(
                    f"SLCAN-адаптер отклонил команду {command!r}"
                )
            if byte == b"\r":
                text = response.decode("ascii", errors="replace")
                response.clear()
                if prefix is not None:
                    if text.startswith(prefix):
                        return text
                    continue
                # An empty record is the documented ACK. CAN frames that were
                # already queued are skipped until the actual command ACK.
                if not text:
                    return ""
                continue
            response.extend(byte)
        raise InitializationError(
            f"SLCAN-адаптер не подтвердил команду {command!r}: {bytes(response)!r}"
        )

    def recv(self, timeout: float) -> Frame | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            self._serial.timeout = min(0.1, max(0.001, remaining))
            line = self._serial.read_until(b"\r", size=64)
            if not line.endswith(b"\r"):
                continue
            frame = self._parse_frame(line[:-1])
            if frame is not None:
                return frame
        return None

    def _parse_frame(self, line: bytes) -> Frame | None:
        try:
            text = line.decode("ascii")
            if not text or text[0] not in "tTrR":
                return None
            extended = text[0] in "TR"
            remote = text[0] in "rR"
            id_length = 8 if extended else 3
            arbitration_id = int(text[1 : 1 + id_length], 16)
            dlc_offset = 1 + id_length
            dlc = int(text[dlc_offset], 16)
            if dlc > 8:
                return None
            data_offset = dlc_offset + 1
            payload_length = 0 if remote else dlc * 2
            payload = bytes.fromhex(
                text[data_offset : data_offset + payload_length]
            )
            if len(payload) != (0 if remote else dlc):
                return None
        except (UnicodeDecodeError, ValueError, IndexError):
            return None

        return Frame(
            timestamp=time.time(),
            arbitration_id=arbitration_id,
            is_extended_id=extended,
            is_remote_frame=remote,
            is_error_frame=False,
            data=payload,
            dlc=dlc,
            channel=self._serial.port,
        )

    def close(self) -> None:
        if self._serial is not None:
            try:
                if self._serial.is_open:
                    try:
                        self._serial.write(b"C\r")
                        self._serial.flush()
                        time.sleep(0.05)
                    finally:
                        self._serial.close()
            except Exception:
                # Closing must not hide the original hardware/initialization error.
                pass
            finally:
                self._serial = None


class CandlelightReader:
    """CandleLight/GS-USB reader with an explicit LISTEN_ONLY USB mode flag."""

    def __init__(self, index: int, bitrate: int) -> None:
        try:
            import libusb_package
            import usb.core
            import usb.util
            from gs_usb.constants import (
                GS_CAN_MODE_HW_TIMESTAMP,
                GS_CAN_MODE_LISTEN_ONLY,
            )
            from gs_usb.gs_usb import GsUsb
            from gs_usb.gs_usb_frame import GsUsbFrame
        except ImportError as error:
            raise InitializationError(
                "не установлены зависимости GS-USB из requirements.txt"
            ) from error

        self._usb_error = usb.core.USBError
        self._usb_util = usb.util
        self._frame_type = GsUsbFrame
        self._device = None
        self._index = index

        try:
            raw_devices = list(
                libusb_package.find(
                    find_all=True,
                    custom_match=GsUsb.is_gs_usb_device,
                )
            )
            if index >= len(raw_devices):
                raise InitializationError(
                    f"GS-USB устройство с индексом {index} не найдено; "
                    f"найдено устройств: {len(raw_devices)}"
                )

            self._device = GsUsb(raw_devices[index])
            capabilities = self._device.device_capability.feature
            if not capabilities & GS_CAN_MODE_LISTEN_ONLY:
                raise InitializationError(
                    "прошивка GS-USB не заявляет аппаратный LISTEN_ONLY"
                )
            if not self._device.set_bitrate(bitrate):
                raise InitializationError(
                    f"скорость {bitrate} не поддерживается GS-USB backend"
                )

            flags = GS_CAN_MODE_LISTEN_ONLY
            if capabilities & GS_CAN_MODE_HW_TIMESTAMP:
                flags |= GS_CAN_MODE_HW_TIMESTAMP
            self._device.start(flags=flags)

            # gs_usb.start() маскирует неподдерживаемые флаги. Проверяем итог.
            if not self._device.device_flags & GS_CAN_MODE_LISTEN_ONLY:
                raise InitializationError("GS-USB не включил LISTEN_ONLY")
        except InitializationError:
            self.close()
            raise
        except (ValueError, TypeError, OSError, self._usb_error) as error:
            self.close()
            raise InitializationError(str(error)) from error

    def recv(self, timeout: float) -> Frame | None:
        frame = self._frame_type()
        timeout_ms = max(1, round(timeout * 1000))
        if not self._device.read(frame=frame, timeout_ms=timeout_ms):
            return None
        return Frame(
            timestamp=time.time(),
            arbitration_id=frame.arbitration_id,
            is_extended_id=frame.is_extended_id,
            is_remote_frame=frame.is_remote_frame,
            is_error_frame=frame.is_error_frame,
            data=bytes(frame.data[: frame.can_dlc]),
            dlc=frame.can_dlc,
            channel=f"gs_usb:{self._index}",
        )

    def close(self) -> None:
        if self._device is not None:
            try:
                self._device.stop()
            finally:
                self._usb_util.dispose_resources(self._device.gs_usb)
                self._device = None
                time.sleep(0.05)


class PrefetchedReader:
    """Return the frame used for auto-detection before reading new frames."""

    def __init__(self, reader: Reader, first_frame: Frame) -> None:
        self._reader = reader
        self._first_frame = first_frame

    def recv(self, timeout: float) -> Frame | None:
        if self._first_frame is not None:
            frame = self._first_frame
            self._first_frame = None
            return frame
        return self._reader.recv(timeout)

    def close(self) -> None:
        self._reader.close()


def detect_sustained_activity(
    reader: Reader,
    window: float,
) -> Frame | None:
    """Ignore stale adapter FIFO data and require a sustained frame stream."""
    warmup = min(0.02, max(0.005, window / 10))
    warmup_deadline = time.monotonic() + warmup
    while time.monotonic() < warmup_deadline:
        reader.recv(min(0.02, warmup_deadline - time.monotonic()))

    deadline = time.monotonic() + window
    frames: list[Frame] = []
    while time.monotonic() < deadline:
        frame = reader.recv(min(0.05, deadline - time.monotonic()))
        # A controller at the wrong bitrate may emit error frames. Only normal
        # received CAN frames are evidence that the bitrate is correct.
        if frame is not None and not frame.is_error_frame:
            frames.append(frame)

    # The observed RaccoonLab stale FIFO burst contains two frames, while live
    # traffic arrives in larger bursts. Requiring three frames rejects that
    # residue without assuming that traffic is continuous throughout the window.
    if len(frames) >= 3:
        return frames[-1]
    return None


def open_reader(args: argparse.Namespace) -> Reader:
    if args.device in {"zubax", "raccoonlab", "slcan"}:
        if not args.channel:
            raise InitializationError(
                f"для {args.device} необходимо указать COM-порт через --channel"
            )
        tty_baudrate = args.tty_baudrate
        if tty_baudrate is None:
            tty_baudrate = 1_000_000 if args.device == "raccoonlab" else 115_200
        if args.btr is not None:
            if args.device == "raccoonlab":
                raise InitializationError(
                    "прошивка RaccoonLab V0009 не поддерживает команду sBTR0BTR1; "
                    "используйте стандартный --bitrate из S0-S8"
                )
            return SlcanReader(args.channel, None, tty_baudrate, btr=args.btr)
        if args.bitrate == "auto":
            unsupported = [
                value for value in args.bitrates if value not in SlcanReader._BITRATE_COMMANDS
            ]
            if unsupported:
                raise InitializationError(
                    f"auto содержит неподдерживаемые SLCAN-скорости: {unsupported}"
                )
            attempts: list[str] = []
            for bitrate in args.bitrates:
                reader = None
                keep_reader = False
                try:
                    reader = SlcanReader(args.channel, bitrate, tty_baudrate)
                    frame = detect_sustained_activity(
                        reader,
                        args.autodetect_window,
                    )
                    if frame is not None:
                        keep_reader = True
                        print(
                            f"Автоопределение CAN bitrate: {bitrate} бит/с",
                            file=sys.stderr,
                        )
                        return PrefetchedReader(reader, frame)
                    attempts.append(f"{bitrate}: нет кадров")
                except InitializationError as error:
                    attempts.append(f"{bitrate}: {error}")
                finally:
                    if reader is not None and not keep_reader:
                        # Successful readers are returned above. Failed attempts
                        # are closed here; close() only sends the local C command.
                        reader.close()
            raise InitializationError(
                "не удалось определить CAN bitrate; " + "; ".join(attempts)
            )
        return SlcanReader(args.channel, args.bitrate, tty_baudrate)

    if args.btr is not None:
        raise InitializationError("--btr поддерживается только SLCAN-устройствами")
    try:
        index = int(args.channel or "0")
    except ValueError as error:
        raise InitializationError(
            "для GS-USB --channel должен быть индексом устройства, например 0"
        ) from error
    if index < 0:
        raise InitializationError("индекс GS-USB не может быть отрицательным")
    if args.bitrate == "auto":
        attempts: list[str] = []
        for bitrate in args.bitrates:
            reader = None
            keep_reader = False
            try:
                reader = CandlelightReader(index, bitrate)
                frame = detect_sustained_activity(
                    reader,
                    args.autodetect_window,
                )
                if frame is not None:
                    keep_reader = True
                    print(
                        f"Автоопределение CAN bitrate: {bitrate} бит/с",
                        file=sys.stderr,
                    )
                    return PrefetchedReader(reader, frame)
                attempts.append(f"{bitrate}: нет обычных CAN-кадров")
            except InitializationError as error:
                attempts.append(f"{bitrate}: {error}")
            finally:
                if reader is not None and not keep_reader:
                    reader.close()
        raise InitializationError(
            "не удалось определить CAN bitrate GS-USB; " + "; ".join(attempts)
        )
    return CandlelightReader(index, args.bitrate)


def format_frame(frame: Frame) -> str:
    timestamp = datetime.fromtimestamp(frame.timestamp).astimezone().isoformat(
        timespec="microseconds"
    )
    identifier_width = 8 if frame.is_extended_id else 3
    frame_format = "EXT" if frame.is_extended_id else "STD"
    payload = " ".join(f"{byte:02X}" for byte in frame.data) or "-"
    flags = [frame_format]
    if frame.is_remote_frame:
        flags.append("RTR")
    if frame.is_error_frame:
        flags.append("ERROR")
    return (
        f"{timestamp}  ID=0x{frame.arbitration_id:0{identifier_width}X}  "
        f"{' '.join(flags)}  DLC={frame.dlc}  DATA={payload}"
    )


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        reader = open_reader(args)
    except InitializationError as error:
        print(f"Не удалось безопасно открыть адаптер: {error}", file=sys.stderr)
        return 2

    try:
        for _ in range(args.count):
            frame = reader.recv(args.timeout)
            if frame is None:
                print(
                    f"CAN-кадр не получен за {args.timeout:g} с.",
                    file=sys.stderr,
                )
                return 1
            print(format_frame(frame), flush=True)
    except KeyboardInterrupt:
        print("Остановлено пользователем.", file=sys.stderr)
        return 130
    except Exception as error:  # hardware backends expose different error types
        print(f"Ошибка чтения CAN: {error}", file=sys.stderr)
        return 2
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
