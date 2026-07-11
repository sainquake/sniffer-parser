"""Continuously log Classical CAN frames in hardware listen-only mode."""

from __future__ import annotations

import argparse
import json
import queue
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence

from can_dump import (
    InitializationError,
    bitrate_list,
    bitrate_value,
    btr_value,
    format_frame,
    non_negative_float,
    open_reader,
    positive_float,
    positive_int,
)


class DetectingStderr:
    def __init__(self, wrapped) -> None:
        self._wrapped = wrapped
        self.detected_bitrate: int | None = None

    def write(self, text: str) -> int:
        match = re.search(r"CAN bitrate:\s*(\d+)", text)
        if match is not None:
            self.detected_bitrate = int(match.group(1))
        return self._wrapped.write(text)

    def flush(self) -> None:
        self._wrapped.flush()


def safe_log_name(value: str) -> str:
    name = re.sub(r"[^0-9A-Za-zА-Яа-я._-]+", "_", value.strip(), flags=re.UNICODE)
    name = name.strip("._-")
    if not name:
        raise argparse.ArgumentTypeError("название лога не должно быть пустым")
    return name[:80]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Непрерывно писать CAN-кадры в JSONL-лог. "
            "Адаптер открывается только в hardware listen-only/silent режиме."
        )
    )
    parser.add_argument(
        "log_name",
        type=safe_log_name,
        help="название лога; будет использовано в имени файла",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=Path("logs"),
        help="папка для логов (по умолчанию: logs)",
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
    speed_group = parser.add_mutually_exclusive_group()
    speed_group.add_argument(
        "--bitrate",
        type=bitrate_value,
        default="auto",
        help="скорость CAN в бит/с либо auto (по умолчанию: auto)",
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
        "--recv-timeout",
        type=non_negative_float,
        default=1.0,
        help="тайм-аут ожидания очередного кадра в секундах (по умолчанию: 1)",
    )
    parser.add_argument(
        "--flush-every",
        type=positive_int,
        default=100,
        help="сбрасывать файл на диск каждые N кадров (по умолчанию: 100)",
    )
    parser.add_argument(
        "--print",
        dest="print_frames",
        action="store_true",
        help="дополнительно печатать кадры в консоль",
    )
    parser.add_argument(
        "--no-comments",
        action="store_true",
        help="не читать комментарии из консоли во время записи",
    )
    return parser


def make_log_path(logs_dir: Path, log_name: str) -> Path:
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    base = logs_dir / f"{timestamp}_{log_name}.jsonl"
    if not base.exists():
        return base

    for index in range(1, 1000):
        candidate = logs_dir / f"{timestamp}_{log_name}_{index}.jsonl"
        if not candidate.exists():
            return candidate
    raise RuntimeError("не удалось подобрать свободное имя файла лога")


def frame_to_record(frame, sequence: int) -> dict:
    timestamp = datetime.fromtimestamp(frame.timestamp).astimezone().isoformat(
        timespec="microseconds"
    )
    return {
        "type": "frame",
        "sequence": sequence,
        "timestamp": timestamp,
        "timestamp_epoch": frame.timestamp,
        "channel": frame.channel,
        "id": f"0x{frame.arbitration_id:08X}" if frame.is_extended_id else f"0x{frame.arbitration_id:03X}",
        "arbitration_id": frame.arbitration_id,
        "extended": frame.is_extended_id,
        "remote": frame.is_remote_frame,
        "error": frame.is_error_frame,
        "dlc": frame.dlc,
        "data": frame.data.hex().upper(),
        "data_bytes": list(frame.data),
    }


def comment_to_record(text: str, sequence: int, timestamp_epoch: float) -> dict:
    return {
        "type": "comment",
        "sequence": sequence,
        "timestamp": datetime.fromtimestamp(timestamp_epoch).astimezone().isoformat(
            timespec="microseconds"
        ),
        "timestamp_epoch": timestamp_epoch,
        "text": text,
    }


def start_comment_reader(
    comments: "queue.Queue[tuple[float, str]]",
    stop_event: threading.Event,
) -> threading.Thread:
    def read_loop() -> None:
        while not stop_event.is_set():
            line = sys.stdin.readline()
            if line == "":
                return
            text = line.strip()
            if text:
                comments.put((time.time(), text))

    thread = threading.Thread(target=read_loop, name="console-comment-reader", daemon=True)
    thread.start()
    return thread


def write_jsonl(log_file, record: dict) -> None:
    log_file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def drain_comments(
    log_file,
    comments: "queue.Queue[tuple[float, str]]",
    comment_count: int,
) -> int:
    while True:
        try:
            timestamp_epoch, text = comments.get_nowait()
        except queue.Empty:
            break
        comment_count += 1
        write_jsonl(log_file, comment_to_record(text, comment_count, timestamp_epoch))
        log_file.flush()
    return comment_count


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = make_log_path(args.logs_dir, args.log_name)

    detecting_stderr = DetectingStderr(sys.stderr)
    original_stderr = sys.stderr
    try:
        sys.stderr = detecting_stderr
        reader = open_reader(args)
    except InitializationError as error:
        print(f"Не удалось безопасно открыть адаптер: {error}", file=sys.stderr)
        return 2
    finally:
        sys.stderr = original_stderr

    count = 0
    comment_count = 0
    started = time.time()
    comments: queue.Queue[tuple[float, str]] = queue.Queue()
    stop_comments = threading.Event()
    print(f"Лог: {log_path.resolve()}", file=sys.stderr)
    print("Остановка: Ctrl+C", file=sys.stderr)
    if not args.no_comments:
        start_comment_reader(comments, stop_comments)
        print("Комментарии: напишите текст в консоль и нажмите Enter.", file=sys.stderr)

    try:
        with log_path.open("w", encoding="utf-8", newline="\n") as log_file:
            metadata = {
                "type": "metadata",
                "started_at": datetime.fromtimestamp(started).astimezone().isoformat(timespec="seconds"),
                "device": args.device,
                "channel": args.channel if args.channel is not None else "0",
                "bitrate_request": args.bitrate,
                "detected_bitrate": detecting_stderr.detected_bitrate,
                "btr": args.btr,
                "listen_only": True,
                "comments_enabled": not args.no_comments,
            }
            write_jsonl(log_file, metadata)

            while True:
                comment_count = drain_comments(log_file, comments, comment_count)
                frame = reader.recv(args.recv_timeout)
                comment_count = drain_comments(log_file, comments, comment_count)
                if frame is None:
                    continue

                count += 1
                record = frame_to_record(frame, count)
                write_jsonl(log_file, record)

                if args.print_frames:
                    print(format_frame(frame), flush=True)
                if count % args.flush_every == 0:
                    log_file.flush()

    except KeyboardInterrupt:
        print(
            f"Остановлено пользователем. Записано кадров: {count}, комментариев: {comment_count}",
            file=sys.stderr,
        )
        return 0
    except Exception as error:
        print(f"Ошибка записи CAN-лога: {error}", file=sys.stderr)
        return 2
    finally:
        stop_comments.set()
        reader.close()


if __name__ == "__main__":
    raise SystemExit(run())
