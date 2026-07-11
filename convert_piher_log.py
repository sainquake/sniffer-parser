"""Convert direct_piher_canopen.py console output to can_log.py JSONL format."""

from __future__ import annotations

import argparse
import ast
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence


RX_RE = re.compile(
    r"^RX\s*->\s*(?P<raw>b'.*?')\s+id=0x(?P<id>[0-9A-Fa-f]+)\s+dlc=(?P<dlc>[0-9]+)\s+data=(?P<data>[0-9A-Fa-f ]*?)"
    r"(?:\s+angle_raw=(?P<angle_raw>-?\d+)\s+angle_deg=(?P<angle_deg>-?\d+(?:\.\d+)?))?"
    r"\s*$"
)
TX_RE = re.compile(r"^(?P<command>[tTrR][0-9A-Fa-f]+)\s*->\s*(?P<response>b'.*?')")
CAN_BITRATE_RE = re.compile(r"^CAN bitrate:\s*(?P<bitrate>\d+)")
CONNECTING_RE = re.compile(r"^Connecting:\s*(?P<channel>.*?)\s+@\s+(?P<baudrate>\d+)")
ADAPTER_COMMAND_RE = re.compile(r"^(?:[VCSOF]|S[0-8]|\s*)\s*->\s*b'.*?'$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Преобразовать текстовый stdout direct_piher_canopen.py в JSONL, "
            "совместимый с canopen_decode.py."
        )
    )
    parser.add_argument("input", type=Path, help="исходный текстовый лог")
    parser.add_argument(
        "--output",
        type=Path,
        help="путь выходного JSONL; по умолчанию logs/<input-stem>.jsonl",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=Path("logs"),
        help="папка для выходного JSONL, если --output не указан",
    )
    parser.add_argument(
        "--start-time",
        default="2026-07-11T15:10:00+03:00",
        help="начальное время для синтетических timestamp, ISO-8601",
    )
    parser.add_argument(
        "--step",
        type=float,
        default=0.01,
        help="шаг времени между событиями, секунд (по умолчанию: 0.01)",
    )
    parser.add_argument(
        "--channel",
        default=None,
        help="переопределить channel в выходном логе",
    )
    return parser


def parse_lawicel_frame(text: str) -> dict[str, Any] | None:
    if not text or text[0] not in "tTrR":
        return None

    extended = text[0] in "TR"
    remote = text[0] in "rR"
    id_length = 8 if extended else 3
    try:
        arbitration_id = int(text[1 : 1 + id_length], 16)
        dlc_offset = 1 + id_length
        dlc = int(text[dlc_offset], 16)
        payload_start = dlc_offset + 1
        payload = b"" if remote else bytes.fromhex(text[payload_start : payload_start + dlc * 2])
    except (ValueError, IndexError):
        return None

    if len(payload) != (0 if remote else dlc):
        return None

    return {
        "arbitration_id": arbitration_id,
        "extended": extended,
        "remote": remote,
        "dlc": dlc,
        "data": payload,
    }


def timestamp_at(start_epoch: float, sequence: int, step: float) -> tuple[float, str]:
    timestamp_epoch = start_epoch + sequence * step
    timestamp = datetime.fromtimestamp(timestamp_epoch).astimezone().isoformat(
        timespec="microseconds"
    )
    return timestamp_epoch, timestamp


def make_frame_record(
    *,
    source_sequence: int,
    event_sequence: int,
    start_epoch: float,
    step: float,
    channel: str,
    frame: dict[str, Any],
    direction: str,
    source_line: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timestamp_epoch, timestamp = timestamp_at(start_epoch, event_sequence, step)
    data = frame["data"]
    arbitration_id = frame["arbitration_id"]
    extended = frame["extended"]
    record: dict[str, Any] = {
        "type": "frame",
        "sequence": source_sequence,
        "timestamp": timestamp,
        "timestamp_epoch": timestamp_epoch,
        "channel": channel,
        "id": f"0x{arbitration_id:08X}" if extended else f"0x{arbitration_id:03X}",
        "arbitration_id": arbitration_id,
        "extended": extended,
        "remote": frame["remote"],
        "error": False,
        "dlc": frame["dlc"],
        "data": data.hex().upper(),
        "data_bytes": list(data),
        "direction": direction,
        "source": "direct_piher_canopen.py",
        "source_line": source_line,
    }
    if extra:
        record.update(extra)
    return record


def make_comment_record(
    *,
    source_sequence: int,
    event_sequence: int,
    start_epoch: float,
    step: float,
    text: str,
) -> dict[str, Any]:
    timestamp_epoch, timestamp = timestamp_at(start_epoch, event_sequence, step)
    return {
        "type": "comment",
        "sequence": source_sequence,
        "timestamp": timestamp,
        "timestamp_epoch": timestamp_epoch,
        "text": text,
        "source": "direct_piher_canopen.py",
    }


def load_bytes_literal(value: str) -> bytes | None:
    try:
        result = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return None
    return result if isinstance(result, bytes) else None


def convert(input_path: Path, output_path: Path, start_time: str, step: float, channel_override: str | None) -> dict[str, Any]:
    start_dt = datetime.fromisoformat(start_time)
    start_epoch = start_dt.timestamp()

    metadata: dict[str, Any] = {
        "type": "metadata",
        "started_at": start_dt.astimezone().isoformat(timespec="seconds"),
        "device": "direct_piher_canopen.py",
        "channel": channel_override or "unknown",
        "bitrate_request": None,
        "detected_bitrate": None,
        "btr": None,
        "listen_only": False,
        "comments_enabled": True,
        "source_log": str(input_path),
        "note": "Converted from active PIHER startup script output; TX frames are preserved with direction=tx.",
    }

    records: list[dict[str, Any]] = []
    frame_sequence = 0
    comment_sequence = 0
    event_sequence = 0

    for raw_line in input_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        connecting = CONNECTING_RE.match(line)
        if connecting:
            metadata["channel"] = channel_override or connecting.group("channel")
            metadata["tty_baudrate"] = int(connecting.group("baudrate"))
            continue

        bitrate = CAN_BITRATE_RE.match(line)
        if bitrate:
            metadata["bitrate_request"] = int(bitrate.group("bitrate"))
            metadata["detected_bitrate"] = int(bitrate.group("bitrate"))
            continue

        rx = RX_RE.match(line)
        if rx:
            response = load_bytes_literal(rx.group("raw"))
            frame_text = response.decode("ascii", errors="replace").strip() if response else ""
            frame = parse_lawicel_frame(frame_text)
            if frame is None:
                comment_sequence += 1
                event_sequence += 1
                records.append(
                    make_comment_record(
                        source_sequence=comment_sequence,
                        event_sequence=event_sequence,
                        start_epoch=start_epoch,
                        step=step,
                        text=f"unparsed RX: {line}",
                    )
                )
                continue

            frame_sequence += 1
            event_sequence += 1
            extra: dict[str, Any] = {}
            if rx.group("angle_raw") is not None:
                extra["piher_angle_raw"] = int(rx.group("angle_raw"))
            if rx.group("angle_deg") is not None:
                extra["piher_angle_deg"] = float(rx.group("angle_deg"))
            records.append(
                make_frame_record(
                    source_sequence=frame_sequence,
                    event_sequence=event_sequence,
                    start_epoch=start_epoch,
                    step=step,
                    channel=metadata["channel"],
                    frame=frame,
                    direction="rx",
                    source_line=line,
                    extra=extra,
                )
            )
            continue

        tx = TX_RE.match(line)
        if tx:
            command = tx.group("command")
            frame = parse_lawicel_frame(command)
            if frame is not None:
                frame_sequence += 1
                event_sequence += 1
                records.append(
                    make_frame_record(
                        source_sequence=frame_sequence,
                        event_sequence=event_sequence,
                        start_epoch=start_epoch,
                        step=step,
                        channel=metadata["channel"],
                        frame=frame,
                        direction="tx",
                        source_line=line,
                        extra={"adapter_response": tx.group("response")},
                    )
                )
                continue

        if ADAPTER_COMMAND_RE.match(line):
            continue

        comment_sequence += 1
        event_sequence += 1
        records.append(
            make_comment_record(
                source_sequence=comment_sequence,
                event_sequence=event_sequence,
                start_epoch=start_epoch,
                step=step,
                text=line,
            )
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as file:
        file.write(json.dumps(metadata, ensure_ascii=False, separators=(",", ":")) + "\n")
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    return {
        "output": str(output_path),
        "records": len(records),
        "frames": frame_sequence,
        "comments": comment_sequence,
    }


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = args.output or (args.logs_dir / f"{args.input.stem}.jsonl")
    result = convert(args.input, output, args.start_time, args.step, args.channel)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
