"""Decode CANopen traffic from logs produced by can_log.py."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


HEARTBEAT_STATES = {
    0x00: "boot-up",
    0x04: "stopped",
    0x05: "operational",
    0x7F: "pre-operational",
}

NMT_COMMANDS = {
    0x01: "start remote node",
    0x02: "stop remote node",
    0x80: "enter pre-operational",
    0x81: "reset node",
    0x82: "reset communication",
}

SDO_ABORT_CODES = {
    0x05030000: "toggle bit not alternated",
    0x05040000: "SDO protocol timed out",
    0x05040001: "client/server command specifier invalid or unknown",
    0x05040005: "out of memory",
    0x06010000: "unsupported access to object",
    0x06010001: "attempt to read a write-only object",
    0x06010002: "attempt to write a read-only object",
    0x06020000: "object does not exist",
    0x06040041: "object cannot be mapped to PDO",
    0x06040042: "PDO mapping length exceeded",
    0x06040043: "general parameter incompatibility",
    0x06040047: "general internal incompatibility",
    0x06060000: "access failed due to hardware error",
    0x06070010: "data type does not match",
    0x06070012: "data type too high",
    0x06070013: "data type too low",
    0x06090011: "sub-index does not exist",
    0x06090030: "value range exceeded",
    0x06090031: "value too high",
    0x06090032: "value too low",
    0x08000000: "general error",
    0x08000020: "data cannot be transferred or stored",
    0x08000021: "data cannot be transferred or stored because of local control",
    0x08000022: "data cannot be transferred or stored because of device state",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Декодировать CANopen из JSONL-лога can_log.py. "
            "Если лог не указан, берётся последний *.jsonl из папки logs."
        )
    )
    parser.add_argument(
        "log",
        nargs="?",
        help="путь к JSONL-логу или имя/часть имени файла из папки logs",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=Path("logs"),
        help="папка с исходными логами (по умолчанию: logs)",
    )
    parser.add_argument(
        "--parsed-dir",
        type=Path,
        default=Path("parsed"),
        help="папка для результата декодирования (по умолчанию: parsed)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="дополнительно печатать декодированные события в консоль",
    )
    return parser


def resolve_log(log_arg: str | None, logs_dir: Path) -> Path:
    if log_arg is None:
        candidates = sorted(
            logs_dir.glob("*.jsonl"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            raise FileNotFoundError(f"в папке {logs_dir} нет *.jsonl логов")
        return candidates[0]

    path = Path(log_arg)
    if path.exists():
        return path

    direct = logs_dir / log_arg
    if direct.exists():
        return direct

    if not log_arg.lower().endswith(".jsonl"):
        direct_jsonl = logs_dir / f"{log_arg}.jsonl"
        if direct_jsonl.exists():
            return direct_jsonl

    matches = sorted(logs_dir.glob(f"*{log_arg}*.jsonl"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = ", ".join(path.name for path in matches[:10])
        raise FileNotFoundError(f"найдено несколько подходящих логов: {names}")
    raise FileNotFoundError(f"лог не найден: {log_arg}")


def output_dir_for(log_path: Path, parsed_dir: Path) -> Path:
    return parsed_dir / log_path.stem


def parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


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


def le_uint(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little", signed=False)


def signed_or_unsigned(data: bytes) -> dict[str, int]:
    if not data:
        return {"u": 0, "i": 0}
    return {
        "u": int.from_bytes(data, byteorder="little", signed=False),
        "i": int.from_bytes(data, byteorder="little", signed=True),
    }


def base_event(record: dict[str, Any], protocol: str = "canopen") -> dict[str, Any]:
    return {
        "type": "decoded",
        "protocol": protocol,
        "source_sequence": record.get("sequence"),
        "timestamp": record.get("timestamp"),
        "timestamp_epoch": record.get("timestamp_epoch"),
        "can_id": record.get("id"),
        "arbitration_id": record.get("arbitration_id"),
    }


def decode_nmt(record: dict[str, Any], data: bytes) -> dict[str, Any]:
    event = base_event(record)
    event["service"] = "NMT"
    if len(data) >= 2:
        command = data[0]
        node_id = data[1]
        event.update(
            {
                "command": command,
                "command_name": NMT_COMMANDS.get(command, "unknown"),
                "node_id": node_id,
                "target": "all nodes" if node_id == 0 else f"node {node_id}",
            }
        )
    else:
        event["malformed"] = True
        event["reason"] = "NMT frame must contain command and node id"
    return event


def decode_sync(record: dict[str, Any], data: bytes) -> dict[str, Any]:
    event = base_event(record)
    event["service"] = "SYNC"
    if len(data) == 1:
        event["counter"] = data[0]
    elif len(data) not in (0, 1):
        event["malformed"] = True
        event["reason"] = "SYNC DLC is normally 0 or 1"
    return event


def decode_emcy(record: dict[str, Any], data: bytes, node_id: int) -> dict[str, Any]:
    event = base_event(record)
    event.update({"service": "EMCY", "node_id": node_id})
    if len(data) >= 3:
        event.update(
            {
                "error_code": f"0x{le_uint(data[0:2]):04X}",
                "error_register": f"0x{data[2]:02X}",
                "manufacturer_specific": data[3:].hex().upper(),
            }
        )
    else:
        event["malformed"] = True
        event["reason"] = "EMCY frame must contain at least 3 bytes"
    return event


def decode_time(record: dict[str, Any], data: bytes) -> dict[str, Any]:
    event = base_event(record)
    event["service"] = "TIME"
    if len(data) >= 6:
        event["milliseconds_after_midnight"] = le_uint(data[0:4])
        event["days_since_1984_01_01"] = le_uint(data[4:6])
    else:
        event["malformed"] = True
        event["reason"] = "TIME frame must contain 6 bytes"
    return event


def decode_pdo(
    record: dict[str, Any],
    data: bytes,
    service: str,
    pdo_number: int,
    node_id: int,
) -> dict[str, Any]:
    event = base_event(record)
    event.update(
        {
            "service": service,
            "pdo_number": pdo_number,
            "node_id": node_id,
            "data": data.hex().upper(),
            "data_bytes": list(data),
            "note": "PDO signal names require EDS/DCF or a known mapping",
        }
    )
    for size in (1, 2, 4, 8):
        if len(data) >= size:
            event[f"le_u{size * 8}"] = le_uint(data[:size])
    if data:
        event["chunks_le_u16"] = [le_uint(data[index : index + 2]) for index in range(0, len(data) - 1, 2)]
        event["chunks_le_u32"] = [le_uint(data[index : index + 4]) for index in range(0, len(data) - 3, 4)]
    return event


def decode_sdo(record: dict[str, Any], data: bytes, direction: str, node_id: int) -> dict[str, Any]:
    event = base_event(record)
    event.update({"service": "SDO", "direction": direction, "node_id": node_id})
    if not data:
        event["malformed"] = True
        event["reason"] = "empty SDO frame"
        return event

    command = data[0]
    event["command_byte"] = f"0x{command:02X}"

    if len(data) >= 4:
        index = data[1] | (data[2] << 8)
        subindex = data[3]
        event["index"] = f"0x{index:04X}"
        event["subindex"] = f"0x{subindex:02X}"
    else:
        index = None
        subindex = None

    specifier = command >> 5
    if direction == "client_to_server":
        event["client_command_specifier"] = specifier
        if specifier == 1:
            event["operation"] = "initiate download request"
            add_expedited_sdo_value(event, command, data)
        elif specifier == 2:
            event["operation"] = "initiate upload request"
        elif specifier == 3:
            event["operation"] = "download segment request"
            event["toggle"] = bool(command & 0x10)
            event["no_more_segments"] = bool(command & 0x01)
            event["segment_data"] = data[1:].hex().upper()
        elif specifier == 4:
            event["operation"] = "abort transfer"
            add_sdo_abort(event, data)
        elif specifier == 5:
            event["operation"] = "block upload request"
        elif specifier == 6:
            event["operation"] = "block download request"
        else:
            event["operation"] = "unknown client request"
    else:
        event["server_command_specifier"] = specifier
        if command == 0x60:
            event["operation"] = "initiate download response"
        elif specifier == 2:
            event["operation"] = "upload segment response"
            event["toggle"] = bool(command & 0x10)
            event["no_more_segments"] = bool(command & 0x01)
            event["segment_data"] = data[1:].hex().upper()
        elif specifier == 3:
            event["operation"] = "initiate upload response"
            add_expedited_sdo_value(event, command, data)
        elif specifier == 4:
            event["operation"] = "abort transfer"
            add_sdo_abort(event, data)
        elif specifier == 5:
            event["operation"] = "block download response"
        elif specifier == 6:
            event["operation"] = "block upload response"
        else:
            event["operation"] = "unknown server response"

    if index is not None and subindex is not None:
        event["object"] = f"{index:04X}:{subindex:02X}"
    return event


def add_expedited_sdo_value(event: dict[str, Any], command: int, data: bytes) -> None:
    expedited = bool(command & 0x02)
    size_indicated = bool(command & 0x01)
    event["expedited"] = expedited
    event["size_indicated"] = size_indicated
    if not expedited or len(data) < 8:
        return

    unused = (command >> 2) & 0x03
    size = 4 - unused if size_indicated else 4
    value = data[4 : 4 + size]
    event["value_size"] = size
    event["value_hex"] = value.hex().upper()
    event["value"] = signed_or_unsigned(value)


def add_sdo_abort(event: dict[str, Any], data: bytes) -> None:
    if len(data) >= 8:
        abort_code = le_uint(data[4:8])
        event["abort_code"] = f"0x{abort_code:08X}"
        event["abort_description"] = SDO_ABORT_CODES.get(abort_code, "unknown")
    else:
        event["malformed"] = True
        event["reason"] = "SDO abort must contain 4-byte abort code"


def decode_heartbeat(record: dict[str, Any], data: bytes, node_id: int) -> dict[str, Any]:
    event = base_event(record)
    event.update({"service": "heartbeat", "node_id": node_id})
    if data:
        state = data[0]
        event["state"] = state
        event["state_name"] = HEARTBEAT_STATES.get(state, "unknown")
    else:
        event["malformed"] = True
        event["reason"] = "heartbeat must contain state byte"
    return event


def decode_lss(record: dict[str, Any], data: bytes, direction: str) -> dict[str, Any]:
    event = base_event(record)
    event.update(
        {
            "service": "LSS",
            "direction": direction,
            "command": f"0x{data[0]:02X}" if data else None,
            "data": data.hex().upper(),
        }
    )
    return event


def decode_frame(record: dict[str, Any]) -> dict[str, Any]:
    arbitration_id = parse_int(record.get("arbitration_id"))
    data = parse_data(record)
    if arbitration_id is None:
        event = base_event(record, protocol="unknown")
        event.update({"service": "unknown", "reason": "missing arbitration_id"})
        return event

    extended = bool(record.get("extended"))
    if extended:
        event = base_event(record, protocol="unknown")
        event.update({"service": "non-canopen", "reason": "CANopen base profile uses 11-bit identifiers"})
        return event

    if arbitration_id == 0x000:
        return decode_nmt(record, data)
    if arbitration_id == 0x080:
        return decode_sync(record, data)
    if 0x081 <= arbitration_id <= 0x0FF:
        return decode_emcy(record, data, arbitration_id - 0x080)
    if arbitration_id == 0x100:
        return decode_time(record, data)

    pdo_ranges = (
        (0x180, 0x1FF, "TPDO", 1),
        (0x200, 0x27F, "RPDO", 1),
        (0x280, 0x2FF, "TPDO", 2),
        (0x300, 0x37F, "RPDO", 2),
        (0x380, 0x3FF, "TPDO", 3),
        (0x400, 0x47F, "RPDO", 3),
        (0x480, 0x4FF, "TPDO", 4),
        (0x500, 0x57F, "RPDO", 4),
    )
    for start, end, service, number in pdo_ranges:
        if start <= arbitration_id <= end:
            return decode_pdo(record, data, service, number, arbitration_id - start)

    if 0x580 <= arbitration_id <= 0x5FF:
        return decode_sdo(record, data, "server_to_client", arbitration_id - 0x580)
    if 0x600 <= arbitration_id <= 0x67F:
        return decode_sdo(record, data, "client_to_server", arbitration_id - 0x600)
    if 0x700 <= arbitration_id <= 0x77F:
        return decode_heartbeat(record, data, arbitration_id - 0x700)
    if arbitration_id == 0x7E4:
        return decode_lss(record, data, "master_to_slave")
    if arbitration_id == 0x7E5:
        return decode_lss(record, data, "slave_to_master")

    event = base_event(record, protocol="unknown")
    event.update({"service": "unknown", "data": data.hex().upper()})
    return event


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                yield {
                    "type": "parse_error",
                    "line": line_number,
                    "error": str(error),
                    "raw": line,
                }
                continue
            record["_line"] = line_number
            yield record


def update_summary(summary: dict[str, Any], event: dict[str, Any]) -> None:
    service = event.get("service", "unknown")
    summary["services"][service] += 1
    node_id = event.get("node_id")
    if isinstance(node_id, int) and 1 <= node_id <= 127:
        node = summary["nodes"][str(node_id)]
        node["node_id"] = node_id
        node["services"][service] += 1
        if service == "heartbeat" and event.get("state_name"):
            node["last_state"] = event["state_name"]
            node["last_state_timestamp"] = event.get("timestamp")
        if service == "EMCY":
            node["emcy_count"] += 1
        if service == "SDO":
            node["sdo_count"] += 1


def counter_to_dict(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(value)
    if isinstance(value, defaultdict):
        return {key: counter_to_dict(item) for key, item in value.items()}
    if isinstance(value, dict):
        return {key: counter_to_dict(item) for key, item in value.items()}
    return value


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        log_path = resolve_log(args.log, args.logs_dir)
    except FileNotFoundError as error:
        print(f"Не удалось выбрать лог: {error}", file=sys.stderr)
        return 2

    out_dir = output_dir_for(log_path, args.parsed_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    decoded_path = out_dir / "canopen_decoded.jsonl"
    comments_path = out_dir / "comments.jsonl"
    summary_path = out_dir / "summary.json"
    nodes_path = out_dir / "nodes.json"

    summary: dict[str, Any] = {
        "source_log": str(log_path.resolve()),
        "parsed_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "frames_total": 0,
        "comments_total": 0,
        "metadata_records": 0,
        "decode_errors": 0,
        "services": Counter(),
        "nodes": defaultdict(lambda: {"services": Counter(), "emcy_count": 0, "sdo_count": 0}),
    }

    with decoded_path.open("w", encoding="utf-8", newline="\n") as decoded_file, comments_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as comments_file:
        for record in read_jsonl(log_path):
            record_type = record.get("type")
            if record_type == "metadata":
                summary["metadata_records"] += 1
                continue
            if record_type == "comment":
                summary["comments_total"] += 1
                comments_file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                decoded_event = {
                    "type": "comment",
                    "source_sequence": record.get("sequence"),
                    "timestamp": record.get("timestamp"),
                    "timestamp_epoch": record.get("timestamp_epoch"),
                    "text": record.get("text"),
                }
                decoded_file.write(json.dumps(decoded_event, ensure_ascii=False, separators=(",", ":")) + "\n")
                if args.stdout:
                    print(json.dumps(decoded_event, ensure_ascii=False))
                continue
            if record_type == "parse_error":
                summary["decode_errors"] += 1
                decoded_file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                continue
            if record_type not in (None, "frame"):
                continue

            summary["frames_total"] += 1
            event = decode_frame(record)
            update_summary(summary, event)
            decoded_file.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            if args.stdout:
                print(json.dumps(event, ensure_ascii=False))

    nodes = counter_to_dict(summary["nodes"])
    summary_for_json = counter_to_dict(summary)
    summary_for_json["nodes_total"] = len(nodes)
    write_json(summary_path, summary_for_json)
    write_json(nodes_path, nodes)

    print(f"Источник: {log_path.resolve()}", file=sys.stderr)
    print(f"Результат: {out_dir.resolve()}", file=sys.stderr)
    print(f"Декодировано кадров: {summary['frames_total']}", file=sys.stderr)
    print(f"Комментарии: {summary['comments_total']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
