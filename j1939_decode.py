"""Decode J1939 traffic from logs produced by can_log.py."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


GLOBAL_ADDRESS = 0xFF
NULL_ADDRESS = 0xFE

PGN_NAMES = {
    0x00EA00: "Request",
    0x00E800: "Acknowledgement",
    0x00EB00: "Transport Protocol - Data Transfer",
    0x00EC00: "Transport Protocol - Connection Management",
    0x00EE00: "Address Claimed / Cannot Claim",
    0x00F004: "Electronic Engine Controller 1 (EEC1)",
    0x00F003: "Electronic Engine Controller 2 (EEC2)",
    0x00F002: "Electronic Transmission Controller 1 (ETC1)",
    0x00FEEE: "Engine Temperature 1 (ET1)",
    0x00FEF1: "Cruise Control / Vehicle Speed (CCVS)",
    0x00FEF2: "Fuel Economy (LFE)",
    0x00FECA: "Active Diagnostic Trouble Codes (DM1)",
    0x00FECB: "Previously Active Diagnostic Trouble Codes (DM2)",
    0x00FEDA: "Software Identification",
    0x00FED8: "Vehicle Electrical Power 1",
    0x00FEE9: "Vehicle Hours",
    0x00FEE5: "Engine Hours / Revolutions",
}

TP_CM_CONTROL = {
    0x10: "RTS",
    0x11: "CTS",
    0x13: "EndOfMsgACK",
    0x20: "BAM",
    0xFF: "Abort",
}

ACK_CONTROL = {
    0x00: "ACK",
    0x01: "NACK",
    0x02: "AccessDenied",
    0x03: "CannotRespond",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Декодировать SAE J1939 из JSONL-лога can_log.py. "
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


def pgn_hex(pgn: int) -> str:
    return f"0x{pgn:05X}"


def parse_j1939_id(arbitration_id: int) -> dict[str, Any]:
    priority = (arbitration_id >> 26) & 0x07
    extended_data_page = (arbitration_id >> 25) & 0x01
    data_page = (arbitration_id >> 24) & 0x01
    pdu_format = (arbitration_id >> 16) & 0xFF
    pdu_specific = (arbitration_id >> 8) & 0xFF
    source_address = arbitration_id & 0xFF
    pdu_type = "PDU1" if pdu_format < 240 else "PDU2"
    destination_address = pdu_specific if pdu_format < 240 else None
    group_extension = None if pdu_format < 240 else pdu_specific
    pgn = (
        (extended_data_page << 17)
        | (data_page << 16)
        | (pdu_format << 8)
        | (0 if pdu_format < 240 else pdu_specific)
    )
    return {
        "priority": priority,
        "extended_data_page": extended_data_page,
        "data_page": data_page,
        "pdu_format": pdu_format,
        "pdu_specific": pdu_specific,
        "pdu_type": pdu_type,
        "pgn": pgn,
        "pgn_hex": pgn_hex(pgn),
        "pgn_name": PGN_NAMES.get(pgn, "unknown"),
        "source_address": source_address,
        "destination_address": destination_address,
        "destination": (
            "global"
            if destination_address == GLOBAL_ADDRESS
            else (f"0x{destination_address:02X}" if destination_address is not None else None)
        ),
        "group_extension": group_extension,
    }


def base_event(record: dict[str, Any], protocol: str = "j1939") -> dict[str, Any]:
    event = {
        "type": "decoded",
        "protocol": protocol,
        "source_sequence": record.get("sequence"),
        "timestamp": record.get("timestamp"),
        "timestamp_epoch": record.get("timestamp_epoch"),
        "can_id": record.get("id"),
        "arbitration_id": record.get("arbitration_id"),
    }
    for key in ("direction", "source"):
        if key in record:
            event[key] = record[key]
    return event


def add_raw_payload(event: dict[str, Any], data: bytes) -> None:
    event["dlc"] = len(data)
    event["data"] = data.hex().upper()
    event["data_bytes"] = list(data)
    for size in (1, 2, 4, 8):
        if len(data) >= size:
            event[f"le_u{size * 8}"] = le_uint(data[:size])


def scaled(
    data: bytes,
    start: int,
    length: int,
    factor: float,
    offset: float = 0.0,
    *,
    unavailable: int | None = None,
) -> float | None:
    if len(data) < start + length:
        return None
    raw = le_uint(data[start : start + length])
    if unavailable is not None and raw == unavailable:
        return None
    return raw * factor + offset


def decode_request(data: bytes) -> dict[str, Any]:
    if len(data) < 3:
        return {"malformed": True, "reason": "Request PGN must contain 3-byte requested PGN"}
    requested = data[0] | (data[1] << 8) | (data[2] << 16)
    return {
        "requested_pgn": requested,
        "requested_pgn_hex": pgn_hex(requested),
        "requested_pgn_name": PGN_NAMES.get(requested, "unknown"),
    }


def decode_ack(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        return {"malformed": True, "reason": "ACK PGN normally contains 8 bytes"}
    requested = data[5] | (data[6] << 8) | (data[7] << 16)
    return {
        "ack_control": data[0],
        "ack_control_name": ACK_CONTROL.get(data[0], "unknown"),
        "group_function": data[1],
        "address_acknowledged": data[4],
        "acknowledged_pgn": requested,
        "acknowledged_pgn_hex": pgn_hex(requested),
        "acknowledged_pgn_name": PGN_NAMES.get(requested, "unknown"),
    }


def decode_tp_cm(data: bytes) -> dict[str, Any]:
    if not data:
        return {"malformed": True, "reason": "TP.CM frame is empty"}
    control = data[0]
    result: dict[str, Any] = {
        "tp_control": control,
        "tp_control_name": TP_CM_CONTROL.get(control, "unknown"),
    }
    if len(data) >= 8:
        pgn = data[5] | (data[6] << 8) | (data[7] << 16)
        result["target_pgn"] = pgn
        result["target_pgn_hex"] = pgn_hex(pgn)
        result["target_pgn_name"] = PGN_NAMES.get(pgn, "unknown")
    if control in (0x10, 0x20) and len(data) >= 8:
        result["total_message_size"] = data[1] | (data[2] << 8)
        result["total_packets"] = data[3]
        if control == 0x10:
            result["max_packets_per_cts"] = data[4]
    elif control == 0x11 and len(data) >= 8:
        result["packets_to_send"] = data[1]
        result["next_packet_number"] = data[2]
    elif control == 0x13 and len(data) >= 8:
        result["total_message_size"] = data[1] | (data[2] << 8)
        result["total_packets"] = data[3]
    elif control == 0xFF and len(data) >= 8:
        result["abort_reason"] = data[1]
    return result


def decode_tp_dt(data: bytes) -> dict[str, Any]:
    if not data:
        return {"malformed": True, "reason": "TP.DT frame is empty"}
    return {
        "sequence_number": data[0],
        "segment_data": data[1:].hex().upper(),
        "segment_data_bytes": list(data[1:]),
    }


def decode_address_claim(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        return {"malformed": True, "reason": "Address Claim NAME must contain 8 bytes"}
    name = le_uint(data[:8])
    identity_number = name & 0x1FFFFF
    manufacturer_code = (name >> 21) & 0x7FF
    ecu_instance = (name >> 32) & 0x7
    function_instance = (name >> 35) & 0x1F
    function = (name >> 40) & 0xFF
    vehicle_system = (name >> 49) & 0x7F
    arbitrary_address_capable = (name >> 63) & 0x01
    return {
        "name": f"0x{name:016X}",
        "identity_number": identity_number,
        "manufacturer_code": manufacturer_code,
        "ecu_instance": ecu_instance,
        "function_instance": function_instance,
        "function": function,
        "vehicle_system": vehicle_system,
        "arbitrary_address_capable": bool(arbitrary_address_capable),
    }


def decode_dm(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if len(data) >= 2:
        result["lamp_status_byte_1"] = f"0x{data[0]:02X}"
        result["lamp_status_byte_2"] = f"0x{data[1]:02X}"
    dtcs = []
    for index in range(2, len(data) - 3, 4):
        chunk = data[index : index + 4]
        raw1 = chunk[0] | (chunk[1] << 8) | ((chunk[2] & 0xE0) << 11)
        fmi = chunk[2] & 0x1F
        occurrence_count = chunk[3] & 0x7F
        conversion_method = (chunk[3] >> 7) & 0x01
        if raw1 == 0x7FFFF and fmi == 0x1F:
            continue
        dtcs.append(
            {
                "spn": raw1,
                "fmi": fmi,
                "occurrence_count": occurrence_count,
                "conversion_method": conversion_method,
            }
        )
    result["dtcs"] = dtcs
    return result


def decode_known_pgn(pgn: int, data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if pgn == 0x00EA00:
        result.update(decode_request(data))
    elif pgn == 0x00E800:
        result.update(decode_ack(data))
    elif pgn == 0x00EC00:
        result.update(decode_tp_cm(data))
    elif pgn == 0x00EB00:
        result.update(decode_tp_dt(data))
    elif pgn == 0x00EE00:
        result.update(decode_address_claim(data))
    elif pgn == 0x00F004:
        result["signals"] = {
            "engine_torque_mode": data[0] & 0x0F if len(data) >= 1 else None,
            "driver_demand_engine_percent_torque_pct": (data[1] - 125) if len(data) >= 2 and data[1] != 0xFF else None,
            "actual_engine_percent_torque_pct": (data[2] - 125) if len(data) >= 3 and data[2] != 0xFF else None,
            "engine_speed_rpm": scaled(data, 3, 2, 0.125, unavailable=0xFFFF),
            "source_address_of_controlling_device": data[5] if len(data) >= 6 and data[5] != 0xFF else None,
        }
    elif pgn == 0x00F003:
        result["signals"] = {
            "accelerator_pedal_position_1_pct": scaled(data, 1, 1, 0.4, unavailable=0xFF),
            "engine_percent_load_at_current_speed_pct": scaled(data, 2, 1, 1.0, unavailable=0xFF),
            "remote_accelerator_pedal_position_pct": scaled(data, 3, 1, 0.4, unavailable=0xFF),
        }
    elif pgn == 0x00FEEE:
        result["signals"] = {
            "engine_coolant_temperature_deg_c": scaled(data, 0, 1, 1.0, -40.0, unavailable=0xFF),
            "fuel_temperature_deg_c": scaled(data, 1, 1, 1.0, -40.0, unavailable=0xFF),
            "engine_oil_temperature_deg_c": scaled(data, 2, 2, 0.03125, -273.0, unavailable=0xFFFF),
            "turbo_oil_temperature_deg_c": scaled(data, 4, 2, 0.03125, -273.0, unavailable=0xFFFF),
            "engine_intercooler_temperature_deg_c": scaled(data, 6, 1, 1.0, -40.0, unavailable=0xFF),
        }
    elif pgn == 0x00FEF1:
        result["signals"] = {
            "wheel_based_vehicle_speed_kph": scaled(data, 1, 2, 1.0 / 256.0, unavailable=0xFFFF),
            "clutch_switch": (data[3] >> 6) & 0x03 if len(data) >= 4 else None,
            "brake_switch": (data[3] >> 4) & 0x03 if len(data) >= 4 else None,
            "cruise_control_active": data[3] & 0x03 if len(data) >= 4 else None,
            "cruise_control_set_speed_kph": scaled(data, 4, 1, 1.0, unavailable=0xFF),
        }
    elif pgn == 0x00FEF2:
        result["signals"] = {
            "fuel_rate_l_per_h": scaled(data, 0, 2, 0.05, unavailable=0xFFFF),
            "instantaneous_fuel_economy_km_per_l": scaled(data, 2, 2, 1.0 / 512.0, unavailable=0xFFFF),
            "average_fuel_economy_km_per_l": scaled(data, 4, 2, 1.0 / 512.0, unavailable=0xFFFF),
        }
    elif pgn in (0x00FECA, 0x00FECB):
        result.update(decode_dm(data))
    elif pgn == 0x00FED8:
        result["signals"] = {
            "battery_potential_power_input_1_v": scaled(data, 0, 2, 0.05, unavailable=0xFFFF),
            "battery_potential_power_input_2_v": scaled(data, 2, 2, 0.05, unavailable=0xFFFF),
            "alternator_current_a": scaled(data, 4, 2, 1.0, -125.0, unavailable=0xFFFF),
        }
    elif pgn == 0x00FEE5:
        result["signals"] = {
            "total_engine_hours_h": scaled(data, 0, 4, 0.05, unavailable=0xFFFFFFFF),
            "total_engine_revolutions": scaled(data, 4, 4, 1000.0, unavailable=0xFFFFFFFF),
        }
    elif pgn == 0x00FEE9:
        result["signals"] = {
            "total_vehicle_hours_h": scaled(data, 0, 4, 0.05, unavailable=0xFFFFFFFF),
            "total_power_takeoff_hours_h": scaled(data, 4, 4, 0.05, unavailable=0xFFFFFFFF),
        }
    return result


def decode_frame(record: dict[str, Any]) -> dict[str, Any]:
    arbitration_id = parse_int(record.get("arbitration_id"))
    data = parse_data(record)
    if arbitration_id is None:
        event = base_event(record, protocol="unknown")
        event.update({"service": "unknown", "reason": "missing arbitration_id"})
        return event

    event = base_event(record)
    add_raw_payload(event, data)

    if not bool(record.get("extended")):
        event["protocol"] = "unknown"
        event["service"] = "non-j1939"
        event["reason"] = "J1939 uses 29-bit extended CAN identifiers"
        return event

    fields = parse_j1939_id(arbitration_id)
    event.update(fields)
    event["service"] = fields["pgn_name"]
    event.update(decode_known_pgn(fields["pgn"], data))
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
    pgn = event.get("pgn_hex")
    source_address = event.get("source_address")
    summary["services"][service] += 1
    if pgn is not None:
        summary["pgns"][pgn] += 1
    if isinstance(source_address, int):
        source = summary["source_addresses"][f"0x{source_address:02X}"]
        source["source_address"] = source_address
        source["frames"] += 1
        source["pgns"][pgn or "unknown"] += 1
        source["services"][service] += 1


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

    decoded_path = out_dir / "j1939_decoded.jsonl"
    comments_path = out_dir / "j1939_comments.jsonl"
    summary_path = out_dir / "j1939_summary.json"
    sources_path = out_dir / "j1939_sources.json"

    summary: dict[str, Any] = {
        "source_log": str(log_path.resolve()),
        "parsed_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "frames_total": 0,
        "comments_total": 0,
        "metadata_records": 0,
        "decode_errors": 0,
        "services": Counter(),
        "pgns": Counter(),
        "source_addresses": defaultdict(
            lambda: {"frames": 0, "pgns": Counter(), "services": Counter()}
        ),
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

    sources = counter_to_dict(summary["source_addresses"])
    summary_for_json = counter_to_dict(summary)
    summary_for_json["source_addresses_total"] = len(sources)
    write_json(summary_path, summary_for_json)
    write_json(sources_path, sources)

    print(f"Источник: {log_path.resolve()}", file=sys.stderr)
    print(f"Результат: {out_dir.resolve()}", file=sys.stderr)
    print(f"Декодировано кадров: {summary['frames_total']}", file=sys.stderr)
    print(f"Комментарии: {summary['comments_total']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
