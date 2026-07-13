"""D65 CANopen live monitor, raw logger, replay tool, and signal decoder.

Live capture uses the same hardware listen-only readers as can_log.py. Replay
and live frames pass through one decoder and produce identical parsedD65
artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

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
from canopen_decode import HEARTBEAT_STATES, decode_frame, resolve_log
from canopen_live_monitor import IO_TPDO1_SIGNALS, NODE_NAMES
from d65_dashboard import DashboardServer


PARSED_DIR_DEFAULT = Path("parsedD65")

# These endpoints use PDO-shaped identifiers but did not publish heartbeat in
# the captured D65 log. The pairing is structural and remains an inference.
ENDPOINT_NAMES = {
    26: "CPU1-IMAGE",
    27: "CPU3-IMAGE",
    29: "CPU2-IMAGE",
}


@dataclass(frozen=True)
class SignalDefinition:
    key: str
    name: str
    node_id: int
    node_name: str
    cob_id: int
    service: str
    pdo_number: int
    byte: int
    bit: int
    pin: int | None = None
    source: str = "electrical schematic"
    confidence: str = "confirmed"


@dataclass(frozen=True)
class AnalogDefinition:
    key: str
    name: str
    cob_id: int
    node_id: int
    node_name: str
    service: str
    pdo_number: int
    byte: int
    length: int
    scale: float
    offset: float
    unit: str
    raw_unit: str
    signed: bool = False
    byte_order: str = "little"
    source: str = "protocol analysis"
    confidence: str = "confirmed"


@dataclass
class SignalState:
    definition: SignalDefinition
    value: bool | None = None
    updates: int = 0
    changes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_changed: float = 0.0

    @property
    def state_text(self) -> str:
        if self.value is None:
            return "UNKNOWN"
        return "ON" if self.value else "OFF"


@dataclass
class AnalogState:
    definition: AnalogDefinition
    value: float | None = None
    raw_value: int | None = None
    updates: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    samples: deque[tuple[float, float]] = field(default_factory=lambda: deque(maxlen=300))


@dataclass
class PdoState:
    service: str
    number: int
    cob_id: int
    data: bytes = b""
    count: int = 0
    changes: int = 0
    first_seen: float = 0.0
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
    mode: str
    started_wall: float = field(default_factory=time.time)
    first_source_epoch: float = 0.0
    last_source_epoch: float = 0.0
    frames: int = 0
    comments: int = 0
    decode_errors: int = 0
    signal_change_count: int = 0
    services: Counter[str] = field(default_factory=Counter)
    nodes: dict[int, NodeState] = field(default_factory=dict)
    signals: dict[str, SignalState] = field(default_factory=dict)
    analog: dict[str, AnalogState] = field(default_factory=dict)
    recent_events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=50))
    last_frame: str = "-"
    last_error: str = ""

    def node(self, node_id: int) -> NodeState:
        if node_id not in self.nodes:
            name = NODE_NAMES.get(node_id, ENDPOINT_NAMES.get(node_id, f"node-{node_id}"))
            self.nodes[node_id] = NodeState(node_id=node_id, name=name)
        return self.nodes[node_id]


def build_signal_catalog() -> dict[str, SignalDefinition]:
    catalog: dict[str, SignalDefinition] = {}
    for node_id, pin_map in IO_TPDO1_SIGNALS.items():
        node_name = NODE_NAMES[node_id]
        for pin, name in pin_map.items():
            if name == "GND":
                continue
            bit_index = pin - 1
            definition = SignalDefinition(
                key=f"{node_name}.X3.{pin:02d}",
                name=name,
                node_id=node_id,
                node_name=node_name,
                cob_id=0x180 + node_id,
                service="TPDO",
                pdo_number=1,
                byte=(bit_index // 8) + 1,
                bit=bit_index % 8,
                pin=pin,
            )
            catalog[definition.key] = definition

    inferred = (
        SignalDefinition(
            key="CPU3.RPDO4.CABIN_WARNING",
            name="S186-A3 CABIN WARNING ROUTED TO CPU3",
            node_id=17,
            node_name="CPU3",
            cob_id=0x511,
            service="RPDO",
            pdo_number=4,
            byte=1,
            bit=6,
            source="horn log correlation",
            confidence="high",
        ),
        SignalDefinition(
            key="CPU1-IMAGE.TPDO4.CABIN_WARNING",
            name="S186-A3 CABIN WARNING IN CPU1 PROCESS IMAGE",
            node_id=26,
            node_name="CPU1-IMAGE",
            cob_id=0x49A,
            service="TPDO",
            pdo_number=4,
            byte=2,
            bit=4,
            source="horn log correlation",
            confidence="high",
        ),
        SignalDefinition(
            key="CPU3-IMAGE.TPDO4.CABIN_WARNING",
            name="S186-A3 CABIN WARNING IN CPU3 PROCESS IMAGE",
            node_id=27,
            node_name="CPU3-IMAGE",
            cob_id=0x49B,
            service="TPDO",
            pdo_number=4,
            byte=3,
            bit=2,
            source="horn log correlation",
            confidence="high",
        ),
    )
    for definition in inferred:
        catalog[definition.key] = definition
    return catalog


SIGNAL_CATALOG = build_signal_catalog()
SIGNALS_BY_COB_ID: dict[int, list[SignalDefinition]] = {}
for _definition in SIGNAL_CATALOG.values():
    SIGNALS_BY_COB_ID.setdefault(_definition.cob_id, []).append(_definition)

ANALOG_CATALOG: tuple[AnalogDefinition, ...] = (
    AnalogDefinition(
        key="CPU1.TPDO1.Y206A_CURRENT",
        name="Y206A TRAMMING LEFT FORWARD actual current",
        node_id=16,
        node_name="CPU1",
        cob_id=0x190,
        service="TPDO",
        pdo_number=1,
        byte=0,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="mA",
        raw_unit="mA",
        source="d65_nodes.yaml cpu1_tpdo1_tramming_pwm_feedback",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU1.TPDO1.Y206B_CURRENT",
        name="Y206B TRAMMING LEFT BACKWARD actual current",
        node_id=16,
        node_name="CPU1",
        cob_id=0x190,
        service="TPDO",
        pdo_number=1,
        byte=2,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="mA",
        raw_unit="mA",
        source="d65_nodes.yaml cpu1_tpdo1_tramming_pwm_feedback",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU1.TPDO1.Y207A_CURRENT",
        name="Y207A TRAMMING RIGHT FORWARD actual current",
        node_id=16,
        node_name="CPU1",
        cob_id=0x190,
        service="TPDO",
        pdo_number=1,
        byte=4,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="mA",
        raw_unit="mA",
        source="d65_nodes.yaml cpu1_tpdo1_tramming_pwm_feedback",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU1.TPDO1.Y207B_CURRENT",
        name="Y207B TRAMMING RIGHT BACKWARD actual current",
        node_id=16,
        node_name="CPU1",
        cob_id=0x190,
        service="TPDO",
        pdo_number=1,
        byte=6,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="mA",
        raw_unit="mA",
        source="d65_nodes.yaml cpu1_tpdo1_tramming_pwm_feedback",
        confidence="high",
    ),
    AnalogDefinition(
        key="D553.TPDO2.S174A_FORWARD",
        name="S174A TRAMMING LEFT FORWARD",
        node_id=5,
        node_name="D553",
        cob_id=0x285,
        service="TPDO",
        pdo_number=2,
        byte=0,
        length=2,
        scale=1.0 / 1.2,
        offset=-(2.0 / 1.2),
        unit="%",
        raw_unit="RM",
        source="d65_nodes.yaml d553_tpdo2_tramming_joysticks",
        confidence="high",
    ),
    AnalogDefinition(
        key="D553.TPDO2.S174B_BACKWARD",
        name="S174B TRAMMING LEFT BACKWARD",
        node_id=5,
        node_name="D553",
        cob_id=0x285,
        service="TPDO",
        pdo_number=2,
        byte=2,
        length=2,
        scale=1.0 / 1.2,
        offset=-(2.0 / 1.2),
        unit="%",
        raw_unit="RM",
        source="d65_nodes.yaml d553_tpdo2_tramming_joysticks",
        confidence="high",
    ),
    AnalogDefinition(
        key="D553.TPDO2.S175A_FORWARD",
        name="S175A TRAMMING RIGHT FORWARD",
        node_id=5,
        node_name="D553",
        cob_id=0x285,
        service="TPDO",
        pdo_number=2,
        byte=4,
        length=2,
        scale=1.0 / 1.2,
        offset=-(2.0 / 1.2),
        unit="%",
        raw_unit="RM",
        source="d65_nodes.yaml d553_tpdo2_tramming_joysticks",
        confidence="high",
    ),
    AnalogDefinition(
        key="D553.TPDO2.S175B_BACKWARD",
        name="S175B TRAMMING RIGHT BACKWARD",
        node_id=5,
        node_name="D553",
        cob_id=0x285,
        service="TPDO",
        pdo_number=2,
        byte=6,
        length=2,
        scale=1.0 / 1.2,
        offset=-(2.0 / 1.2),
        unit="%",
        raw_unit="RM",
        source="d65_nodes.yaml d553_tpdo2_tramming_joysticks",
        confidence="high",
    ),
    AnalogDefinition(
        key="D552.TPDO2.S272_WATER_MIST_FLOW_RAW",
        name="S272 WATER MIST FLOW raw",
        node_id=6,
        node_name="D552",
        cob_id=0x286,
        service="TPDO",
        pdo_number=2,
        byte=6,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="RM",
        raw_unit="RM",
        source="d65_nodes.yaml d552_tpdo2_watermist_flow",
        confidence="high; engineering scale unknown",
    ),
    AnalogDefinition(
        key="CPU3.TPDO1.Y504_CURRENT",
        name="Y504 COOLING FAN HYDRAULIC OIL AND COMPRESSOR OIL actual current",
        node_id=17,
        node_name="CPU3",
        cob_id=0x191,
        service="TPDO",
        pdo_number=1,
        byte=0,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="mA",
        raw_unit="mA",
        source="d65_nodes.yaml pwm_feedback_candidates",
        confidence="inferred",
    ),
    AnalogDefinition(
        key="CPU3.TPDO2.Y501_CURRENT",
        name="Y501 COOLING FAN DIESEL MOTOR actual current",
        node_id=17,
        node_name="CPU3",
        cob_id=0x291,
        service="TPDO",
        pdo_number=2,
        byte=6,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="mA",
        raw_unit="mA",
        source="d65_nodes.yaml pwm_feedback_candidates",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU3.TPDO3.B147_AMBIENT_TEMP",
        name="B147 AMBIENT TEMP",
        node_id=17,
        node_name="CPU3",
        cob_id=0x391,
        service="TPDO",
        pdo_number=3,
        byte=6,
        length=2,
        scale=1.0 / 80.0,
        offset=-100.0,
        unit="degC",
        raw_unit="uA",
        source="d65_nodes.yaml analog_pdo_candidates",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU3.TPDO4.B362_HYDRAULIC_OIL_TEMP",
        name="B362 HYDRAULIC OIL TEMP",
        node_id=17,
        node_name="CPU3",
        cob_id=0x491,
        service="TPDO",
        pdo_number=4,
        byte=0,
        length=2,
        scale=1.0 / 80.0,
        offset=-100.0,
        unit="degC",
        raw_unit="uA",
        source="d65_nodes.yaml analog_pdo_candidates",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU3.TPDO4.B366A_COMPRESSOR_TEMP_HIGH",
        name="B366A COMPRESSOR TEMP HIGH STAGE",
        node_id=17,
        node_name="CPU3",
        cob_id=0x491,
        service="TPDO",
        pdo_number=4,
        byte=2,
        length=2,
        scale=1.0 / 80.0,
        offset=-100.0,
        unit="degC",
        raw_unit="uA",
        source="d65_nodes.yaml analog_pdo_candidates",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU3.TPDO4.B366B_COMPRESSOR_TEMP_LOW",
        name="B366B COMPRESSOR TEMP LOW STAGE",
        node_id=17,
        node_name="CPU3",
        cob_id=0x491,
        service="TPDO",
        pdo_number=4,
        byte=4,
        length=2,
        scale=1.0 / 80.0,
        offset=-100.0,
        unit="degC",
        raw_unit="uA",
        source="d65_nodes.yaml analog_pdo_candidates",
        confidence="high",
    ),
    AnalogDefinition(
        key="CPU2.TPDO3.B460_COMPRESSOR_OIL_STOP_VALVE_PRESSURE_RAW",
        name="B460 COMPRESSOR OIL STOP VALVE PRESSURE raw",
        node_id=19,
        node_name="CPU2",
        cob_id=0x393,
        service="TPDO",
        pdo_number=3,
        byte=4,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="uA",
        raw_unit="uA",
        source="d65_nodes.yaml analog_pdo_candidates",
        confidence="high for raw channel identity; engineering pressure scale unknown",
    ),
    AnalogDefinition(
        key="CPU2.TPDO3.B456_VESSEL_PRESSURE_RAW",
        name="B456 VESSEL PRESSURE raw",
        node_id=19,
        node_name="CPU2",
        cob_id=0x393,
        service="TPDO",
        pdo_number=3,
        byte=6,
        length=2,
        scale=1.0,
        offset=0.0,
        unit="mV",
        raw_unit="mV",
        source="d65_nodes.yaml analog_pdo_candidates",
        confidence="high for raw channel identity; engineering pressure scale unknown",
    ),
    AnalogDefinition(
        key="CPU2.TPDO4.B352_DIESEL_LEVEL",
        name="B352 DIESEL LEVEL",
        node_id=19,
        node_name="CPU2",
        cob_id=0x493,
        service="TPDO",
        pdo_number=4,
        byte=2,
        length=2,
        scale=1.0 / 1.5,
        offset=0.0,
        unit="%",
        raw_unit="RM",
        source="d65_nodes.yaml analog_pdo_candidates",
        confidence="high raw identity; percent scale inferred from one HMI point",
    ),
)
ANALOG_BY_COB_ID: dict[int, list[AnalogDefinition]] = {}
for _definition in ANALOG_CATALOG:
    ANALOG_BY_COB_ID.setdefault(_definition.cob_id, []).append(_definition)


def dashboard_port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("dashboard port must be an integer") from error
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("dashboard port must be between 0 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Monitor D65 CANopen signals without scrolling, write the raw live "
            "JSONL log, and save decoded artifacts under parsedD65."
        )
    )
    parser.add_argument("log_name", nargs="?", type=safe_log_name, default="D65_canopen_live_v2")
    parser.add_argument("--logs-dir", type=Path, default=Path("logs"))
    parser.add_argument("--parsed-dir", type=Path, default=PARSED_DIR_DEFAULT)
    parser.add_argument(
        "--device",
        "--adapter",
        dest="device",
        choices=("zubax", "raccoonlab", "slcan", "candlelight", "canable", "gs_usb"),
        help="same passive adapter selector as can_log.py",
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
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="serve and open the read-only browser dashboard",
    )
    parser.add_argument(
        "--dashboard-host",
        default="127.0.0.1",
        help="dashboard bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--dashboard-port",
        type=dashboard_port,
        default=8765,
        help="preferred dashboard port; tries the next 19 ports if busy (default: 8765)",
    )
    parser.add_argument(
        "--dashboard-no-open",
        action="store_true",
        help="start the dashboard server without opening a browser tab",
    )
    parser.add_argument(
        "--playback-log",
        help="existing JSONL path, filename, or unique part of a filename from logs/",
    )
    parser.add_argument(
        "--replay-rate",
        type=non_negative_float,
        default=0.0,
        help="0 parses immediately; 1 preserves timing; 2 is twice real time",
    )
    parser.add_argument(
        "--focus-node",
        type=int,
        choices=tuple(sorted(IO_TPDO1_SIGNALS)),
        help="show one I/O module with full signal names instead of five columns",
    )
    parser.add_argument("--no-screen", action="store_true", help="disable the terminal dashboard")
    parser.add_argument(
        "--duration",
        type=non_negative_float,
        default=0.0,
        help="stop live capture after N seconds; 0 waits for Ctrl+C",
    )
    return parser


def parse_data(record: dict[str, Any]) -> bytes:
    raw = record.get("data")
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return b""
    values = record.get("data_bytes")
    if isinstance(values, list):
        try:
            return bytes(int(value) & 0xFF for value in values)
        except (TypeError, ValueError):
            return b""
    return b""


def source_epoch(record: dict[str, Any]) -> float:
    value = record.get("timestamp_epoch")
    if isinstance(value, (int, float)):
        return float(value)
    return time.time()


def generic_values(data: bytes) -> dict[str, Any]:
    return {
        "bytes_u8": list(data),
        "le_u16": [int.from_bytes(data[index : index + 2], "little") for index in range(0, len(data) - 1, 2)],
        "le_i16": [int.from_bytes(data[index : index + 2], "little", signed=True) for index in range(0, len(data) - 1, 2)],
    }


def frame_label(record: dict[str, Any]) -> str:
    data = parse_data(record)
    return f"{record.get('id', '?')} DLC={record.get('dlc', len(data))} DATA={data.hex(' ').upper() or '-'}"


def signal_value(data: bytes, definition: SignalDefinition) -> bool | None:
    byte_index = definition.byte - 1
    if byte_index >= len(data):
        return None
    return bool(data[byte_index] & (1 << definition.bit))


def analog_record(analog: AnalogState) -> dict[str, Any]:
    definition = analog.definition
    return {
        **asdict(definition),
        "value": analog.value,
        "raw_value": analog.raw_value,
        "updates": analog.updates,
        "first_seen": analog.first_seen or None,
        "last_seen": analog.last_seen or None,
    }


def update_analog_channels(state: MonitorState, cob_id: int, data: bytes, timestamp: float) -> list[dict[str, Any]]:
    decoded: list[dict[str, Any]] = []
    for definition in ANALOG_BY_COB_ID.get(cob_id, []):
        start = definition.byte
        end = start + definition.length
        if start < 0 or end > len(data):
            continue
        raw_value = int.from_bytes(
            data[start:end],
            byteorder=definition.byte_order,
            signed=definition.signed,
        )
        value = raw_value * definition.scale + definition.offset
        analog = state.analog.get(definition.key)
        if analog is None:
            analog = AnalogState(definition=definition)
            state.analog[definition.key] = analog
        if not analog.updates:
            analog.first_seen = timestamp
        analog.raw_value = raw_value
        analog.value = value
        analog.updates += 1
        analog.last_seen = timestamp
        analog.samples.append((timestamp, value))
        decoded.append(
            {
                "key": definition.key,
                "name": definition.name,
                "value": value,
                "raw_value": raw_value,
                "unit": definition.unit,
                "raw_unit": definition.raw_unit,
                "byte": definition.byte,
                "length": definition.length,
                "confidence": definition.confidence,
            }
        )
    return decoded


def signal_record(signal: SignalState) -> dict[str, Any]:
    definition = signal.definition
    return {
        **asdict(definition),
        "value": signal.value,
        "state": signal.state_text,
        "updates": signal.updates,
        "changes": signal.changes,
        "first_seen": signal.first_seen or None,
        "last_seen": signal.last_seen or None,
        "last_changed": signal.last_changed or None,
    }


def update_signal(
    state: MonitorState,
    definition: SignalDefinition,
    value: bool | None,
    timestamp: float,
    record: dict[str, Any],
) -> tuple[SignalState, dict[str, Any] | None]:
    signal = state.signals.get(definition.key)
    if signal is None:
        signal = SignalState(definition=definition)
        state.signals[definition.key] = signal

    previous = signal.value
    initial = signal.updates == 0
    signal.updates += 1
    if initial:
        signal.first_seen = timestamp
    signal.last_seen = timestamp
    signal.value = value

    if not initial and previous == value:
        return signal, None

    if not initial:
        signal.changes += 1
        state.signal_change_count += 1
    signal.last_changed = timestamp
    change = {
        "type": "signal_state",
        "source_sequence": record.get("sequence"),
        "timestamp": record.get("timestamp"),
        "timestamp_epoch": timestamp,
        "initial": initial,
        "key": definition.key,
        "name": definition.name,
        "node_id": definition.node_id,
        "node_name": definition.node_name,
        "cob_id": f"0x{definition.cob_id:03X}",
        "previous": previous,
        "value": value,
        "state": "UNKNOWN" if value is None else ("ON" if value else "OFF"),
        "pin": definition.pin,
        "byte": definition.byte,
        "bit": definition.bit,
        "confidence": definition.confidence,
    }
    return signal, change


def decode_d65_frame(
    state: MonitorState, record: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    timestamp = source_epoch(record)
    if not state.first_source_epoch:
        state.first_source_epoch = timestamp
    state.last_source_epoch = timestamp
    state.frames += 1
    state.last_frame = frame_label(record)

    try:
        event = decode_frame(record)
    except Exception as error:
        state.decode_errors += 1
        state.last_error = f"decode error: {error}"
        event = {
            "type": "decode_error",
            "source_sequence": record.get("sequence"),
            "timestamp": record.get("timestamp"),
            "timestamp_epoch": timestamp,
            "error": str(error),
        }
        return event, []

    arbitration_id = record.get("arbitration_id")
    if arbitration_id == 0x07F:
        event.update({"protocol": "d65_canopen", "service": "FAST_SYNC", "role": "proprietary fast cycle marker"})
    elif arbitration_id == 0x002:
        event.update({"protocol": "d65_canopen", "service": "D65_CONTROL", "role": "proprietary high-priority control"})
    else:
        event["protocol"] = "d65_canopen"

    service = str(event.get("service", "unknown"))
    state.services[service] += 1
    node_id = event.get("node_id")
    if isinstance(node_id, int):
        node = state.node(node_id)
        event["node_name"] = node.name
        if node_id in ENDPOINT_NAMES:
            event["node_role"] = "inferred process-image endpoint"

        if service == "heartbeat":
            state_byte = event.get("state")
            if isinstance(state_byte, int):
                node.heartbeat = HEARTBEAT_STATES.get(state_byte, f"0x{state_byte:02X}")
            else:
                node.heartbeat = str(event.get("state_name") or "?")
            node.heartbeat_seen = timestamp

        if service in ("TPDO", "RPDO"):
            pdo_number = event.get("pdo_number")
            if isinstance(pdo_number, int) and isinstance(arbitration_id, int):
                payload = parse_data(record)
                key = (service, pdo_number)
                pdo = node.pdo.get(key)
                if pdo is None:
                    pdo = PdoState(service=service, number=pdo_number, cob_id=arbitration_id)
                    node.pdo[key] = pdo
                if pdo.count and pdo.data != payload:
                    pdo.changes += 1
                if not pdo.count:
                    pdo.first_seen = timestamp
                pdo.data = payload
                pdo.count += 1
                pdo.last_seen = timestamp
                event["values"] = generic_values(payload)

    payload = parse_data(record)
    decoded_signals: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    if isinstance(arbitration_id, int):
        decoded_analog = update_analog_channels(state, arbitration_id, payload, timestamp)
        if decoded_analog:
            event["analog"] = decoded_analog
        for definition in SIGNALS_BY_COB_ID.get(arbitration_id, []):
            value = signal_value(payload, definition)
            signal, change = update_signal(state, definition, value, timestamp, record)
            decoded_signals.append(
                {
                    "key": definition.key,
                    "name": definition.name,
                    "value": value,
                    "state": signal.state_text,
                    "pin": definition.pin,
                    "byte": definition.byte,
                    "bit": definition.bit,
                }
            )
            if change is not None:
                changes.append(change)
                if not change["initial"]:
                    state.recent_events.appendleft(change)
    if decoded_signals:
        event["signals"] = decoded_signals
    return event, changes


class ParsedOutputs:
    def __init__(self, output_dir: Path, source_log: Path, mode: str) -> None:
        self.output_dir = output_dir
        self.source_log = source_log
        self.mode = mode
        output_dir.mkdir(parents=True, exist_ok=True)
        self.decoded_path = output_dir / "canopen_decoded.jsonl"
        self.changes_path = output_dir / "signal_changes.jsonl"
        self.comments_path = output_dir / "comments.jsonl"
        self.decoded_file = self.decoded_path.open("w", encoding="utf-8", newline="\n")
        self.changes_file = self.changes_path.open("w", encoding="utf-8", newline="\n")
        self.comments_file = self.comments_path.open("w", encoding="utf-8", newline="\n")
        self.written_frames = 0
        self.written_changes = 0
        self._write_json(
            output_dir / "signal_catalog.json",
            [asdict(definition) for definition in sorted(SIGNAL_CATALOG.values(), key=lambda item: item.key)],
        )
        self._write_json(
            output_dir / "analog_catalog.json",
            [asdict(definition) for definition in sorted(ANALOG_CATALOG, key=lambda item: item.key)],
        )

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def write_frame(self, event: dict[str, Any], changes: Iterable[dict[str, Any]]) -> None:
        self.decoded_file.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.written_frames += 1
        for change in changes:
            self.changes_file.write(json.dumps(change, ensure_ascii=False, separators=(",", ":")) + "\n")
            self.written_changes += 1

    def write_comment(self, record: dict[str, Any]) -> None:
        self.comments_file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    def flush(self) -> None:
        self.decoded_file.flush()
        self.changes_file.flush()
        self.comments_file.flush()

    def close(self, state: MonitorState, status: str = "complete") -> None:
        self.flush()
        self.decoded_file.close()
        self.changes_file.close()
        self.comments_file.close()

        final_signals = [
            signal_record(state.signals.get(key, SignalState(definition=definition)))
            for key, definition in sorted(SIGNAL_CATALOG.items())
        ]
        self._write_json(self.output_dir / "final_state.json", final_signals)
        final_analog = [
            analog_record(state.analog.get(definition.key, AnalogState(definition=definition)))
            for definition in sorted(ANALOG_CATALOG, key=lambda item: item.key)
        ]
        self._write_json(self.output_dir / "analog_final_state.json", final_analog)

        nodes = {}
        for node_id, node in sorted(state.nodes.items()):
            nodes[str(node_id)] = {
                "node_id": node_id,
                "name": node.name,
                "heartbeat": node.heartbeat,
                "heartbeat_seen": node.heartbeat_seen or None,
                "pdo": [
                    {
                        "service": pdo.service,
                        "number": pdo.number,
                        "cob_id": f"0x{pdo.cob_id:03X}",
                        "data": pdo.data.hex().upper(),
                        "bytes_u8": list(pdo.data),
                        "le_u16": generic_values(pdo.data)["le_u16"],
                        "count": pdo.count,
                        "changes": pdo.changes,
                        "first_seen": pdo.first_seen,
                        "last_seen": pdo.last_seen,
                    }
                    for pdo in sorted(node.pdo.values(), key=lambda item: (item.service, item.number))
                ],
            }
        self._write_json(self.output_dir / "nodes.json", nodes)

        observed = sum(1 for signal in final_signals if signal["value"] is not None)
        analog_observed = sum(1 for signal in final_analog if signal["value"] is not None)
        duration = max(0.0, state.last_source_epoch - state.first_source_epoch) if state.first_source_epoch else 0.0
        summary = {
            "status": status,
            "mode": self.mode,
            "source_log": str(self.source_log.resolve()),
            "parsed_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "duration_seconds": duration,
            "frames_total": state.frames,
            "comments_total": state.comments,
            "decode_errors": state.decode_errors,
            "services": dict(sorted(state.services.items())),
            "nodes_total": len(state.nodes),
            "signals_total": len(SIGNAL_CATALOG),
            "signals_observed": observed,
            "analog_signals_total": len(ANALOG_CATALOG),
            "analog_signals_observed": analog_observed,
            "signal_changes": state.signal_change_count,
            "output_files": {
                "decoded": self.decoded_path.name,
                "signal_changes": self.changes_path.name,
                "signal_catalog": "signal_catalog.json",
                "analog_catalog": "analog_catalog.json",
                "final_state": "final_state.json",
                "analog_final_state": "analog_final_state.json",
                "nodes": "nodes.json",
                "comments": self.comments_path.name,
            },
        }
        self._write_json(self.output_dir / "summary.json", summary)


def short(text: str, width: int) -> str:
    text = re.sub(r"[\r\n\t]+", " ", text)
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "~"


def compact_signal_name(name: str) -> str:
    """Keep the electrical tag while removing words that add little in a matrix."""
    replacements = (
        (" MANIPULATOR ", " "),
        (" MANPULATER ", " "),
        (" SWITCH ", " "),
        (" SWITH ", " "),
        (" SWTCH ", " "),
        (" SIGNAL ", " "),
    )
    result = f" {name} "
    for old, new in replacements:
        result = result.replace(old, new)
    result = re.sub(r"\s+", " ", result).strip()
    result = result.replace("TRACK OSCILLATION", "TRACK OSC.")
    result = result.replace("HYDRAULIC", "HYDR.")
    result = result.replace("DRILL SUPPORT", "DRILL SUPP.")
    result = result.replace("IGNITION KEY", "IGN.KEY")
    result = result.replace("WARNING CABIN", "CABIN WARNING")
    return result


def compact_payload(data: bytes, width: int = 8) -> str:
    text = data.hex().upper()
    if not text:
        return "-"
    if len(text) <= width:
        return text
    if width < 6:
        return text[:width]
    tail = 2
    head = width - tail - 2
    return f"{text[:head]}..{text[-tail:]}"


def terminal_size() -> os.terminal_size:
    try:
        return os.get_terminal_size()
    except OSError:
        return os.terminal_size((160, 45))


def render_io_columns(state: MonitorState, width: int) -> list[str]:
    node_ids = sorted(IO_TPDO1_SIGNALS)
    prefix_width = 4
    gap = " | "
    column_width = max(16, (width - prefix_width - len(gap) * (len(node_ids) - 1)) // len(node_ids))
    lines = ["I/O X3 INPUTS | ON=active  .=inactive  ?=not received"]
    lines.append("Pin " + gap.join(NODE_NAMES[node_id].center(column_width) for node_id in node_ids))
    for pin in range(1, 17):
        cells = []
        for node_id in node_ids:
            name = IO_TPDO1_SIGNALS[node_id][pin]
            if name == "GND":
                text = "   --"
            else:
                key = f"{NODE_NAMES[node_id]}.X3.{pin:02d}"
                definition = SIGNAL_CATALOG[key]
                signal = state.signals.get(key)
                if signal is None or signal.value is None:
                    marker = "?"
                else:
                    marker = "ON" if signal.value else "."
                text = f"{marker:<3}{compact_signal_name(definition.name)}"
            cells.append(short(text, column_width).ljust(column_width))
        lines.append(f"{pin:>2}  " + gap.join(cells))
    return lines


def render_focus_node(state: MonitorState, node_id: int) -> list[str]:
    node_name = NODE_NAMES[node_id]
    lines = [f"{node_name} node {node_id} | X3 inputs | TPDO1 0x{0x180 + node_id:03X}"]
    for pin in range(1, 17):
        name = IO_TPDO1_SIGNALS[node_id][pin]
        if name == "GND":
            lines.append(f"X3:{pin:02d}  --       GND")
            continue
        definition = SIGNAL_CATALOG[f"{node_name}.X3.{pin:02d}"]
        signal = state.signals.get(definition.key)
        value = "UNKNOWN" if signal is None else signal.state_text
        changes = 0 if signal is None else signal.changes
        lines.append(f"X3:{pin:02d}  {value:<7}  chg={changes:<3}  {name}")
    return lines


def heartbeat_short(value: str) -> str:
    return {
        "operational": "OP",
        "pre-operational": "PRE",
        "stopped": "STOP",
        "boot-up": "BOOT",
        "-": "-",
    }.get(value, short(value.upper(), 4))


def render_node_table(state: MonitorState) -> list[str]:
    columns = (
        ("TPDO", 1, "T1"),
        ("TPDO", 2, "T2"),
        ("TPDO", 3, "T3"),
        ("TPDO", 4, "T4"),
        ("RPDO", 1, "R1"),
        ("RPDO", 2, "R2"),
        ("RPDO", 3, "R3"),
        ("RPDO", 4, "R4"),
    )
    lines = ["ID  NODE         NMT  " + " ".join(label.center(8) for _, _, label in columns) + "   (HEX)"]
    for node_id in sorted(state.nodes):
        node = state.nodes[node_id]
        values = []
        for service, number, _ in columns:
            pdo = node.pdo.get((service, number))
            value = "-" if pdo is None else compact_payload(pdo.data)
            values.append(value.center(8))
        lines.append(
            f"{node_id:>2}  {short(node.name, 12):<12} {heartbeat_short(node.heartbeat):<4} "
            + " ".join(values)
        )
    return lines


def format_number(value: float | None) -> str:
    if value is None:
        return "UNKNOWN"
    if abs(value) >= 1000:
        return f"{value:.0f}"
    if abs(value) >= 100:
        return f"{value:.1f}"
    return f"{value:.2f}"


def render_analog_table(state: MonitorState, width: int) -> list[str]:
    rows: list[str] = []
    for definition in sorted(ANALOG_CATALOG, key=lambda item: (item.node_id, item.cob_id, item.byte, item.key)):
        analog = state.analog.get(definition.key)
        value = None if analog is None else analog.value
        raw_value = None if analog is None else analog.raw_value
        rows.append(
            "  ".join(
                (
                    f"{definition.node_name:<5}",
                    f"0x{definition.cob_id:03X}",
                    f"B{definition.byte:<1}",
                    f"{format_number(value):>8} {definition.unit:<4}",
                    f"raw={('-' if raw_value is None else raw_value):>5} {definition.raw_unit:<3}",
                    short(definition.name, max(18, width - 46)),
                )
            )
        )
    if not rows:
        return ["ANALOG/PWM SIGNALS | no mapped channels"]
    return ["ANALOG/PWM SIGNALS | decoded word channels from d65_nodes.yaml"] + rows


def render_dashboard(
    state: MonitorState,
    source_log: Path,
    parsed_dir: Path,
    width: int,
    height: int,
    focus_node: int | None,
) -> str:
    source_duration = (
        max(0.0, state.last_source_epoch - state.first_source_epoch) if state.first_source_epoch else 0.0
    )
    lines = [
        f"D65 CANopen monitor v2  |  mode={state.mode.upper()}  |  Ctrl+C: stop",
        f"SOURCE  {source_log.resolve()}",
        f"OUTPUT  {parsed_dir.resolve()}",
        f"FRAMES  {state.frames:<8}  TIME  {source_duration:>8.3f}s  CHANGES  {state.signal_change_count:<5}  ERRORS  {state.decode_errors}",
        "SERVICES  " + "  ".join(f"{name}:{count}" for name, count in sorted(state.services.items())),
        f"LAST  {state.last_frame}",
    ]
    if state.last_error:
        lines.append(f"Error: {state.last_error}")
    lines.append("")
    if focus_node is None:
        lines.extend(render_io_columns(state, width))
    else:
        lines.extend(render_focus_node(state, focus_node))

    lines.append("")
    lines.extend(render_analog_table(state, width))

    lines.append("")
    lines.extend(render_node_table(state))

    if height > 0:
        lines = lines[: max(1, height - 1)]
    return "\n".join(short(line.rstrip(), width) for line in lines)


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


class StableScreen:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stdout.isatty()
        self.first = True

    def __enter__(self) -> "StableScreen":
        if self.enabled:
            enable_virtual_terminal()
            sys.stdout.write("\x1b[?25l\x1b[?7l\x1b[2J\x1b[H")
            sys.stdout.flush()
        return self

    def draw(self, text: str) -> None:
        if not self.enabled:
            return
        sys.stdout.write("\x1b[H")
        sys.stdout.write(text)
        sys.stdout.write("\x1b[J")
        sys.stdout.flush()
        self.first = False

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.enabled:
            sys.stdout.write("\x1b[?7h\x1b[?25h\n")
            sys.stdout.flush()


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as error:
                yield {"type": "parse_error", "line": line_number, "error": str(error)}


def browser_dashboard_snapshot(
    state: MonitorState,
    source_log: Path,
    output_dir: Path,
    phase: str,
) -> dict[str, Any]:
    duration = max(0.0, state.last_source_epoch - state.first_source_epoch) if state.first_source_epoch else 0.0
    grouped_signals: dict[tuple[int, int, str, int], dict[str, Any]] = {}
    for definition in sorted(
        SIGNAL_CATALOG.values(),
        key=lambda item: (item.node_id, item.cob_id, item.byte, item.bit),
    ):
        group_key = (definition.node_id, definition.cob_id, definition.service, definition.pdo_number)
        group = grouped_signals.setdefault(
            group_key,
            {
                "node_id": definition.node_id,
                "node_name": definition.node_name,
                "cob_id": f"0x{definition.cob_id:03X}",
                "service": f"{definition.service}{definition.pdo_number}",
                "signals": [],
            },
        )
        signal = state.signals.get(definition.key)
        value = None if signal is None else signal.value
        group["signals"].append(
            {
                "key": definition.key,
                "name": definition.name,
                "pin": definition.pin,
                "location": (
                    f"X3:{definition.pin:02d}"
                    if definition.pin is not None
                    else f"B{definition.byte}.{definition.bit}"
                ),
                "value": value,
                "state": "UNKNOWN" if value is None else ("ON" if value else "OFF"),
                "changes": 0 if signal is None else signal.changes,
                "confidence": definition.confidence,
            }
        )

    nodes = []
    for node_id, node in sorted(state.nodes.items()):
        pdo_values = {f"{pdo.service[0]}{pdo.number}": pdo.data.hex().upper() or "-" for pdo in node.pdo.values()}
        nodes.append(
            {
                "node_id": node_id,
                "name": node.name,
                "heartbeat": node.heartbeat,
                "pdo": pdo_values,
                "frames": sum(pdo.count for pdo in node.pdo.values()),
            }
        )

    events = []
    for event in state.recent_events:
        event_epoch = float(event.get("timestamp_epoch") or state.first_source_epoch or 0.0)
        events.append(
            {
                "name": event["name"],
                "key": event["key"],
                "value": event["value"],
                "state": event["state"],
                "offset_seconds": max(0.0, event_epoch - state.first_source_epoch),
            }
        )

    analog_channels = []
    for definition in ANALOG_CATALOG:
        analog = state.analog.get(definition.key)
        analog_channels.append(
            {
                "key": definition.key,
                "name": definition.name,
                "node_id": definition.node_id,
                "node_name": definition.node_name,
                "cob_id": f"0x{definition.cob_id:03X}",
                "service": f"{definition.service}{definition.pdo_number}",
                "byte": definition.byte,
                "value": None if analog is None else analog.value,
                "raw_value": None if analog is None else analog.raw_value,
                "unit": definition.unit,
                "raw_unit": definition.raw_unit,
                "confidence": definition.confidence,
                "samples": (
                    []
                    if analog is None
                    else [
                        {
                            "time": max(0.0, timestamp - state.first_source_epoch),
                            "value": value,
                        }
                        for timestamp, value in analog.samples
                    ]
                ),
            }
        )

    return {
        "phase": phase,
        "mode": state.mode,
        "source": str(source_log.resolve()),
        "output": str(output_dir.resolve()),
        "frames": state.frames,
        "duration_seconds": duration,
        "signal_changes": state.signal_change_count,
        "decode_errors": state.decode_errors,
        "last_frame": state.last_frame,
        "last_error": state.last_error,
        "services": dict(sorted(state.services.items())),
        "digital_modules": list(grouped_signals.values()),
        "analog": analog_channels,
        "nodes": nodes,
        "events": events,
    }


def start_browser_dashboard(
    args: argparse.Namespace,
    state: MonitorState,
    source_log: Path,
    output_dir: Path,
) -> DashboardServer | None:
    if not args.dashboard:
        return None
    dashboard = DashboardServer(
        host=args.dashboard_host,
        port=args.dashboard_port,
        open_browser=not args.dashboard_no_open,
    )
    dashboard.update(browser_dashboard_snapshot(state, source_log, output_dir, "starting"))
    url = dashboard.start()
    if dashboard.actual_port != args.dashboard_port and args.dashboard_port != 0:
        print(f"Dashboard: {url} (requested port {args.dashboard_port} was busy)", file=sys.stderr)
    else:
        print(f"Dashboard: {url}", file=sys.stderr)
    return dashboard


def publish_browser_dashboard(
    dashboard: DashboardServer | None,
    state: MonitorState,
    source_log: Path,
    output_dir: Path,
    phase: str,
) -> None:
    if dashboard is not None:
        dashboard.update(browser_dashboard_snapshot(state, source_log, output_dir, phase))


def maybe_draw(
    screen: StableScreen,
    state: MonitorState,
    source_log: Path,
    output_dir: Path,
    focus_node: int | None,
) -> None:
    if not screen.enabled:
        return
    size = terminal_size()
    screen.draw(render_dashboard(state, source_log, output_dir, size.columns, size.lines, focus_node))


def run_playback(args: argparse.Namespace) -> int:
    try:
        log_path = resolve_log(args.playback_log, args.logs_dir)
    except FileNotFoundError as error:
        print(f"Could not select playback log: {error}", file=sys.stderr)
        return 2

    output_dir = args.parsed_dir / log_path.stem
    state = MonitorState(mode="replay")
    try:
        dashboard = start_browser_dashboard(args, state, log_path, output_dir)
    except OSError as error:
        print(f"Could not start dashboard: {error}", file=sys.stderr)
        return 2
    outputs = ParsedOutputs(output_dir, log_path, mode="replay")
    next_draw = 0.0
    first_frame_epoch: float | None = None
    replay_started = time.monotonic()
    status = "complete"
    return_code = 0

    try:
        with StableScreen(not args.no_screen) as screen:
            for record in read_jsonl(log_path):
                record_type = record.get("type")
                if record_type == "comment":
                    state.comments += 1
                    outputs.write_comment(record)
                    continue
                if record_type == "parse_error":
                    state.decode_errors += 1
                    state.last_error = f"line {record.get('line')}: {record.get('error')}"
                    continue
                if record_type not in (None, "frame"):
                    continue

                if args.replay_rate > 0:
                    frame_epoch = source_epoch(record)
                    if first_frame_epoch is None:
                        first_frame_epoch = frame_epoch
                    target = (frame_epoch - first_frame_epoch) / args.replay_rate
                    delay = target - (time.monotonic() - replay_started)
                    if delay > 0:
                        time.sleep(delay)

                event, changes = decode_d65_frame(state, record)
                outputs.write_frame(event, changes)
                if state.frames % args.flush_every == 0:
                    outputs.flush()

                now = time.monotonic()
                if now >= next_draw:
                    maybe_draw(screen, state, log_path, output_dir, args.focus_node)
                    publish_browser_dashboard(dashboard, state, log_path, output_dir, "running")
                    next_draw = now + args.refresh

            maybe_draw(screen, state, log_path, output_dir, args.focus_node)
            publish_browser_dashboard(dashboard, state, log_path, output_dir, "complete")
    except KeyboardInterrupt:
        status = "interrupted"
        return_code = 0
    except Exception as error:
        status = "error"
        state.last_error = str(error)
        print(f"Playback error: {error}", file=sys.stderr)
        return_code = 2
    finally:
        outputs.close(state, status=status)

    print(f"Source: {log_path.resolve()}", file=sys.stderr)
    print(f"Parsed: {output_dir.resolve()}", file=sys.stderr)
    print(f"Frames: {state.frames}; signal changes: {state.signal_change_count}", file=sys.stderr)
    publish_browser_dashboard(dashboard, state, log_path, output_dir, status)
    if dashboard is not None:
        if status == "complete":
            print(f"Replay complete; dashboard remains at {dashboard.url} (Ctrl+C to stop)", file=sys.stderr)
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass
        dashboard.stop()
    return return_code


def run_live(args: argparse.Namespace) -> int:
    if not args.device:
        print("error: --device/--adapter is required unless --playback-log is used", file=sys.stderr)
        return 2

    args.logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = make_log_path(args.logs_dir, args.log_name)
    output_dir = args.parsed_dir / log_path.stem

    detecting_stderr = DetectingStderr(sys.stderr)
    original_stderr = sys.stderr
    try:
        sys.stderr = detecting_stderr
        reader = open_reader(args)
    except InitializationError as error:
        print(f"Could not safely open CAN adapter in listen-only mode: {error}", file=original_stderr)
        return 2
    finally:
        sys.stderr = original_stderr

    state = MonitorState(mode="live")
    outputs = ParsedOutputs(output_dir, log_path, mode="live")
    try:
        dashboard = start_browser_dashboard(args, state, log_path, output_dir)
    except OSError as error:
        print(f"Could not start dashboard: {error}", file=sys.stderr)
        reader.close()
        outputs.close(state, status="error")
        return 2
    next_draw = 0.0
    status = "complete"
    return_code = 0

    print(f"Raw log: {log_path.resolve()}", file=sys.stderr)
    print(f"Parsed: {output_dir.resolve()}", file=sys.stderr)
    try:
        with log_path.open("w", encoding="utf-8", newline="\n") as raw_file, StableScreen(
            not args.no_screen
        ) as screen:
            write_jsonl(
                raw_file,
                {
                    "type": "metadata",
                    "started_at": datetime.fromtimestamp(state.started_wall).astimezone().isoformat(timespec="seconds"),
                    "device": args.device,
                    "channel": args.channel if args.channel is not None else "0",
                    "bitrate_request": args.bitrate,
                    "detected_bitrate": detecting_stderr.detected_bitrate,
                    "btr": args.btr,
                    "listen_only": True,
                    "comments_enabled": False,
                    "live_monitor": "canopen_live_monitor_v2",
                },
            )
            live_started = time.monotonic()
            while True:
                if args.duration and time.monotonic() - live_started >= args.duration:
                    break
                frame = reader.recv(args.recv_timeout)
                if frame is not None:
                    record = frame_to_record(frame, state.frames + 1)
                    write_jsonl(raw_file, record)
                    event, changes = decode_d65_frame(state, record)
                    outputs.write_frame(event, changes)
                    if state.frames % args.flush_every == 0:
                        raw_file.flush()
                        outputs.flush()

                now = time.monotonic()
                if now >= next_draw:
                    maybe_draw(screen, state, log_path, output_dir, args.focus_node)
                    publish_browser_dashboard(dashboard, state, log_path, output_dir, "running")
                    next_draw = now + args.refresh
            maybe_draw(screen, state, log_path, output_dir, args.focus_node)
            publish_browser_dashboard(dashboard, state, log_path, output_dir, "complete")
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception as error:
        status = "error"
        state.last_error = str(error)
        print(f"CAN live monitor error: {error}", file=sys.stderr)
        return_code = 2
    finally:
        reader.close()
        outputs.close(state, status=status)
        publish_browser_dashboard(dashboard, state, log_path, output_dir, status)
        if dashboard is not None:
            dashboard.stop()

    print(f"Stopped. Raw frames: {state.frames}; signal changes: {state.signal_change_count}", file=sys.stderr)
    return return_code


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.playback_log:
        return run_playback(args)
    return run_live(args)


if __name__ == "__main__":
    raise SystemExit(run())
