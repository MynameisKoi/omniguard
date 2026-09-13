"""Suricata EVE JSON Telemetry Parser.

Parses Suricata EVE.json streaming records (flow, netflow, and tls event types)
into normalized flow profiles for behavioral beaconing analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Iterator, Optional, Dict, Any, TextIO


@dataclass
class SuricataFlowRecord:
    """Normalized flow metadata from Suricata eve.json."""
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    event_type: str
    duration: float
    bytes_toserver: int
    bytes_toclient: int
    pkts_toserver: int
    pkts_toclient: int
    sni: Optional[str] = None
    app_proto: Optional[str] = None

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.proto}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SuricataEveParser:
    """Streams and parses Suricata eve.json event records."""

    @staticmethod
    def _parse_timestamp(ts_val: Any) -> float:
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            try:
                # ISO-8601 parsing (e.g. 2026-09-12T14:30:00.123456+0000)
                # Normalize trailing timezone offset for standard strptime/fromisoformat
                cleaned = ts_val.replace("Z", "+00:00")
                return datetime.fromisoformat(cleaned).timestamp()
            except ValueError:
                return 0.0
        return 0.0

    @classmethod
    def parse_line(cls, line: str) -> Optional[SuricataFlowRecord]:
        """Parses a single line of EVE.json."""
        stripped = line.strip()
        if not stripped:
            return None

        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return None

        event_type = data.get("event_type")
        if event_type not in ("flow", "netflow", "tls", "alert"):
            return None

        src_ip = data.get("src_ip", "")
        src_port = int(data.get("src_port", 0))
        dst_ip = data.get("dest_ip", "")
        dst_port = int(data.get("dest_port", 0))
        proto = data.get("proto", "TCP")
        app_proto = data.get("app_proto")

        ts = cls._parse_timestamp(data.get("timestamp"))

        # Extract nested flow statistics if present
        flow_data = data.get("flow", {})
        bytes_toserver = int(flow_data.get("bytes_toserver", data.get("bytes_toserver", 0)))
        bytes_toclient = int(flow_data.get("bytes_toclient", data.get("bytes_toclient", 0)))
        pkts_toserver = int(flow_data.get("pkts_toserver", data.get("pkts_toserver", 0)))
        pkts_toclient = int(flow_data.get("pkts_toclient", data.get("pkts_toclient", 0)))
        duration = float(flow_data.get("age", 0.0))

        # Extract TLS SNI
        tls_data = data.get("tls", {})
        sni = tls_data.get("sni")

        return SuricataFlowRecord(
            timestamp=ts,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            event_type=event_type,
            duration=duration,
            bytes_toserver=bytes_toserver,
            bytes_toclient=bytes_toclient,
            pkts_toserver=pkts_toserver,
            pkts_toclient=pkts_toclient,
            sni=sni,
            app_proto=app_proto,
        )

    @classmethod
    def parse_file(cls, file_obj: TextIO) -> Iterator[SuricataFlowRecord]:
        for line in file_obj:
            record = cls.parse_line(line)
            if record:
                yield record
