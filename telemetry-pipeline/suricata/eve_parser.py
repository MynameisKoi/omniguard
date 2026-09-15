"""Suricata EVE JSON Telemetry Parser.

Parses Suricata EVE.json streaming records (flow, netflow, and tls event types)
into normalized flow profiles for behavioral beaconing analysis.
"""

from __future__ import annotations

import json
import logging
import queue
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Iterator, Optional, Dict, Any, TextIO

logger = logging.getLogger("SuricataEveParser")

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError, NoBrokersAvailable
    KAFKA_INSTALLED = True
except ImportError:
    KAFKA_INSTALLED = False
    KafkaProducer = None  # type: ignore
    KafkaError = Exception  # type: ignore
    NoBrokersAvailable = Exception  # type: ignore


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

    @classmethod
    def stream_to_kafka(
        cls,
        file_obj: TextIO,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "network-flows",
        fallback_queue: Optional[queue.Queue] = None,
    ) -> tuple[int, SuricataKafkaProducer]:
        """Parses EVE stream and publishes to Kafka topic 'network-flows' (or fallback queue)."""
        producer = SuricataKafkaProducer(
            bootstrap_servers=bootstrap_servers,
            topic=topic,
            fallback_queue=fallback_queue,
        )
        count = 0
        for record in cls.parse_file(file_obj):
            producer.publish_record(record)
            count += 1
        producer.flush()
        return count, producer


class SuricataKafkaProducer:
    """Publishes Suricata flow records to Kafka topic 'network-flows'.

    Gracefully detects broker availability; falls back to an in-memory queue
    when Kafka is unreachable.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "network-flows",
        fallback_queue: Optional[queue.Queue] = None,
        timeout_ms: int = 1000,
    ):
        self.topic = topic
        self.bootstrap_servers = bootstrap_servers
        self.fallback_queue = fallback_queue if fallback_queue is not None else queue.Queue()
        self.producer = None
        self.is_kafka_connected = False

        if KAFKA_INSTALLED:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    request_timeout_ms=timeout_ms,
                    max_block_ms=timeout_ms,
                )
                self.is_kafka_connected = True
                logger.info(f"Connected to Kafka at {bootstrap_servers} for topic '{topic}'")
            except (KafkaError, NoBrokersAvailable, Exception) as exc:
                logger.warning(
                    f"Kafka broker unavailable at {bootstrap_servers} ({exc}). Using in-memory fallback queue."
                )
                self.is_kafka_connected = False
                self.producer = None
        else:
            logger.info("kafka-python not installed. Operating in in-memory fallback queue mode.")

    def publish_record(self, record: SuricataFlowRecord) -> Dict[str, Any]:
        """Serializes and sends record to Kafka topic 'network-flows' or fallback queue."""
        payload = {
            "source": "suricata",
            "timestamp": record.timestamp,
            "host_id": record.src_ip,
            "src_ip": record.src_ip,
            "src_port": record.src_port,
            "dst_ip": record.dst_ip,
            "dst_port": record.dst_port,
            "proto": record.proto.lower(),
            "service": record.app_proto or "unknown",
            "duration": record.duration,
            "bytes": record.bytes_toserver + record.bytes_toclient,
            "bytes_toserver": record.bytes_toserver,
            "bytes_toclient": record.bytes_toclient,
            "pkts_toserver": record.pkts_toserver,
            "pkts_toclient": record.pkts_toclient,
            "sni": record.sni,
            "flow_key": record.flow_key,
        }

        if self.is_kafka_connected and self.producer:
            try:
                self.producer.send(self.topic, value=payload)
            except Exception as exc:
                logger.warning(f"Failed Kafka dispatch: {exc}. Routing to fallback queue.")
                self.fallback_queue.put(payload)
        else:
            self.fallback_queue.put(payload)

        return payload

    def flush(self) -> None:
        if self.is_kafka_connected and self.producer:
            try:
                self.producer.flush()
            except Exception:
                pass

    def close(self) -> None:
        if self.is_kafka_connected and self.producer:
            try:
                self.producer.close()
            except Exception:
                pass

