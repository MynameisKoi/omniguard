"""Zeek Telemetry Parser (conn.log & ssl.log).

Parses both JSON and TSV (tab-delimited) Zeek flow logs to extract
connection identifiers, timing deltas, and SSL/TLS session metadata.
"""

from __future__ import annotations

import json
import logging
import queue
from dataclasses import dataclass, asdict
from typing import Iterator, Optional, Dict, Any, TextIO

logger = logging.getLogger("ZeekLogParser")

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
class ZeekConnRecord:
    """Normalized connection flow record from Zeek conn.log."""
    ts: float
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: Optional[str]
    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    conn_state: str
    ssl_server_name: Optional[str] = None

    @property
    def flow_key(self) -> str:
        """Unique 5-tuple key for flow window aggregation."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.proto}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ZeekLogParser:
    """Streams and parses Zeek conn.log and ssl.log files."""

    @staticmethod
    def parse_line(line: str, fields: Optional[list[str]] = None) -> Optional[Dict[str, Any]]:
        """Parses a single line of Zeek log (JSON or TSV)."""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        # Check if line is JSON
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return None

        # TSV format
        if fields:
            parts = stripped.split("\t")
            if len(parts) == len(fields):
                return dict(zip(fields, parts))
        return None

    @classmethod
    def parse_file(cls, file_obj: TextIO) -> Iterator[ZeekConnRecord]:
        """Parses an open Zeek log file stream yielding ZeekConnRecord objects."""
        fields = None
        for line in file_obj:
            stripped = line.strip()
            if stripped.startswith("#fields"):
                fields = stripped.split("\t")[1:]
                continue
            if stripped.startswith("#"):
                continue

            raw = cls.parse_line(line, fields)
            if not raw:
                continue

            try:
                # Handle both dot-notation and flat keys
                ts = float(raw.get("ts", 0.0))
                uid = raw.get("uid", "")
                src_ip = raw.get("id.orig_h", raw.get("src_ip", ""))
                src_port = int(raw.get("id.orig_p", raw.get("src_port", 0)))
                dst_ip = raw.get("id.resp_h", raw.get("dst_ip", ""))
                dst_port = int(raw.get("id.resp_p", raw.get("dst_port", 0)))
                proto = raw.get("proto", "tcp")
                service = raw.get("service") if raw.get("service") != "-" else None

                dur_raw = raw.get("duration", "0.0")
                duration = float(dur_raw) if dur_raw not in ("-", "", None) else 0.0

                orig_b_raw = raw.get("orig_bytes", "0")
                orig_bytes = int(orig_b_raw) if orig_b_raw not in ("-", "", None) else 0

                resp_b_raw = raw.get("resp_bytes", "0")
                resp_bytes = int(resp_b_raw) if resp_b_raw not in ("-", "", None) else 0

                orig_p_raw = raw.get("orig_pkts", "0")
                orig_pkts = int(orig_p_raw) if orig_p_raw not in ("-", "", None) else 0

                resp_p_raw = raw.get("resp_pkts", "0")
                resp_pkts = int(resp_p_raw) if resp_p_raw not in ("-", "", None) else 0

                conn_state = raw.get("conn_state", "-")
                server_name = raw.get("server_name") if raw.get("server_name") != "-" else None

                yield ZeekConnRecord(
                    ts=ts,
                    uid=uid,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    proto=proto,
                    service=service,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                    orig_pkts=orig_pkts,
                    resp_pkts=resp_pkts,
                    conn_state=conn_state,
                    ssl_server_name=server_name,
                )
            except (ValueError, TypeError):
                continue

    @classmethod
    def stream_to_kafka(
        cls,
        file_obj: TextIO,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "network-flows",
        fallback_queue: Optional[queue.Queue] = None,
    ) -> tuple[int, ZeekKafkaProducer]:
        """Parses log stream and publishes to Kafka topic 'network-flows' (or fallback queue)."""
        producer = ZeekKafkaProducer(
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


class ZeekKafkaProducer:
    """Publishes Zeek connection records to Kafka topic 'network-flows'.

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

    def publish_record(self, record: ZeekConnRecord) -> Dict[str, Any]:
        """Serializes and sends record to Kafka topic 'network-flows' or fallback queue."""
        payload = {
            "source": "zeek",
            "timestamp": record.ts,
            "uid": record.uid,
            "host_id": record.src_ip,
            "src_ip": record.src_ip,
            "src_port": record.src_port,
            "dst_ip": record.dst_ip,
            "dst_port": record.dst_port,
            "proto": record.proto,
            "service": record.service or "unknown",
            "duration": record.duration,
            "bytes": record.orig_bytes + record.resp_bytes,
            "orig_bytes": record.orig_bytes,
            "resp_bytes": record.resp_bytes,
            "orig_pkts": record.orig_pkts,
            "resp_pkts": record.resp_pkts,
            "conn_state": record.conn_state,
            "sni": record.ssl_server_name,
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

