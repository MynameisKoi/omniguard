"""Streaming Telemetry Consumer & Sliding Window Flow Aggregator.

Ingests Zeek and Suricata flow events from Kafka topic 'network-flows'
(with in-memory fallback queue support), maintains sliding time-windows per
5-tuple, evaluates beacon periodicity via the SpectraC2 engine, and dispatches
strictly formatted alerts to the Graph-Triage Core API via httpx.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import httpx

# Ensure spectrac2-engine is importable
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
engine_path = os.path.join(repo_root, "spectrac2-engine")
if engine_path not in sys.path:
    sys.path.insert(0, engine_path)

from inference.predictor import SpectraC2Predictor

try:
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError, NoBrokersAvailable
    KAFKA_INSTALLED = True
except ImportError:
    KAFKA_INSTALLED = False
    KafkaConsumer = None  # type: ignore
    KafkaError = Exception  # type: ignore
    NoBrokersAvailable = Exception  # type: ignore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SpectraC2-Consumer] %(message)s",
)
logger = logging.getLogger("SpectraC2Consumer")


@dataclass
class FlowWindow:
    """Sliding temporal window of packets for an individual 5-tuple flow."""
    flow_key: str
    host: str
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 443
    proto: str = "tcp"
    service: str = "ssl"
    domain: Optional[str] = None
    timestamps: List[float] = field(default_factory=list)
    packet_sizes: List[int] = field(default_factory=list)
    directions: List[str] = field(default_factory=list)
    last_evaluated_packet_count: int = 0
    last_updated: float = field(default_factory=time.time)

    def add_packet(
        self,
        ts: float,
        size: int = 128,
        direction: str = "fwd",
        domain: Optional[str] = None,
        service: Optional[str] = None,
    ):
        self.timestamps.append(ts)
        self.packet_sizes.append(size)
        self.directions.append(direction)
        if domain:
            self.domain = domain
        if service and service != "unknown":
            self.service = service
        self.last_updated = time.time()

        # Enforce maximum sliding window of 100 packets
        if len(self.timestamps) > 100:
            self.timestamps.pop(0)
            self.packet_sizes.pop(0)
            self.directions.pop(0)


class TelemetryStreamConsumer:
    """Ingests flow events, aggregates packet windows, and dispatches alerts."""

    def __init__(
        self,
        predictor: Optional[SpectraC2Predictor] = None,
        alert_api_url: str = "http://localhost:8000/api/v1/alerts",
        min_eval_packets: int = 8,
        eval_interval_packets: int = 5,
    ):
        self.predictor = predictor or SpectraC2Predictor()
        self.alert_api_url = alert_api_url
        self.min_eval_packets = min_eval_packets
        self.eval_interval_packets = eval_interval_packets
        self.active_flows: Dict[str, FlowWindow] = defaultdict(lambda: FlowWindow("", "", "", ""))
        self.emitted_alert_keys: set[str] = set()
        self.recent_alerts: List[Dict[str, Any]] = []

    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes a single flow/packet event from Zeek or Suricata."""
        src_ip = event.get("src_ip", event.get("id.orig_h", "0.0.0.0"))
        dst_ip = event.get("dst_ip", event.get("id.resp_h", "0.0.0.0"))
        src_port = int(event.get("src_port", event.get("id.orig_p", 0)))
        dst_port = int(event.get("dst_port", event.get("id.resp_p", 443)))
        proto = str(event.get("proto", "tcp")).lower()
        service = str(event.get("service", event.get("app_proto", "ssl")))
        host = str(event.get("host_id", event.get("host", src_ip)))
        sni = event.get("sni", event.get("domain", event.get("ssl_server_name")))

        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}"
        flow = self.active_flows[flow_key]

        if not flow.flow_key:
            flow.flow_key = flow_key
            flow.host = host
            flow.src_ip = src_ip
            flow.dst_ip = dst_ip
            flow.src_port = src_port
            flow.dst_port = dst_port
            flow.proto = proto
            flow.service = service

        ts = float(event.get("timestamp", event.get("ts", time.time())))
        size = int(event.get("bytes", event.get("orig_bytes", 128)))
        direction = event.get("direction", "fwd")

        flow.add_packet(ts=ts, size=size, direction=direction, domain=sni, service=service)

        # Trigger evaluation when sufficient new packets arrive
        pkt_count = len(flow.timestamps)
        if (
            pkt_count >= self.min_eval_packets
            and (pkt_count - flow.last_evaluated_packet_count) >= self.eval_interval_packets
        ):
            flow.last_evaluated_packet_count = pkt_count
            return self._evaluate_flow(flow)

        return None

    def _evaluate_flow(self, flow: FlowWindow) -> Optional[Dict[str, Any]]:
        """Runs SpectraC2 inference on the windowed flow and formats standardized alert."""
        meta = {
            "host": flow.host,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "domain": flow.domain,
        }

        result = self.predictor.analyze_flow(
            timestamps=flow.timestamps,
            packet_sizes=flow.packet_sizes,
            directions=flow.directions,
            flow_metadata=meta,
        )

        if result["is_beacon"]:
            # Format strictly according to the standardized OmniGuard alert schema
            alert = {
                "source": "spectrac2",
                "event_type": "c2_beacon_detected",
                "severity": result["severity"].upper(),
                "timestamp": float(flow.timestamps[-1] if flow.timestamps else time.time()),
                "host_id": str(flow.host or flow.src_ip),
                "src_ip": str(flow.src_ip),
                "dst_ip": str(flow.dst_ip),
                "dst_port": int(flow.dst_port),
                "proto": str(flow.proto),
                "service": str(flow.service if flow.service != "unknown" else "ssl"),
                "sni": flow.domain if flow.domain else None,
                "mitre_technique": "T1071",
                "confidence": float(round(result["threat_score"], 4)),
                "beacon_interval": float(round(result["spectral_metrics"]["dominant_period"], 4)),
                "mean_jitter": float(round(result["temporal_metrics"]["mean_jitter"], 4)),
            }

            alert_fingerprint = f"{flow.flow_key}:{alert['severity']}"
            # Deduplicate rapid repeating alerts
            if alert_fingerprint not in self.emitted_alert_keys:
                self.emitted_alert_keys.add(alert_fingerprint)
                self.recent_alerts.append(alert)
                self.dispatch_alert(alert)
                return alert

        return None

    def dispatch_alert(self, alert: Dict[str, Any]) -> bool:
        """Dispatches detected alert to Graph-Triage Core API via httpx."""
        logger.warning(
            f"🚨 [C2 BEACON DETECTED] Host: {alert['host_id']} | "
            f"Severity: {alert['severity']} | "
            f"Target: {alert.get('sni') or alert.get('dst_ip')}:{alert['dst_port']} | "
            f"Interval: ~{alert['beacon_interval']}s | Jitter: {alert['mean_jitter']}s | "
            f"Confidence: {alert['confidence']:.1%}"
        )

        try:
            with httpx.Client(timeout=0.5) as client:
                resp = client.post(self.alert_api_url, json=alert)
                if resp.status_code in (200, 201, 202):
                    logger.info(f"✅ Alert accepted by Graph Core: {resp.json().get('alert_id', 'ok')}")
                    return True
                else:
                    logger.warning(f"Graph Core returned status {resp.status_code}: {resp.text}")
                    return False
        except Exception as exc:
            logger.debug(f"Graph Core API at {self.alert_api_url} unreachable ({exc}). Alert buffered locally.")
            return False

    async def dispatch_alert_async(self, alert: Dict[str, Any]) -> bool:
        """Asynchronous non-blocking dispatch via httpx.AsyncClient."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(self.alert_api_url, json=alert)
                return resp.status_code in (200, 201, 202)
        except Exception as exc:
            logger.debug(f"Async dispatch error: {exc}")
            return False

    def consume_from_kafka(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "network-flows",
        group_id: str = "spectrac2-consumer",
        max_messages: Optional[int] = None,
        timeout_ms: int = 1000,
        fallback_queue: Optional[queue.Queue] = None,
    ) -> int:
        """Consumes records from Kafka topic 'network-flows' (or fallback queue) and processes them."""
        processed_count = 0
        consumer = None

        if fallback_queue is None and KAFKA_INSTALLED:
            try:
                consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=bootstrap_servers,
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    group_id=group_id,
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    consumer_timeout_ms=timeout_ms,
                )
                logger.info(f"Connected to Kafka topic '{topic}' at {bootstrap_servers}")
            except (KafkaError, NoBrokersAvailable, Exception) as exc:
                logger.warning(
                    f"Kafka broker unavailable at {bootstrap_servers} ({exc}). Operating in fallback queue mode."
                )
                consumer = None

        if consumer is not None:
            try:
                for message in consumer:
                    event = message.value
                    self.process_event(event)
                    processed_count += 1
                    if max_messages and processed_count >= max_messages:
                        break
            except Exception as e:
                logger.error(f"Error reading from Kafka topic '{topic}': {e}")
            finally:
                consumer.close()
        elif fallback_queue is not None:
            while not fallback_queue.empty():
                try:
                    event = fallback_queue.get_nowait()
                    self.process_event(event)
                    processed_count += 1
                    fallback_queue.task_done()
                    if max_messages and processed_count >= max_messages:
                        break
                except queue.Empty:
                    break

        return processed_count

    def run_file_stream(self, file_path: str) -> int:
        """Simulates live streaming ingestion from a raw log file."""
        logger.info(f"[*] Replaying telemetry stream from file: {file_path}")
        alerts_emitted = 0
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                try:
                    event = json.loads(stripped)
                    alert = self.process_event(event)
                    if alert:
                        alerts_emitted += 1
                except json.JSONDecodeError:
                    continue
        logger.info(f"[+] Telemetry replay finished. Emitted {alerts_emitted} beacon alerts.")
        return alerts_emitted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SpectraC2 Streaming Telemetry Consumer")
    parser.add_argument("--dry-run", action="store_true", help="Run a quick synthetic validation loop")
    parser.add_argument("--file", type=str, help="Path to telemetry JSON log file to stream")
    parser.add_argument("--kafka", action="store_true", help="Consume from Kafka topic 'network-flows'")
    parser.add_argument("--broker", type=str, default="localhost:9092", help="Kafka bootstrap broker")
    parser.add_argument("--topic", type=str, default="network-flows", help="Kafka topic")
    parser.add_argument("--api", type=str, default="http://localhost:8000/api/v1/alerts", help="Target Graph Core API URL")
    args = parser.parse_args()

    consumer = TelemetryStreamConsumer(alert_api_url=args.api)

    if args.dry_run:
        from inference.dataset_generator import SyntheticFlowGenerator
        logger.info("[*] Running dry-run validation with synthetic C2 beacon flow...")
        gen = SyntheticFlowGenerator()
        beacon_flow = gen.generate_c2_beacon(base_interval=5.0, jitter_pct=0.2, num_packets=25)
        for ts, sz, dr in zip(beacon_flow["timestamps"], beacon_flow["packet_sizes"], beacon_flow["directions"]):
            event = {
                "source": "synthetic",
                "src_ip": "10.0.4.15",
                "dst_ip": "198.51.100.42",
                "src_port": 49152,
                "dst_port": 443,
                "proto": "tcp",
                "service": "ssl",
                "host_id": "WORKSTATION-CORP-42",
                "sni": "api-telemetry-cdn.net",
                "timestamp": ts,
                "bytes": sz,
                "direction": dr,
            }
            consumer.process_event(event)
        logger.info("[+] Dry-run completed successfully.")
    elif args.kafka:
        logger.info(f"[*] Consuming live from Kafka topic '{args.topic}' at {args.broker}...")
        consumer.consume_from_kafka(bootstrap_servers=args.broker, topic=args.topic)
    elif args.file:
        consumer.run_file_stream(args.file)
    else:
        logger.info("[*] Starting SpectraC2 Consumer in standalone polling mode...")
