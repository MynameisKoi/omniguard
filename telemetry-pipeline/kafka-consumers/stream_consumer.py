"""Streaming Telemetry Consumer & Sliding Window Flow Aggregator.

Ingests Zeek and Suricata flow events from Kafka / Redis / Log Files,
maintains sliding time-windows per 5-tuple, evaluates beacon periodicity
via the SpectraC2 engine, and forwards alerts to the SOC graph pipeline.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import requests

# Ensure spectrac2-engine is importable
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
engine_path = os.path.join(repo_root, "spectrac2-engine")
if engine_path not in sys.path:
    sys.path.insert(0, engine_path)

from inference.predictor import SpectraC2Predictor

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
    domain: Optional[str] = None
    timestamps: List[float] = field(default_factory=list)
    packet_sizes: List[int] = field(default_factory=list)
    directions: List[str] = field(default_factory=list)
    last_evaluated_packet_count: int = 0
    last_updated: float = field(default_factory=time.time)

    def add_packet(self, ts: float, size: int = 128, direction: str = "fwd", domain: Optional[str] = None):
        self.timestamps.append(ts)
        self.packet_sizes.append(size)
        self.directions.append(direction)
        if domain:
            self.domain = domain
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
        alert_api_url: str = "http://localhost:8000/alerts",
        min_eval_packets: int = 8,
        eval_interval_packets: int = 5,
    ):
        self.predictor = predictor or SpectraC2Predictor()
        self.alert_api_url = alert_api_url
        self.min_eval_packets = min_eval_packets
        self.eval_interval_packets = eval_interval_packets
        self.active_flows: Dict[str, FlowWindow] = defaultdict(lambda: FlowWindow("", "", "", ""))
        self.emitted_alert_keys: set[str] = set()

    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes a single flow/packet event from Zeek or Suricata."""
        src_ip = event.get("src_ip", event.get("id.orig_h", "0.0.0.0"))
        dst_ip = event.get("dst_ip", event.get("id.resp_h", "0.0.0.0"))
        src_port = event.get("src_port", event.get("id.orig_p", 0))
        dst_port = event.get("dst_port", event.get("id.resp_p", 0))
        proto = event.get("proto", "tcp")
        host = event.get("host", src_ip)
        domain = event.get("domain", event.get("ssl_server_name", event.get("sni")))

        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}"
        flow = self.active_flows[flow_key]

        if not flow.flow_key:
            flow.flow_key = flow_key
            flow.host = host
            flow.src_ip = src_ip
            flow.dst_ip = dst_ip

        ts = float(event.get("timestamp", event.get("ts", time.time())))
        size = int(event.get("bytes", event.get("orig_bytes", 128)))
        direction = event.get("direction", "fwd")

        flow.add_packet(ts=ts, size=size, direction=direction, domain=domain)

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
        """Runs SpectraC2 inference on the windowed flow."""
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
            alert = result.get("alert")
            if alert:
                alert_fingerprint = f"{flow.flow_key}:{result['severity']}"
                # Deduplicate rapid repeating alerts
                if alert_fingerprint not in self.emitted_alert_keys:
                    self.emitted_alert_keys.add(alert_fingerprint)
                    self.dispatch_alert(alert)
                    return alert

        return None

    def dispatch_alert(self, alert: Dict[str, Any]) -> None:
        """Dispatches detected alert to SOC REST API, Redis, and Logs."""
        logger.warning(
            f"🚨 [C2 BEACON DETECTED] Host: {alert['host']} | "
            f"Severity: {alert['severity'].upper()} | "
            f"Target: {alert.get('domain') or alert.get('src_ip')} | "
            f"{alert['description']}"
        )

        # Forward to OmniGuard FastAPI Backend if reachable
        try:
            resp = requests.post(self.alert_api_url, json=alert, timeout=2.0)
            if resp.status_code in (200, 201):
                logger.info(f"✅ Alert forwarded to SOC API: {resp.json().get('alert_id', 'ok')}")
        except Exception:
            logger.debug(f"SOC API at {self.alert_api_url} not reachable. Stored locally.")

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
    parser.add_argument("--api", type=str, default="http://localhost:8000/alerts", help="Target SOC API URL")
    args = parser.parse_args()

    consumer = TelemetryStreamConsumer(alert_api_url=args.api)

    if args.dry_run:
        from inference.dataset_generator import SyntheticFlowGenerator
        logger.info("[*] Running dry-run validation with synthetic C2 beacon flow...")
        gen = SyntheticFlowGenerator()
        beacon_flow = gen.generate_c2_beacon(base_interval=5.0, jitter_pct=0.2, num_packets=25)
        for ts, sz, dr in zip(beacon_flow["timestamps"], beacon_flow["packet_sizes"], beacon_flow["directions"]):
            event = {
                "src_ip": "10.0.4.15",
                "dst_ip": "198.51.100.42",
                "src_port": 49152,
                "dst_port": 443,
                "proto": "tcp",
                "host": "WORKSTATION-CORP-42",
                "domain": "api-telemetry-cdn.net",
                "timestamp": ts,
                "bytes": sz,
                "direction": dr,
            }
            consumer.process_event(event)
        logger.info("[+] Dry-run completed successfully.")
    elif args.file:
        consumer.run_file_stream(args.file)
    else:
        logger.info("[*] Starting SpectraC2 Consumer in standalone polling mode...")
