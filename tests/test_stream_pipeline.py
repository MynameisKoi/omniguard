"""Integration and unit tests for Phase 2 Live Ingestion Pipeline.

Tests:
1. Zeek and Suricata Kafka producer serialization and fallback queuing.
2. TelemetryStreamConsumer sliding window evaluation and standardized alert schema formatting.
3. Asynchronous httpx dispatch and Graph-Triage Core API alert ingestion and buffering.
"""

import io
import json
import os
import queue
import sys
import time
import pytest
from fastapi.testclient import TestClient

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
telemetry_dir = os.path.join(repo_root, "telemetry-pipeline")
graph_dir = os.path.join(repo_root, "graph-triage-core")
engine_dir = os.path.join(repo_root, "spectrac2-engine")

for p in (telemetry_dir, graph_dir, engine_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

import importlib
zeek_mod = importlib.import_module("zeek-scripts.conn_parser")
suricata_mod = importlib.import_module("suricata.eve_parser")
consumer_mod = importlib.import_module("kafka-consumers.stream_consumer")

ZeekLogParser = zeek_mod.ZeekLogParser
ZeekKafkaProducer = zeek_mod.ZeekKafkaProducer
SuricataEveParser = suricata_mod.SuricataEveParser
SuricataKafkaProducer = suricata_mod.SuricataKafkaProducer
TelemetryStreamConsumer = consumer_mod.TelemetryStreamConsumer

from api.main import app as graph_core_app
from api.schemas import SpectraC2AlertInput

graph_client = TestClient(graph_core_app)


class TestKafkaTelemetryProducers:
    def test_zeek_producer_serialization_and_fallback(self):
        tsv_log = (
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\tresp_pkts\n"
            "1700000000.0\tCZeek01\t10.0.1.10\t49200\t198.51.100.20\t443\ttcp\tssl\t15.2\t1200\t4800\tSF\t-\t-\t0\tDd\t10\t12\n"
        )
        mem_queue = queue.Queue()
        count, producer = ZeekLogParser.stream_to_kafka(
            io.StringIO(tsv_log),
            bootstrap_servers="localhost:9092",
            fallback_queue=mem_queue,
        )
        assert count == 1
        assert not mem_queue.empty()

        item = mem_queue.get()
        assert item["source"] == "zeek"
        assert item["src_ip"] == "10.0.1.10"
        assert item["dst_ip"] == "198.51.100.20"
        assert item["dst_port"] == 443
        assert item["proto"] == "tcp"
        assert item["service"] == "ssl"
        assert item["bytes"] == 6000
        assert item["flow_key"] == "10.0.1.10:49200->198.51.100.20:443/tcp"

    def test_suricata_producer_serialization_and_fallback(self):
        eve_line = (
            '{"timestamp":"2026-09-14T12:00:00.000000+0000","event_type":"flow",'
            '"src_ip":"10.0.2.15","src_port":51234,"dest_ip":"203.0.113.50","dest_port":8443,'
            '"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":15,"pkts_toclient":12,'
            '"bytes_toserver":1800,"bytes_toclient":3200,"age":30.5},"tls":{"sni":"stealth-c2.net"}}'
        )
        mem_queue = queue.Queue()
        count, producer = SuricataEveParser.stream_to_kafka(
            io.StringIO(eve_line),
            bootstrap_servers="localhost:9092",
            fallback_queue=mem_queue,
        )
        assert count == 1
        assert not mem_queue.empty()

        item = mem_queue.get()
        assert item["source"] == "suricata"
        assert item["src_ip"] == "10.0.2.15"
        assert item["dst_ip"] == "203.0.113.50"
        assert item["dst_port"] == 8443
        assert item["proto"] == "tcp"
        assert item["service"] == "tls"
        assert item["sni"] == "stealth-c2.net"
        assert item["bytes"] == 5000


class TestStreamConsumerAndAlertSchema:
    def test_consumer_kafka_queue_ingest_and_alert_formatting(self):
        from inference.dataset_generator import SyntheticFlowGenerator

        gen = SyntheticFlowGenerator(random_seed=42)
        beacon_flow = gen.generate_c2_beacon(base_interval=5.0, jitter_pct=0.15, num_packets=25)

        # Feed packets through an in-memory queue to simulate Kafka topic 'network-flows'
        mem_queue = queue.Queue()
        for ts, sz, dr in zip(beacon_flow["timestamps"], beacon_flow["packet_sizes"], beacon_flow["directions"]):
            mem_queue.put({
                "source": "zeek",
                "src_ip": "10.0.5.20",
                "dst_ip": "198.51.100.88",
                "src_port": 54321,
                "dst_port": 443,
                "proto": "tcp",
                "service": "ssl",
                "host_id": "WORKSTATION-CORP-99",
                "sni": "beacon-service-domain.com",
                "timestamp": ts,
                "bytes": sz,
                "direction": dr,
            })

        consumer = TelemetryStreamConsumer()
        processed = consumer.consume_from_kafka(fallback_queue=mem_queue)
        assert processed == 25
        assert len(consumer.recent_alerts) > 0

        alert = consumer.recent_alerts[0]

        # Verify all 14 fields required by the OmniGuard alert specification
        required_keys = [
            "source",
            "event_type",
            "severity",
            "timestamp",
            "host_id",
            "src_ip",
            "dst_ip",
            "dst_port",
            "proto",
            "service",
            "sni",
            "mitre_technique",
            "confidence",
            "beacon_interval",
            "mean_jitter",
        ]
        for key in required_keys:
            assert key in alert, f"Missing required alert key: {key}"

        assert alert["source"] == "spectrac2"
        assert alert["event_type"] == "c2_beacon_detected"
        assert alert["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert isinstance(alert["timestamp"], float)
        assert alert["host_id"] == "WORKSTATION-CORP-99"
        assert alert["src_ip"] == "10.0.5.20"
        assert alert["dst_ip"] == "198.51.100.88"
        assert alert["dst_port"] == 443
        assert alert["proto"] == "tcp"
        assert alert["service"] == "ssl"
        assert alert["sni"] == "beacon-service-domain.com"
        assert alert["mitre_technique"] == "T1071"
        assert 0.0 <= alert["confidence"] <= 1.0
        assert alert["beacon_interval"] > 0.0
        assert alert["mean_jitter"] >= 0.0


class TestGraphCoreAlertEndpoint:
    def test_health_check(self):
        response = graph_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "graph-triage-core"
        assert "redis_connected" in data
        assert "pending_alerts_count" in data

    def test_post_valid_alert(self):
        alert_payload = {
            "source": "spectrac2",
            "event_type": "c2_beacon_detected",
            "severity": "CRITICAL",
            "timestamp": 1700000000.0,
            "host_id": "ENDPOINT-SEC-01",
            "src_ip": "10.20.30.40",
            "dst_ip": "198.51.100.99",
            "dst_port": 443,
            "proto": "tcp",
            "service": "ssl",
            "sni": "c2-exfil-node.org",
            "mitre_technique": "T1071",
            "confidence": 0.965,
            "beacon_interval": 10.0,
            "mean_jitter": 0.45,
        }
        response = graph_client.post("/api/v1/alerts", json=alert_payload)
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert "alert_id" in data
        assert data["timestamp"] == 1700000000.0
        assert data["buffered_in"] in ("redis", "memory")

        # Verify alert can be queried from buffer
        get_resp = graph_client.get("/api/v1/alerts")
        assert get_resp.status_code == 200
        alerts = get_resp.json()
        assert any(a.get("host_id") == "ENDPOINT-SEC-01" for a in alerts)

    def test_post_invalid_alert_confidence(self):
        # Confidence > 1.0 should fail Pydantic validation
        invalid_payload = {
            "source": "spectrac2",
            "event_type": "c2_beacon_detected",
            "severity": "CRITICAL",
            "timestamp": 1700000000.0,
            "host_id": "ENDPOINT-SEC-01",
            "src_ip": "10.20.30.40",
            "dst_ip": "198.51.100.99",
            "dst_port": 443,
            "confidence": 1.5,  # Invalid
            "beacon_interval": 10.0,
            "mean_jitter": 0.45,
        }
        response = graph_client.post("/api/v1/alerts", json=invalid_payload)
        assert response.status_code == 422

    def test_post_valid_verifyeye_alert(self):
        verifyeye_payload = {
            "source": "verifyeye",
            "event_type": "phishing_page_detected",
            "severity": "CRITICAL",
            "timestamp": 1700000010.0,
            "host_id": "HOST-CORP-WKSTN-10",
            "user": "maharjan",
            "src_ip": "10.0.1.42",
            "target_url": "https://evil-microsoft-login.com/auth/login.php",
            "domain": "evil-microsoft-login.com",
            "action_endpoint": "https://evil-microsoft-login.com/api/v1/harvest",
            "brand_target": "Microsoft 365",
            "confidence": 0.985,
            "phash_distance": 2.0,
            "input_frozen": True,
            "mitre_technique": "T1566.002",
            "description": "Visual impersonation of Microsoft 365 login portal intercepted.",
        }
        response = graph_client.post("/api/v1/alerts", json=verifyeye_payload)
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert "alert_id" in data
        assert data["timestamp"] == 1700000010.0

        # Verify alert appears in buffer
        get_resp = graph_client.get("/api/v1/alerts")
        assert get_resp.status_code == 200
        alerts = get_resp.json()
        assert any(a.get("source") == "verifyeye" and a.get("brand_target") == "Microsoft 365" for a in alerts)
