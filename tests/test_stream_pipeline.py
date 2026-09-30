"""Integration and unit tests for Phase 2 Live Ingestion Pipeline.

Tests:
1. Zeek and Suricata Kafka producer serialization and fallback queuing.
2. TelemetryStreamConsumer sliding window evaluation, and that its alerts validate
   against backend AlertCreate.

The Graph-Triage Core endpoint tests were removed: alert ingestion is
consolidated onto backend/ (POST /alerts), so there is one API and one
contract. See docs/graph-schema.md.
"""

import io
import json
import os
import queue
import sys
import time
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
telemetry_dir = os.path.join(repo_root, "telemetry-pipeline")
engine_dir = os.path.join(repo_root, "spectrac2-engine")
backend_dir = os.path.join(repo_root, "backend")

for p in (telemetry_dir, engine_dir, backend_dir):
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

from models import AlertCreate  # backend/models.py, the alert contract


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

        # The consumer must emit exactly what backend POST /alerts accepts.
        # Validating against AlertCreate itself means a rename on either side
        # fails here instead of as a silent 422 at runtime.
        AlertCreate.model_validate(alert)
        assert set(alert) <= set(AlertCreate.model_fields), (
            f"fields the backend would silently drop: {set(alert) - set(AlertCreate.model_fields)}"
        )

        # identity is stamped server-side, never by the producer
        assert "alert_id" not in alert
        assert "timestamp" not in alert

        assert alert["source"] == "spectrac2"
        assert alert["event_type"] == "c2_beacon_detected"
        assert alert["severity"] in ("low", "medium", "high", "critical")
        assert alert["host"] == "WORKSTATION-CORP-99"
        assert alert["src_ip"] == "10.0.5.20"
        assert alert["dst_ip"] == "198.51.100.88"
        assert alert["dst_port"] == 443
        assert alert["domain"] == "beacon-service-domain.com"
        assert alert["mitre_technique"] == "T1071"
        assert 0.0 <= alert["confidence"] <= 1.0
        assert alert["beacon_interval"] > 0.0
        assert alert["mean_jitter"] >= 0.0
