"""Unit tests for Zeek and Suricata telemetry parsers."""

import sys
import os
import io
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
telemetry_dir = os.path.join(repo_root, "telemetry-pipeline")
if telemetry_dir not in sys.path:
    sys.path.insert(0, telemetry_dir)

from zeek_scripts.conn_parser import ZeekLogParser
from suricata.eve_parser import SuricataEveParser


class TestZeekParser:
    def test_parse_json_zeek_record(self):
        json_line = (
            '{"ts":1700000000.5,"uid":"C12345","id.orig_h":"192.168.1.50",'
            '"id.orig_p":49812,"id.resp_h":"198.51.100.4","id.resp_p":443,'
            '"proto":"tcp","service":"ssl","duration":12.4,"orig_bytes":1420,'
            '"resp_bytes":5820,"orig_pkts":14,"resp_pkts":18,"conn_state":"SF"}'
        )
        record = next(ZeekLogParser.parse_file(io.StringIO(json_line)))
        assert record.uid == "C12345"
        assert record.src_ip == "192.168.1.50"
        assert record.src_port == 49812
        assert record.dst_ip == "198.51.100.4"
        assert record.dst_port == 443
        assert record.orig_bytes == 1420
        assert record.resp_bytes == 5820
        assert record.flow_key == "192.168.1.50:49812->198.51.100.4:443/tcp"

    def test_parse_tsv_zeek_record(self):
        tsv_content = (
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\tresp_pkts\n"
            "1700000010.0\tCUidTest\t10.0.0.1\t50000\t1.1.1.1\t53\tudp\tdns\t0.02\t45\t120\tSF\t-\t-\t0\tDd\t1\t1\n"
        )
        records = list(ZeekLogParser.parse_file(io.StringIO(tsv_content)))
        assert len(records) == 1
        rec = records[0]
        assert rec.uid == "CUidTest"
        assert rec.src_ip == "10.0.0.1"
        assert rec.dst_ip == "1.1.1.1"
        assert rec.proto == "udp"
        assert rec.orig_bytes == 45


class TestSuricataParser:
    def test_parse_eve_flow_event(self):
        eve_line = (
            '{"timestamp":"2026-09-12T14:20:10.500000+0000","event_type":"flow",'
            '"src_ip":"10.0.2.15","src_port":54321,"dest_ip":"203.0.113.8","dest_port":443,'
            '"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":20,"pkts_toclient":18,'
            '"bytes_toserver":2400,"bytes_toclient":4800,"age":45}}'
        )
        record = SuricataEveParser.parse_line(eve_line)
        assert record is not None
        assert record.src_ip == "10.0.2.15"
        assert record.dst_ip == "203.0.113.8"
        assert record.dst_port == 443
        assert record.bytes_toserver == 2400
        assert record.bytes_toclient == 4800
        assert record.duration == 45.0

    def test_parse_eve_tls_event(self):
        tls_line = (
            '{"timestamp":"2026-09-12T14:20:12.000000+0000","event_type":"tls",'
            '"src_ip":"10.0.2.15","src_port":54321,"dest_ip":"203.0.113.8","dest_port":443,'
            '"proto":"TCP","tls":{"sni":"evil-c2-listener.org","version":"TLS 1.3"}}'
        )
        record = SuricataEveParser.parse_line(tls_line)
        assert record is not None
        assert record.sni == "evil-c2-listener.org"
