import json
from pathlib import Path
import tempfile
import unittest
from dns_trace.core import investigate, normalize_queries, in_zone, timestamp, normalize_leases
from dns_trace.__main__ import main

LABEL = "mzxw6ytboi234567abcdefghijklmno"
def event(second=0, query=None):
    return {"timestamp": f"2026-01-01T10:00:{second:02d}Z", "src_ip": "192.0.2.10",
            "query": query or LABEL + ".relay.example"}

class DNSTests(unittest.TestCase):
    def test_burst_links_original_rows_without_claiming_compromise(self):
        report = investigate([event(0), event(10), event(20)])
        alert = report["alerts"][0]
        self.assertEqual(alert["evidence_rows"], [1, 2, 3])
        self.assertIn("not proof", alert["assessment"])
        self.assertNotIn(LABEL, json.dumps(report))

    def test_window_uses_elapsed_time_not_bucket_boundaries(self):
        rows = [event(50), event(55), {**event(), "timestamp": "2026-01-01T10:01:01Z"}]
        self.assertEqual(len(investigate(rows)["alerts"]), 1)

    def test_events_outside_window_do_not_alert(self):
        rows = [event(0), event(40), {**event(), "timestamp": "2026-01-01T10:02:00Z"}]
        self.assertFalse(investigate(rows)["alerts"])

    def test_allowlist_has_label_boundaries(self):
        self.assertFalse(in_zone("eviltrusted.example", "trusted.example"))
        self.assertTrue(in_zone("a.trusted.example", "trusted.example"))
        self.assertFalse(investigate([event(0), event(10), event(20)], allowlist=["relay.example"])["alerts"])

    def test_reveal_is_explicit(self):
        self.assertIn(LABEL, json.dumps(investigate([event()], reveal_payload=True)))

    def test_low_entropy_and_short_queries_are_not_candidates(self):
        self.assertFalse(investigate([event(query="a" * 40 + ".relay.example")])["timeline"][0]["candidate"])

    def test_dhcp_end_is_exclusive_and_ambiguity_is_preserved(self):
        leases = [{"src_ip": "192.0.2.10", "hostname": x, "start": "2026-01-01T09:00:00Z", "end": "2026-01-01T10:00:10Z"} for x in ("host-a", "host-b")]
        timeline = investigate([event(0), event(10)], leases)["timeline"]
        self.assertEqual(timeline[0]["ownership"]["state"], "ambiguous")
        self.assertEqual(timeline[1]["ownership"]["state"], "unattributed")

    def test_valid_lease_correlation(self):
        lease = {"src_ip": "192.0.2.10", "hostname": "lab-a", "start": "2026-01-01T09:00:00Z", "end": "2026-01-01T11:00:00Z"}
        self.assertEqual(investigate([event()], [lease])["timeline"][0]["ownership"]["candidates"], ["lab-a"])

    def test_tshark_fields_and_dns_responses(self):
        rows = [{"frame.time_epoch": "1767261600.0", "ip.src": "192.0.2.1", "dns.qry.name": "example.com"},
                {"dns.flags.response": "1"}]
        self.assertEqual(len(normalize_queries(rows)), 1)

    def test_tshark_ipv6_with_empty_ipv4_column(self):
        rows = [{"frame.time_epoch": "1767261600.0", "ip.src": "", "ipv6.src": "2001:db8::1", "dns.qry.name": "www.example.com"}]
        self.assertEqual(normalize_queries(rows)[0]["src_ip"], "2001:db8::1")

    def test_timezone_invalid_ip_and_bad_name(self):
        for row in [{**event(), "timestamp": "2026-01-01T10:00:00"}, {**event(), "src_ip": "bad"}, {**event(), "query": "a..example"}]:
            with self.assertRaises(ValueError):
                investigate([row])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            investigate([event()], threshold=0)

    def test_reversed_lease_rejected(self):
        with self.assertRaises(ValueError):
            normalize_leases([{"src_ip": "192.0.2.1", "hostname": "x", "start": "2026-01-02T00:00:00Z", "end": "2026-01-01T00:00:00Z"}])

    def test_cli_generates_reports_with_provenance(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.json"
            path.write_text(json.dumps([event(0), event(1), event(2)]), encoding="utf-8")
            out = Path(folder) / "reports"
            self.assertEqual(main(["--queries", str(path), "--out", str(out)]), 0)
            report = json.loads((out / "investigation.json").read_text(encoding="utf-8"))
            self.assertEqual(len(report["provenance"]["queries_sha256"]), 64)
            self.assertTrue((out / "investigation.html").exists())

if __name__ == "__main__":
    unittest.main()
