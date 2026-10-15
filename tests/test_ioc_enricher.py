import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from ioc_enricher.cache import LookupCache
from ioc_enricher.enrich import Indicator, enrich, load_env, load_indicators


class FakeClient:
    def __init__(self, scores):
        self.scores = scores
        self.calls = []

    def check(self, ip):
        self.calls.append(ip)
        return {"abuseConfidenceScore": self.scores.get(ip, 0), "totalReports": 1 if self.scores.get(ip) else 0,
                "isWhitelisted": False, "countryCode": "XX"}


class EnrichTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def cache(self, hours=24):
        return LookupCache(self.tmp / "cache.json", timedelta(hours=hours))

    def test_private_and_invalid_ips_are_never_sent(self):
        inds = load_indicators("10.0.0.5,192.168.1.1,127.0.0.1,not-an-ip,8.8.8.8")
        client = FakeClient({})
        enrich(inds, client, self.cache())
        self.assertEqual(client.calls, ["8.8.8.8"])
        self.assertEqual([i.verdict for i in inds][:4], ["skipped"] * 4)

    def test_verdict_thresholds(self):
        cases = {80: "malicious", 75: "malicious", 74: "suspicious", 25: "suspicious", 10: "low"}
        for score, expected in cases.items():
            ind = Indicator("1.1.1.1", intel={"abuseConfidenceScore": score, "totalReports": 3})
            self.assertEqual(ind.verdict, expected, score)
        self.assertEqual(Indicator("1.1.1.1", intel={"abuseConfidenceScore": 0, "totalReports": 0}).verdict,
                         "no reports")
        self.assertEqual(Indicator("1.1.1.1", intel={"abuseConfidenceScore": 90, "isWhitelisted": True}).verdict,
                         "whitelisted")

    def test_cache_prevents_repeat_lookups(self):
        client = FakeClient({"8.8.4.4": 50})
        cache = self.cache()
        enrich(load_indicators("8.8.4.4"), client, cache)
        cache.save()
        second = load_indicators("8.8.4.4")
        enrich(second, client, self.cache())
        self.assertEqual(client.calls, ["8.8.4.4"])
        self.assertTrue(second[0].from_cache)
        self.assertEqual(second[0].verdict, "suspicious")

    def test_expired_cache_is_refetched(self):
        client = FakeClient({})
        cache = self.cache()
        enrich(load_indicators("8.8.4.4"), client, cache)
        cache.entries["8.8.4.4"]["fetched_at"] = "2000-01-01T00:00:00+00:00"
        cache.save()
        enrich(load_indicators("8.8.4.4"), client, self.cache())
        self.assertEqual(client.calls, ["8.8.4.4", "8.8.4.4"])

    def test_reads_log_hunter_output_and_ignores_info_alerts(self):
        doc = {
            "summary": {"top_attacking_ips": [["1.2.3.4", 50], ["5.6.7.8", 20]]},
            "alerts": [
                {"rule": "brute_force", "severity": "high", "ip": "1.2.3.4", "count": 50},
                {"rule": "username_spray", "severity": "medium", "ip": "1.2.3.4", "count": 9},
                {"rule": "username_spray", "severity": "medium", "ip": "5.6.7.8", "count": 6},
                {"rule": "clean_login", "severity": "info", "ip": "9.9.9.9", "count": 0},
            ],
        }
        path = self.tmp / "alerts.json"
        path.write_text(json.dumps(doc))
        inds = load_indicators(str(path))
        self.assertEqual([i.ip for i in inds], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(inds[0].log_hunter_rules, ["brute_force", "username_spray"])
        self.assertEqual(inds[0].failed_logins, 50)
        self.assertEqual(inds[1].failed_logins, 20)

    def test_distributed_alert_expands_to_each_source(self):
        doc = {
            "summary": {"top_attacking_ips": []},
            "alerts": [{"rule": "distributed_brute_force", "severity": "medium", "ip": "multiple",
                        "count": 2, "sources": ["192.0.2.1", "192.0.2.2"]}],
        }
        path = self.tmp / "dist.json"
        path.write_text(json.dumps(doc))
        inds = load_indicators(str(path))
        self.assertEqual(sorted(i.ip for i in inds), ["192.0.2.1", "192.0.2.2"])
        self.assertTrue(all(i.log_hunter_rules == ["distributed_brute_force"] for i in inds))

    def test_load_env(self):
        path = self.tmp / ".env"
        path.write_text('# comment\nABUSEIPDB_API_KEY="abc123"\n')
        self.assertEqual(load_env(path)["ABUSEIPDB_API_KEY"], "abc123")


if __name__ == "__main__":
    unittest.main()
