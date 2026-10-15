import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Indicator:
    ip: str
    log_hunter_rules: list[str] = field(default_factory=list)
    failed_logins: int = 0
    skipped_reason: str | None = None
    intel: dict | None = None
    from_cache: bool = False

    @property
    def score(self) -> int | None:
        return self.intel.get("abuseConfidenceScore") if self.intel else None

    @property
    def verdict(self) -> str:
        if self.skipped_reason:
            return "skipped"
        if self.intel is None:
            return "not checked"
        if self.intel.get("isWhitelisted"):
            return "whitelisted"
        s = self.score or 0
        if s >= 75:
            return "malicious"
        if s >= 25:
            return "suspicious"
        if (self.intel.get("totalReports") or 0) > 0:
            return "low"
        return "no reports"


def load_indicators(source: str) -> list[Indicator]:
    """Accepts a Log Hunter alerts.json, a text file of IPs, or a comma-separated list of IPs."""
    path = Path(source)
    if path.suffix == ".json" and path.exists():
        return _from_log_hunter(json.loads(path.read_text(encoding="utf-8")))
    if path.exists():
        raw = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    else:
        raw = [s.strip() for s in source.split(",")]
    return [_screen(Indicator(ip)) for ip in dict.fromkeys(r for r in raw if r and not r.startswith("#"))]


def _from_log_hunter(doc: dict) -> list[Indicator]:
    failed = dict(doc["summary"].get("top_attacking_ips", []))
    by_ip: dict[str, Indicator] = {}
    for alert in doc["alerts"]:
        if alert["severity"] == "info":
            continue
        # Distributed alerts name many attackers in "sources" instead of one "ip".
        for ip in alert.get("sources") or [alert["ip"]]:
            ind = by_ip.setdefault(ip, Indicator(ip))
            if alert["rule"] not in ind.log_hunter_rules:
                ind.log_hunter_rules.append(alert["rule"])
            if alert["rule"] == "brute_force":
                ind.failed_logins = alert["count"]
    for ip, ind in by_ip.items():
        ind.failed_logins = ind.failed_logins or failed.get(ip, 0)
    return [_screen(i) for i in sorted(by_ip.values(), key=lambda i: -i.failed_logins)]


def _screen(ind: Indicator) -> Indicator:
    # Never send private/internal addresses to a third-party service: it leaks network layout
    # and the answer is meaningless anyway.
    try:
        addr = ipaddress.ip_address(ind.ip)
    except ValueError:
        ind.skipped_reason = "not a valid IP address"
        return ind
    if not addr.is_global:
        ind.skipped_reason = "private/reserved address, not sent to AbuseIPDB"
    return ind


def enrich(indicators: list[Indicator], client, cache) -> list[Indicator]:
    for ind in indicators:
        if ind.skipped_reason:
            continue
        cached = cache.get(ind.ip)
        if cached is not None:
            ind.intel, ind.from_cache = cached, True
            continue
        ind.intel = client.check(ind.ip)
        cache.put(ind.ip, ind.intel)
    return indicators


def load_env(path: Path) -> dict[str, str]:
    env = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip().strip('"').strip("'")
    return env
