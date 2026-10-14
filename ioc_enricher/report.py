import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .enrich import Indicator

VERDICT_ORDER = ["malicious", "suspicious", "low", "no reports", "whitelisted", "not checked", "skipped"]


def _row(ind: Indicator) -> dict:
    i = ind.intel or {}
    return {
        "ip": ind.ip,
        "verdict": ind.verdict,
        "abuse_score": ind.score,
        "total_reports": i.get("totalReports"),
        "distinct_reporters": i.get("numDistinctUsers"),
        "last_reported": i.get("lastReportedAt"),
        "country": i.get("countryCode"),
        "isp": i.get("isp"),
        "usage_type": i.get("usageType"),
        "is_tor": i.get("isTor"),
        "log_hunter_rules": ind.log_hunter_rules,
        "failed_logins": ind.failed_logins,
        "skipped_reason": ind.skipped_reason,
        "from_cache": ind.from_cache,
    }


def _sorted(indicators: list[Indicator]) -> list[Indicator]:
    return sorted(indicators, key=lambda i: (VERDICT_ORDER.index(i.verdict), -(i.score or 0), -i.failed_logins))


def print_console(indicators: list[Indicator], remaining_quota: int | None) -> None:
    print()
    for ind in _sorted(indicators):
        r = _row(ind)
        if ind.skipped_reason:
            print(f"[SKIPPED   ] {ind.ip:16} {ind.skipped_reason}")
            continue
        print(f"[{r['verdict'].upper():10}] {ind.ip:16} score {r['abuse_score']:>3}  "
              f"reports {r['total_reports'] or 0:>5}  {r['country'] or '--'}  {r['isp'] or ''}")
    counts = Counter(i.verdict for i in indicators)
    print("\n" + ", ".join(f"{counts[v]} {v}" for v in VERDICT_ORDER if counts[v]))
    if remaining_quota is not None:
        print(f"AbuseIPDB lookups left today: {remaining_quota}")


def write_json(path: Path, indicators: list[Indicator]) -> None:
    path.write_text(json.dumps([_row(i) for i in _sorted(indicators)], indent=2), encoding="utf-8")


def write_markdown(path: Path, indicators: list[Indicator], source: str) -> None:
    counts = Counter(i.verdict for i in indicators)
    lines = [
        "# IOC Enricher report",
        "",
        f"**Input:** `{source}`  ",
        f"**Threat intel:** AbuseIPDB (abuse confidence score 0–100)",
        "",
        "## Verdicts",
        "",
        "| Verdict | IPs |",
        "|---|---|",
    ]
    lines += [f"| {v} | {counts[v]} |" for v in VERDICT_ORDER if counts[v]]
    lines += [
        "",
        "## Indicators",
        "",
        "| IP | Verdict | Score | Reports | Reporters | Last reported | Country | ISP / usage | Seen by Log Hunter as |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for ind in _sorted(indicators):
        r = _row(ind)
        if ind.skipped_reason:
            lines.append(f"| {ind.ip} | skipped | | | | | | {ind.skipped_reason} | |")
            continue
        last = (r["last_reported"] or "")[:10]
        seen = ", ".join(r["log_hunter_rules"])
        if r["failed_logins"]:
            seen += f" ({r['failed_logins']} failed logins)"
        lines.append(
            f"| {ind.ip} | {r['verdict']} | {r['abuse_score']} | {r['total_reports']} | {r['distinct_reporters']} | "
            f"{last} | {r['country'] or ''} | {r['isp'] or ''} / {r['usage_type'] or ''} | {seen} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
