import argparse
import os
import sys
from datetime import timedelta
from pathlib import Path

from .abuseipdb import AbuseIPDBClient, AuthError, QuotaExceeded
from .cache import LookupCache
from .enrich import enrich, load_env, load_indicators
from .report import print_console, write_json, write_markdown

PROJECT_DIR = Path(__file__).resolve().parent.parent


def main() -> None:
    p = argparse.ArgumentParser(prog="ioc_enricher",
                                description="Check IP addresses against AbuseIPDB threat intelligence.")
    p.add_argument("source", help="Log Hunter alerts.json, a text file of IPs, or comma-separated IPs")
    p.add_argument("--out", default="reports", help="output folder")
    p.add_argument("--max-age", type=int, default=365, help="only count abuse reports from the last N days (1-365)")
    p.add_argument("--cache-hours", type=int, default=24, help="reuse lookups younger than this")
    args = p.parse_args()

    api_key = os.environ.get("ABUSEIPDB_API_KEY") or load_env(PROJECT_DIR / ".env").get("ABUSEIPDB_API_KEY", "")
    indicators = load_indicators(args.source)
    cache = LookupCache(PROJECT_DIR / ".cache" / "abuseipdb.json", timedelta(hours=args.cache_hours))

    try:
        client = AbuseIPDBClient(api_key, max_age_days=args.max_age)
        enrich(indicators, client, cache)
    except (AuthError, QuotaExceeded) as e:
        cache.save()
        sys.exit(f"Error: {e}")
    cache.save()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "enriched.json", indicators)
    write_markdown(out / "report.md", indicators, args.source)
    print_console(indicators, client.remaining_quota)
    print(f"Report written to {out / 'report.md'}")


if __name__ == "__main__":
    main()
