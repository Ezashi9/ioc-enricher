import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


class LookupCache:
    """Stores past lookups on disk so re-runs don't spend the free tier's daily quota."""

    def __init__(self, path: Path, max_age: timedelta = timedelta(hours=24)):
        self.path = path
        self.max_age = max_age
        self.entries: dict = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def get(self, ip: str) -> dict | None:
        entry = self.entries.get(ip)
        if not entry:
            return None
        fetched = datetime.fromisoformat(entry["fetched_at"])
        if datetime.now(timezone.utc) - fetched > self.max_age:
            return None
        return entry["data"]

    def put(self, ip: str, data: dict) -> None:
        self.entries[ip] = {"fetched_at": datetime.now(timezone.utc).isoformat(), "data": data}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.entries, indent=2), encoding="utf-8")
