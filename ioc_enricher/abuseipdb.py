import json
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.abuseipdb.com/api/v2/check"


class QuotaExceeded(Exception):
    pass


class AuthError(Exception):
    pass


class AbuseIPDBClient:
    def __init__(self, api_key: str, max_age_days: int = 365, timeout: int = 15):
        if not api_key:
            raise AuthError("No API key. Put ABUSEIPDB_API_KEY=... in the .env file.")
        self.api_key = api_key
        self.max_age_days = max_age_days
        self.timeout = timeout
        self.remaining_quota: int | None = None

    def check(self, ip: str) -> dict:
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": self.max_age_days})
        req = urllib.request.Request(
            f"{API_URL}?{query}",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining is not None:
                    self.remaining_quota = int(remaining)
                return json.load(resp)["data"]
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError("AbuseIPDB rejected the API key (HTTP 401). Check the .env file.") from e
            if e.code == 429:
                raise QuotaExceeded("Daily AbuseIPDB quota used up (HTTP 429). Try again tomorrow.") from e
            raise
