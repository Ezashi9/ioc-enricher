# IOC Enricher

[![Tests](https://github.com/Ezashi9/ioc-enricher/actions/workflows/ci.yml/badge.svg)](https://github.com/Ezashi9/ioc-enricher/actions/workflows/ci.yml)

Checks IP addresses against the [AbuseIPDB](https://www.abuseipdb.com) threat-intelligence database and gives each one a verdict: **malicious, suspicious, low or no reports**. It also adds the country, network owner and how many people have reported the address.

It's the second part of **Home SOC**, a small security operations centre I'm building piece by piece. It reads the alerts from [Log Hunter](https://github.com/Ezashi9/log-hunter) directly, so each attacker IP keeps its context, e.g. "brute force, 286 failed logins".

```
Log Hunter (finds attackers in SSH logs) --> alerts.json --> IOC Enricher (what does the world know about them?)
```

## What it found

### 1. Attackers from historical logs: intelligence goes stale

I ran it on the 6 IPs Log Hunter flagged for brute force in the [Loghub OpenSSH dataset](https://github.com/logpai/loghub/tree/master/OpenSSH). **All 6 came back with no reports.**

That's a real result, not a bug. The logs are several years old and AbuseIPDB only counts reports from the last 365 days. Two of these IPs *were* reported in the past, last in May 2022 and September 2025, but both fall just outside the window. IP addresses also get reassigned: an address used by an attacker years ago may belong to someone innocent today.

**Takeaway:** threat intelligence has a shelf life. Blocking an IP because of an old report can block an innocent user, so this tool shows *when* each IP was last reported, not just whether it ever was.

[Full report](sample-report/historical/report.md)

### 2. IPs attacking SSH right now: 9 out of 10 malicious

To check the tool catches real threats, I ran it on 10 random IPs from [blocklist.de's SSH list](https://lists.blocklist.de/lists/ssh.txt) (addresses reported for SSH attacks in the last 48 hours):

| Verdict | IPs |
|---|---|
| malicious (score 100/100) | 9 |
| low | 1 |

One address had almost 13,000 abuse reports. The single "low" IP had only one report, which is exactly why it isn't labelled malicious: one report could be a mistake, and blocking on weak evidence causes false alarms.

[Full report](sample-report/recent/report.md)

## Design choices and why

| Choice | Why |
|---|---|
| **Private and invalid IPs are never sent** to AbuseIPDB | Addresses like `192.168.x.x` or `10.x.x.x` would reveal internal network layout to a third party, and the answer would be meaningless anyway. They're marked "skipped". |
| **Results cached for 24 hours** (`.cache/`) | The free plan allows 1,000 lookups a day. Re-running a report shouldn't burn quota, and abuse scores don't change minute to minute. |
| **API key read from `.env` or an environment variable**, never from code | `.env` is in `.gitignore`, so the key can't be committed to GitHub by accident. A leaked key lets someone else use up the quota or the account. |
| **Verdict thresholds:** ≥ 75 malicious, 25–74 suspicious, below 25 with reports = low | A high threshold for "malicious" keeps false alarms down. Whitelisted addresses (e.g. known scanners like Shodan) are labelled separately so they don't trigger alerts. |
| **Clear errors for a bad key (401) and used-up quota (429)** | The tool stops with a readable message instead of crashing, and still saves whatever it already looked up. |
| **Standard library only** | Nothing to install, and fewer dependencies means less to keep updated or go wrong. |

## Usage

Requires Python 3.10+. No packages to install.

1. Create a free account at abuseipdb.com, then **Account → API → Create Key**.
2. Copy `.env.example` to `.env` and paste the key after `ABUSEIPDB_API_KEY=`.

```bash
# Log Hunter output
python -m ioc_enricher ../log-hunter/sample-report/alerts.json

# a text file, one IP per line (lines starting with # are ignored)
python -m ioc_enricher samples/blocklist_de_ssh_sample.txt

# IPs on the command line
python -m ioc_enricher 8.8.8.8,1.1.1.1 --max-age 90 --out my-report
```

Outputs, in `reports/` by default: `report.md` (readable report) and `enriched.json` (for the next tool in the pipeline).

Run the tests (they use a fake AbuseIPDB client, so they don't spend real lookups):

```bash
python -m unittest discover -s tests -t .
```

## Project layout

```
ioc_enricher/
  abuseipdb.py  API client: key header, quota tracking, 401/429 handling
  cache.py      24-hour on-disk cache of lookups
  enrich.py     loads IPs (Log Hunter JSON, text file or list), filters private IPs, verdicts
  report.py     console, Markdown and JSON output
  __main__.py   command-line interface
tests/          unit tests
samples/        the blocklist.de sample used above
sample-report/  both example reports
```

## Next steps in Home SOC

- **Honeypot:** a decoy SSH server on a throwaway cloud VM, so the pipeline runs on attacks happening now. Those attackers' intelligence will be fresh, unlike the historical logs above.
- **[Dashboard](https://github.com/Ezashi9/home-soc-dashboard)** (done, [live demo](https://ezashi9.github.io/home-soc-dashboard/)): a web view combining Log Hunter and IOC Enricher results.

## Ethics and legal

This tool only **looks up** IP addresses in a public reputation database. It never contacts, scans or connects to them. In the UK, accessing systems without permission is an offence under the Computer Misuse Act 1990.

## Data credit

- Threat intelligence: [AbuseIPDB](https://www.abuseipdb.com)
- Recent attacker sample: [blocklist.de](https://www.blocklist.de)
- Historical logs: Loghub (Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*, IEEE ISSRE 2023), analysed by Log Hunter
