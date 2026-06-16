# NetScope

A self-contained internal network discovery + open-port dashboard. One Python file
runs `nmap` on a box inside your network, stores every scan in SQLite, and serves its
own dashboard — open it in a browser. No separate frontend, no external CDN.

The point of difference from a one-shot tool like ShieldsUP! is **history**: each scan is
diffed against the previous scan of the same target, so new devices and newly-opened
ports surface on their own in the "Changes since last scan" feed.

## Setup

```bash
pip install -r requirements.txt        # just Flask
# nmap binary must be installed and on PATH:
#   Debian/Ubuntu:  sudo apt install nmap
#   macOS (brew):   brew install nmap
#   Windows:        https://nmap.org/download.html
```

## Run

```bash
# Preview the UI with synthetic data, no nmap or network needed:
python3 netscope.py --demo

# Real scanning:
python3 netscope.py
#   then open http://127.0.0.1:8787
#   enter a target (e.g. 192.168.1.0/24) and pick a profile
```

Options: `--host 0.0.0.0` to expose on the LAN, `--port 8787` to change the port.
The database lives next to the script as `netscope.db` (override with `NETSCOPE_DB`).

## Scan profiles

| Profile  | nmap flags                       | Notes                                   |
|----------|----------------------------------|-----------------------------------------|
| quick    | `-T4 -F`                         | top 100 ports, fast, no root            |
| standard | `-T4 --top-ports 1000 -sV`       | service/version detection (default)     |
| deep     | `-T4 -p- -sV -O`                 | all ports + OS detection; run as root   |

`-O` (OS detection) and MAC/vendor resolution via ARP require root and only work when
scanning your local subnet. Run with `sudo` for those.

## How the risk coding works

`RISK_PORTS` in `netscope.py` maps a port to a severity and a plain-English reason
(Telnet → critical, RDP/SMB → high, databases → medium, and so on). Hosts are sorted so
the highest-severity device is first, and the "Risk findings" stat counts medium-and-above
open ports. Edit that dict to match your own policy.

## Only scan what you own

Point this at your own LAN/VLANs and your own public ranges. Scanning networks you don't
control can be illegal and will trip IDS/IPS. nmap traffic is noisy by design.

## Where this is going

This is piece one of three we scoped:

1. **Internal discovery + port dashboard** ← this tool
2. **External exposure checker** — same UI, but scans your public IP ranges from outside
   and enriches with the Shodan API (what the internet already sees about you).
3. **Posture fusion** — join each discovered host to Microsoft Graph (Intune compliance,
   Entra device state) and the UniFi Controller API, so a row reads
   "Adam's laptop — RDP exposed — non-compliant in Intune" instead of just an IP and a port.

The SQLite schema (`scans` / `hosts` / `ports`) and the `scan_payload` serializer are built
to extend toward 2 and 3 without a rewrite — add an `exposure` source and a `posture` join
keyed on IP/MAC.

---

# ExtScope (piece two)

`extscope.py` is the external counterpart — the ShieldsUP! analog. It shows what the
internet already sees about your public IPs, without you scanning from inside the firewall
(which gives wrong answers due to NAT hairpinning — you'd be looking the wrong direction).

## Sources, in order of preference

1. **Shodan InternetDB** (default) — free, no API key, no scanning on your part. Returns the
   open ports, CVEs, detected software (CPEs), hostnames and tags that Shodan's crawlers
   already observed. Refreshed weekly. This is the low-noise "see yourself as an attacker
   using Shodan does" view.
2. **Shodan API** (optional) — paste an API key for real-time, banner-level detail.
3. **Active nmap** (optional) — `--allow-active`, and **run it from a VPS outside your
   network**, never from inside CEAS, or the results are meaningless.

## Run

```bash
python3 extscope.py --demo          # preview UI with synthetic CEAS-style data
python3 extscope.py                 # real: open http://127.0.0.1:8788, paste public IPs
python3 extscope.py --allow-active  # also enable the active nmap source (from a VPS)
```

## Finding your public IPs

Pull the WAN addresses off the SonicWall, check your ISP's static allocation, or from each
egress run `curl -s ifconfig.me`. Enter them one per line; small CIDRs (<= /24) are expanded.

## Risk model flips for external

Inside a LAN, SMB/RDP/database ports are routine. Facing the internet they are critical.
`RISK_PORTS` in `extscope.py` encodes that — RDP, SMB, VNC, Telnet and any exposed database
are critical; SSH is medium (lock to an allowlist); 80/443/VPN ports are informational. Any
CVE reported by Shodan bumps the host to high.

## Suite note

NetScope (internal) and ExtScope (external) share the same schema shape, severity model, and
delta engine on purpose. Piece three — posture fusion — joins either tool's hosts to Microsoft
Graph (Intune/Entra) and the UniFi Controller by IP/MAC. The two could also be merged into a
single tabbed console later; kept separate for now so each runs independently.