#!/usr/bin/env python3
"""
ExtScope - external exposure checker. The ShieldsUP! analog, done right.

Instead of scanning yourself from inside the firewall (which gives misleading
results), ExtScope asks the internet what it already sees about your public IPs.

  Primary source : Shodan InternetDB  (free, no API key, no scanning by you)
  Optional        : a Shodan API key for real-time banners / richer detail
  Optional        : an active nmap pass -- ONLY meaningful from an off-network host

  Preview UI:   python3 extscope.py --demo
  Real run:     python3 extscope.py        then open http://127.0.0.1:8788
                paste your public IPs, click "Check exposure"

Requires: Flask  (pip install flask). nmap only needed for the optional active mode.
Only check IPs you own or are authorized to assess.
"""

import argparse
import ipaddress
import json
import os
import sqlite3
import subprocess
import threading
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from flask import Flask, request, jsonify, Response

DB_PATH = os.environ.get("EXTSCOPE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "extscope.db"))
DEMO = False
ALLOW_ACTIVE = False
_db_lock = threading.Lock()
app = Flask(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"

# External risk model: ports tuned for INTERNET exposure. Things that are routine
# inside a LAN (SMB, RDP, databases) are critical when reachable from the internet.
RISK_PORTS = {
    23:    ("critical", "Telnet exposed to internet - cleartext admin, never expose"),
    3389:  ("critical", "RDP exposed to internet - prime ransomware entry point"),
    445:   ("critical", "SMB exposed to internet - wormable, never expose"),
    5900:  ("critical", "VNC exposed to internet - remote desktop, often weak auth"),
    3306:  ("critical", "MySQL exposed to internet - database should never be public"),
    5432:  ("critical", "PostgreSQL exposed to internet - database should never be public"),
    1433:  ("critical", "MSSQL exposed to internet - database should never be public"),
    27017: ("critical", "MongoDB exposed to internet - frequently breached unauth"),
    6379:  ("critical", "Redis exposed to internet - frequently breached unauth"),
    9200:  ("critical", "Elasticsearch exposed to internet - often unauthenticated"),
    21:    ("high",     "FTP exposed - cleartext credentials"),
    139:   ("high",     "NetBIOS exposed - legacy SMB session service"),
    135:   ("high",     "MSRPC exposed - enumeration / exploitation surface"),
    161:   ("high",     "SNMP exposed - default community strings are common"),
    111:   ("high",     "rpcbind exposed - service enumeration / amplification"),
    5984:  ("high",     "CouchDB exposed - often unauthenticated"),
    22:    ("medium",   "SSH exposed - restrict to an allowlist and keys-only"),
    53:    ("medium",   "DNS exposed - ensure it is not an open recursive resolver"),
    3000:  ("medium",   "Dev/app port exposed - confirm this should be public"),
    8080:  ("low",      "HTTP-alt exposed - confirm intended service"),
    8443:  ("low",      "HTTPS-alt exposed - confirm intended service"),
    25:    ("low",      "SMTP - expected only if you run mail here (you use M365)"),
    587:   ("info",     "SMTP submission"),
    465:   ("info",     "SMTP submission (implicit TLS)"),
    993:   ("info",     "IMAPS"),
    995:   ("info",     "POP3S"),
    80:    ("info",     "HTTP - expected for a web server"),
    443:   ("info",     "HTTPS - expected for a web server"),
    500:   ("info",     "IKE/IPsec VPN"),
    4500:  ("info",     "IPsec NAT-T VPN"),
}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1}

SOURCES = {
    "internetdb": "Shodan InternetDB (free, no key)",
    "shodan": "Shodan API (needs key, richer)",
    "active": "Active nmap (run from an external host)",
}


# ---------------------------------------------------------------- storage
def dbc():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock, dbc() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL, source TEXT NOT NULL,
            started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, error TEXT,
            ip_count INTEGER DEFAULT 0, exposed_port_count INTEGER DEFAULT 0,
            cve_count INTEGER DEFAULT 0, crit_count INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS hosts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL, hostnames TEXT, tags TEXT, cpes TEXT, vulns TEXT, reachable INTEGER);
        CREATE TABLE IF NOT EXISTS ports(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL, port INTEGER NOT NULL, severity TEXT, reason TEXT, service TEXT);
        CREATE INDEX IF NOT EXISTS idx_h_scan ON hosts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_p_scan ON ports(scan_id);
        """)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- input parsing
def parse_targets(raw):
    """Accept newline/comma/space separated IPs and small CIDRs. Expand CIDR <= /24."""
    ips = []
    for tok in raw.replace(",", " ").split():
        tok = tok.strip()
        if not tok:
            continue
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.num_addresses > 256:
                    raise ValueError(f"{tok} too large (limit /24)")
                ips.extend(str(h) for h in net.hosts())
            else:
                ips.append(str(ipaddress.ip_address(tok)))
        except ValueError as e:
            raise ValueError(f"Bad target '{tok}': {e}")
    # dedupe, keep order
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip); out.append(ip)
    return out


# ---------------------------------------------------------------- sources
def http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ExtScope/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def query_internetdb(ip):
    """Returns dict or None (404 = nothing known / no exposure)."""
    try:
        d = http_json(INTERNETDB_URL.format(ip=ip))
        return {"ip": ip, "ports": d.get("ports", []), "vulns": d.get("vulns", []),
                "cpes": d.get("cpes", []), "hostnames": d.get("hostnames", []),
                "tags": d.get("tags", []), "reachable": True}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ip": ip, "ports": [], "vulns": [], "cpes": [], "hostnames": [],
                    "tags": [], "reachable": True}  # clean: known to Shodan, nothing exposed
        raise


def query_shodan(ip, key):
    try:
        d = http_json(SHODAN_HOST_URL.format(ip=ip, key=key))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ip": ip, "ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": [], "reachable": True}
        raise
    products = []
    for item in d.get("data", []):
        if item.get("product"):
            products.append(item["product"])
    return {"ip": ip, "ports": d.get("ports", []), "vulns": list(d.get("vulns", []) or []),
            "cpes": products, "hostnames": d.get("hostnames", []), "tags": list(d.get("tags", []) or []),
            "reachable": True}


def query_active(ip):
    cmd = ["nmap", "-T4", "--top-ports", "1000", "-Pn", "-oX", "-", ip]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or "nmap failed")
    root = ET.fromstring(proc.stdout)
    ports, hostnames = [], []
    h = root.find("host")
    if h is not None:
        for hn in h.findall("hostnames/hostname"):
            hostnames.append(hn.get("name"))
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is not None and st.get("state") == "open":
                ports.append(int(p.get("portid")))
    return {"ip": ip, "ports": ports, "vulns": [], "cpes": [], "hostnames": hostnames,
            "tags": [], "reachable": True}


# ---------------------------------------------------------------- persist + worker
def persist(scan_id, results):
    exposed = cves = crits = 0
    with _db_lock, dbc() as conn:
        for r in results:
            conn.execute(
                "INSERT INTO hosts(scan_id,ip,hostnames,tags,cpes,vulns,reachable) VALUES (?,?,?,?,?,?,?)",
                (scan_id, r["ip"], json.dumps(r["hostnames"]), json.dumps(r["tags"]),
                 json.dumps(r["cpes"]), json.dumps(r["vulns"]), 1 if r["reachable"] else 0))
            cves += len(r["vulns"])
            for port in sorted(set(r["ports"])):
                sev, reason = RISK_PORTS.get(port, ("medium", "Unexpected port open to internet - investigate"))
                exposed += 1
                if sev == "critical":
                    crits += 1
                conn.execute(
                    "INSERT INTO ports(scan_id,ip,port,severity,reason,service) VALUES (?,?,?,?,?,?)",
                    (scan_id, r["ip"], port, sev, reason, None))
        conn.execute(
            "UPDATE scans SET status='done',finished_at=?,ip_count=?,exposed_port_count=?,cve_count=?,crit_count=? WHERE id=?",
            (now_iso(), len(results), exposed, cves, crits, scan_id))


def scan_worker(scan_id, ips, source, key):
    try:
        results = []
        for ip in ips:
            if source == "shodan":
                results.append(query_shodan(ip, key))
            elif source == "active":
                results.append(query_active(ip))
            else:
                results.append(query_internetdb(ip))
            time.sleep(0.4)  # be polite to the API
        persist(scan_id, results)
    except Exception as e:  # noqa: BLE001
        with _db_lock, dbc() as conn:
            conn.execute("UPDATE scans SET status='error',finished_at=?,error=? WHERE id=?",
                         (now_iso(), str(e), scan_id))


def start_scan(ips, source, key):
    target = ",".join(sorted(ips))
    with _db_lock, dbc() as conn:
        cur = conn.execute("INSERT INTO scans(target,source,started_at,status) VALUES (?,?,?,?)",
                           (target, source, now_iso(), "running"))
        sid = cur.lastrowid
    threading.Thread(target=scan_worker, args=(sid, ips, source, key), daemon=True).start()
    return sid


# ---------------------------------------------------------------- deltas
def previous_done(conn, target, before_id):
    return conn.execute(
        "SELECT * FROM scans WHERE target=? AND status='done' AND id<? ORDER BY id DESC LIMIT 1",
        (target, before_id)).fetchone()


def port_map(conn, sid):
    return {(r["ip"], r["port"]): r for r in
            conn.execute("SELECT ip,port,severity FROM ports WHERE scan_id=?", (sid,)).fetchall()}


def cve_set(conn, sid):
    out = set()
    for r in conn.execute("SELECT ip,vulns FROM hosts WHERE scan_id=?", (sid,)).fetchall():
        for c in json.loads(r["vulns"] or "[]"):
            out.add((r["ip"], c))
    return out


def compute_deltas(conn, scan):
    prev = previous_done(conn, scan["target"], scan["id"])
    if not prev:
        return {"baseline": True, "items": []}
    items = []
    cur_p, prev_p = port_map(conn, scan["id"]), port_map(conn, prev["id"])
    for k in cur_p.keys() - prev_p.keys():
        sev = cur_p[k]["severity"]
        items.append({"severity": sev if SEV_RANK.get(sev, -1) >= 1 else "low", "kind": "port exposed",
                      "text": f"Newly exposed to internet: port {k[1]} on {k[0]}"})
    for k in prev_p.keys() - cur_p.keys():
        items.append({"severity": "info", "kind": "port closed",
                      "text": f"No longer exposed: port {k[1]} on {k[0]}"})
    cur_c, prev_c = cve_set(conn, scan["id"]), cve_set(conn, prev["id"])
    for ip, cve in cur_c - prev_c:
        items.append({"severity": "high", "kind": "new cve", "text": f"New CVE {cve} on {ip}"})
    items.sort(key=lambda i: SEV_RANK.get(i["severity"], -1), reverse=True)
    return {"baseline": False, "items": items}


# ---------------------------------------------------------------- serialize
def cpe_name(cpe):
    parts = cpe.split(":")
    return parts[-1] if parts else cpe


def payload(conn, scan):
    hosts = []
    for h in conn.execute("SELECT * FROM hosts WHERE scan_id=? ORDER BY ip", (scan["id"],)).fetchall():
        prows = conn.execute("SELECT * FROM ports WHERE scan_id=? AND ip=? ORDER BY port",
                             (scan["id"], h["ip"])).fetchall()
        ports = [dict(p) for p in prows]
        vulns = json.loads(h["vulns"] or "[]")
        max_sev = max([SEV_RANK.get(p["severity"], -1) for p in ports] + ([3] if vulns else [-1]))
        max_name = next((k for k, v in SEV_RANK.items() if v == max_sev), "none")
        hosts.append({"ip": h["ip"], "hostnames": json.loads(h["hostnames"] or "[]"),
                      "tags": json.loads(h["tags"] or "[]"),
                      "cpes": [cpe_name(c) for c in json.loads(h["cpes"] or "[]")],
                      "vulns": vulns, "ports": ports, "max_severity": max_name})
    hosts.sort(key=lambda h: SEV_RANK.get(h["max_severity"], -1), reverse=True)
    freq = {}
    for h in hosts:
        for p in h["ports"]:
            freq.setdefault(p["port"], {"port": p["port"], "severity": p["severity"], "count": 0})
            freq[p["port"]]["count"] += 1
    top = sorted(freq.values(), key=lambda x: x["count"], reverse=True)[:12]
    return {"scan": dict(scan), "hosts": hosts, "top_ports": top, "deltas": compute_deltas(conn, scan)}


# ---------------------------------------------------------------- API
@app.post("/api/scan")
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    raw = (data.get("targets") or "").strip()
    source = data.get("source", "internetdb")
    key = (data.get("key") or "").strip()
    if not raw:
        return jsonify({"error": "Enter at least one public IP (e.g. 203.0.113.10)"}), 400
    if source not in SOURCES:
        return jsonify({"error": "unknown source"}), 400
    if DEMO:
        return jsonify({"error": "Demo mode - live lookups disabled. Restart without --demo."}), 400
    if source == "shodan" and not key:
        return jsonify({"error": "Shodan source needs an API key"}), 400
    if source == "active" and not ALLOW_ACTIVE:
        return jsonify({"error": "Active nmap disabled. Restart with --allow-active, and run from an "
                                 "external host (a VPS) -- not from inside your network."}), 400
    try:
        ips = parse_targets(raw)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not ips:
        return jsonify({"error": "No valid IPs found"}), 400
    if len(ips) > 256:
        return jsonify({"error": "Too many IPs in one run (limit 256)"}), 400
    return jsonify({"scan_id": start_scan(ips, source, key)})


@app.get("/api/scan/<int:sid>")
def api_scan_get(sid):
    with dbc() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not scan:
            return jsonify({"error": "not found"}), 404
        if scan["status"] != "done":
            return jsonify({"scan": dict(scan)})
        return jsonify(payload(conn, scan))


@app.get("/api/latest")
def api_latest():
    with dbc() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE status='done' ORDER BY id DESC LIMIT 1").fetchone()
        if not scan:
            return jsonify({"empty": True})
        return jsonify(payload(conn, scan))


@app.get("/api/meta")
def api_meta():
    return jsonify({"demo": DEMO, "allow_active": ALLOW_ACTIVE, "sources": SOURCES})


@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# ---------------------------------------------------------------- demo seed
def seed_demo():
    with _db_lock, dbc() as conn:
        if conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]:
            return
    ips = ["203.0.113.10", "203.0.113.11", "203.0.113.20"]
    target = ",".join(sorted(ips))
    run1 = [
        {"ip": "203.0.113.10", "ports": [80, 443], "vulns": [], "cpes": ["cpe:/a:nginx:nginx"],
         "hostnames": ["www.ceasusa.com"], "tags": ["cdn"], "reachable": True},
        {"ip": "203.0.113.11", "ports": [443, 4500, 500], "vulns": [], "cpes": [],
         "hostnames": ["vpn.ceasusa.com"], "tags": ["vpn"], "reachable": True},
        {"ip": "203.0.113.20", "ports": [80, 443], "vulns": [], "cpes": ["cpe:/a:apache:http_server:2.4.49"],
         "hostnames": ["portal.ceasusa.com"], "tags": [], "reachable": True},
    ]
    run2 = [
        {"ip": "203.0.113.10", "ports": [80, 443], "vulns": [], "cpes": ["cpe:/a:nginx:nginx"],
         "hostnames": ["www.ceasusa.com"], "tags": ["cdn"], "reachable": True},
        {"ip": "203.0.113.11", "ports": [443, 4500, 500, 3389], "vulns": [], "cpes": [],
         "hostnames": ["vpn.ceasusa.com"], "tags": ["vpn"], "reachable": True},  # RDP newly exposed!
        {"ip": "203.0.113.20", "ports": [80, 443], "vulns": ["CVE-2021-41773"],
         "cpes": ["cpe:/a:apache:http_server:2.4.49"],
         "hostnames": ["portal.ceasusa.com"], "tags": [], "reachable": True},  # new CVE
    ]
    for run in (run1, run2):
        with _db_lock, dbc() as conn:
            sid = conn.execute("INSERT INTO scans(target,source,started_at,status) VALUES (?,?,?,?)",
                               (target, "internetdb", now_iso(), "running")).lastrowid
        persist(sid, run)


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ExtScope</title>
<style>
  :root{
    --bg:#0a1424; --bg2:#0d1b30; --panel:#12233e; --panel2:#16294a;
    --line:#1f3a5f; --line2:#274a78; --ink:#e8eef7; --muted:#8aa0c0; --faint:#5d769a;
    --accent:#3b82f6;
    --crit:#ff3b5c; --high:#ff6b4a; --med:#f5a623; --low:#5db0ff; --info:#4a6b94; --ok:#33c27f;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased}
  .wrap{max-width:1240px;margin:0 auto;padding:20px 22px 60px}
  header{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;
    border-bottom:1px solid var(--line);padding-bottom:16px;flex-wrap:wrap}
  .brand{display:flex;align-items:baseline;gap:12px}
  .brand h1{font-size:20px;letter-spacing:.14em;margin:0;font-weight:700;text-transform:uppercase}
  .brand .v{font-family:var(--mono);font-size:11px;color:var(--faint)}
  .demo-tag{font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--med);
    border:1px solid var(--med);border-radius:3px;padding:2px 7px;text-transform:uppercase}
  .controls{display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap;justify-content:flex-end}
  textarea,input,select,button{font-family:var(--mono);font-size:13px;border-radius:5px;
    border:1px solid var(--line2);background:var(--panel);color:var(--ink);padding:8px 11px;outline:none}
  textarea{min-width:230px;height:64px;resize:vertical;line-height:1.5}
  input{min-width:170px}
  textarea:focus,input:focus,select:focus{border-color:var(--accent)}
  .col{display:flex;flex-direction:column;gap:8px}
  button{background:var(--accent);border-color:var(--accent);color:#fff;cursor:pointer;font-weight:600}
  button:hover{filter:brightness(1.1)} button:disabled{opacity:.5;cursor:default}
  #keyWrap{display:none}

  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
  .stat .n{font-family:var(--mono);font-size:26px;font-weight:700;line-height:1}
  .stat .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:7px}
  .stat.crit .n{color:var(--crit)} .stat.cve .n{color:var(--high)}

  .grid{display:grid;grid-template-columns:1fr 360px;gap:18px}
  @media(max-width:920px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.controls{justify-content:flex-start}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
  .card>h2{font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);
    margin:0;padding:13px 16px;border-bottom:1px solid var(--line);font-weight:600}

  table{width:100%;border-collapse:collapse;font-size:13px}
  thead th{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);
    text-align:left;padding:9px 16px;border-bottom:1px solid var(--line);font-weight:600}
  tbody tr{border-bottom:1px solid var(--bg2);cursor:pointer}
  tbody tr:hover{background:var(--panel2)}
  td{padding:11px 16px;vertical-align:top}
  .ip{font-family:var(--mono);font-weight:600}
  .sub{color:var(--faint);font-family:var(--mono);font-size:11px}
  .tag{font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:3px;background:var(--bg2);
    border:1px solid var(--line2);color:var(--muted);margin-left:5px}
  .chips{display:flex;flex-wrap:wrap;gap:5px}
  .chip{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:4px;
    border:1px solid var(--line2);background:var(--bg2);color:var(--muted)}
  .chip.sev-critical{border-color:var(--crit);color:var(--crit)}
  .chip.sev-high{border-color:var(--high);color:var(--high)}
  .chip.sev-medium{border-color:var(--med);color:var(--med)}
  .chip.sev-low{border-color:var(--low);color:var(--low)}
  .cve-chip{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:4px;
    border:1px solid var(--high);color:var(--high);background:rgba(255,107,74,.08)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;vertical-align:middle}
  .d-critical{background:var(--crit)} .d-high{background:var(--high)} .d-medium{background:var(--med)}
  .d-low{background:var(--low)} .d-info,.d-none{background:var(--info)}
  .detail{display:none;background:var(--bg2)} .detail.open{display:table-row}
  .detail td{padding:0} .detail .inner{padding:12px 16px}
  .pline{font-family:var(--mono);font-size:12px;padding:6px 0;border-bottom:1px solid var(--panel);
    display:flex;gap:14px;align-items:baseline}
  .pline:last-child{border-bottom:0} .pline .pn{width:54px;font-weight:700}
  .pline.sev-critical .pn{color:var(--crit)} .pline.sev-high .pn{color:var(--high)}
  .pline.sev-medium .pn{color:var(--med)} .pline .reason{color:var(--faint)}
  .meta{font-family:var(--mono);font-size:11px;color:var(--faint);margin-top:8px}

  .delta-card{border-color:var(--line2)} .delta-list{max-height:300px;overflow:auto}
  .delta{display:flex;gap:11px;align-items:flex-start;padding:11px 16px;border-bottom:1px solid var(--bg2)}
  .delta:last-child{border-bottom:0}
  .delta .bar{width:3px;align-self:stretch;border-radius:2px;flex:0 0 auto}
  .delta.critical .bar{background:var(--crit)} .delta.high .bar{background:var(--high)}
  .delta.medium .bar{background:var(--med)} .delta.low .bar{background:var(--low)} .delta.info .bar{background:var(--info)}
  .delta .t{font-size:13px;line-height:1.4}
  .delta .k{font-family:var(--mono);font-size:10px;color:var(--faint);text-transform:uppercase;margin-top:3px}
  .note{padding:20px 16px;color:var(--muted);font-size:13px;line-height:1.5}
  .cve-list{max-height:220px;overflow:auto;padding:6px 0}
  .cve-row{display:flex;justify-content:space-between;gap:10px;padding:7px 16px;font-family:var(--mono);font-size:12px;border-bottom:1px solid var(--bg2)}
  .cve-row:last-child{border-bottom:0} .cve-row .c{color:var(--high)} .cve-row .ip{color:var(--muted)}

  .bar-row{display:flex;align-items:center;gap:10px;padding:6px 16px;font-family:var(--mono);font-size:12px}
  .bar-row .lbl{width:60px;color:var(--muted)}
  .bar-row .track{flex:1;background:var(--bg2);border-radius:3px;height:14px;overflow:hidden}
  .bar-row .fill{height:100%;border-radius:3px;background:var(--accent)}
  .bar-row .fill.sev-critical{background:var(--crit)} .bar-row .fill.sev-high{background:var(--high)}
  .bar-row .fill.sev-medium{background:var(--med)} .bar-row .fill.sev-low{background:var(--low)}
  .bar-row .cnt{width:24px;text-align:right;color:var(--ink)}

  .status{font-family:var(--mono);font-size:12px;color:var(--muted);margin:14px 0;min-height:16px}
  .status.err{color:var(--high)}
  .foot{color:var(--faint);font-size:11px;margin-top:28px;line-height:1.6;border-top:1px solid var(--line);padding-top:14px}
  .spin{display:inline-block;width:12px;height:12px;border:2px solid var(--line2);border-top-color:var(--accent);
    border-radius:50%;animation:s .7s linear infinite;vertical-align:-1px;margin-right:7px}
  @keyframes s{to{transform:rotate(360deg)}}
  @media(prefers-reduced-motion:reduce){.spin{animation:none}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <h1>ExtScope</h1><span class="v">v1 · external exposure</span>
      <span id="demoTag" class="demo-tag" style="display:none">demo data</span>
    </div>
    <div class="controls">
      <textarea id="targets" placeholder="Public IPs, one per line&#10;203.0.113.10&#10;203.0.113.0/29"></textarea>
      <div class="col">
        <select id="source"></select>
        <span id="keyWrap"><input id="key" placeholder="Shodan API key" /></span>
      </div>
      <button id="run">Check exposure</button>
    </div>
  </header>

  <div id="status" class="status"></div>

  <div class="stats">
    <div class="stat"><div class="n" id="s-ips">—</div><div class="l">IPs checked</div></div>
    <div class="stat"><div class="n" id="s-ports">—</div><div class="l">Exposed ports</div></div>
    <div class="stat crit"><div class="n" id="s-crit">—</div><div class="l">Critical exposures</div></div>
    <div class="stat cve"><div class="n" id="s-cve">—</div><div class="l">Known CVEs</div></div>
  </div>

  <div class="grid">
    <div class="card">
      <h2 id="hostHdr">Public IPs</h2>
      <table>
        <thead><tr><th>Address</th><th>Identity</th><th>Exposed ports</th></tr></thead>
        <tbody id="hosts"></tbody>
      </table>
    </div>
    <div style="display:flex;flex-direction:column;gap:18px">
      <div class="card delta-card">
        <h2>Changes since last check</h2>
        <div id="deltas" class="delta-list"></div>
      </div>
      <div class="card">
        <h2>Known vulnerabilities</h2>
        <div id="cves" class="cve-list"></div>
      </div>
      <div class="card">
        <h2>Most exposed ports</h2>
        <div id="chart" style="padding:10px 0"></div>
      </div>
    </div>
  </div>

  <div class="foot">
    ExtScope shows what the internet already knows about your public IPs via Shodan's InternetDB
    (free, no key, no scanning by you). Results are Shodan's most recent crawl, refreshed weekly.
    For real-time confirmation add a Shodan API key, or run the active nmap source from a host
    outside your network. Each check is diffed against the previous check of the same IP set, so a
    newly exposed port or new CVE surfaces on its own. Only check IPs you own or are authorized to assess.
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const SEV = {critical:4,high:3,medium:2,low:1,info:0,none:-1};
let pollTimer=null, META={};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

async function boot(){
  META = await (await fetch('/api/meta')).json();
  const sel=$('#source');
  sel.innerHTML = Object.entries(META.sources).map(([k,v])=>`<option value="${k}">${esc(v)}</option>`).join('');
  sel.value='internetdb';
  sel.addEventListener('change',()=>{ $('#keyWrap').style.display = sel.value==='shodan'?'block':'none'; });
  if(META.demo){ $('#demoTag').style.display='inline-block'; $('#run').disabled=true; $('#targets').disabled=true; }
  loadLatest();
}
async function loadLatest(){
  const d = await (await fetch('/api/latest')).json();
  if(d.empty){ setStatus('No checks yet. Paste your public IPs and run an exposure check.'); return; }
  render(d);
}
$('#run').addEventListener('click', async ()=>{
  const targets=$('#targets').value.trim();
  if(!targets){ setStatus('Enter at least one public IP.', true); return; }
  $('#run').disabled=true;
  setStatus('<span class="spin"></span>Checking exposure …');
  const res=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({targets, source:$('#source').value, key:$('#key').value})});
  const j=await res.json();
  if(j.error){ setStatus(j.error,true); $('#run').disabled=false; return; }
  poll(j.scan_id);
});
function poll(id){
  clearInterval(pollTimer);
  pollTimer=setInterval(async ()=>{
    const d=await (await fetch('/api/scan/'+id)).json();
    if(d.scan.status==='running'){ setStatus('<span class="spin"></span>Looking up '+esc(d.scan.source)+' …'); return; }
    clearInterval(pollTimer); $('#run').disabled=false;
    if(d.scan.status==='error'){ setStatus('Check failed: '+esc(d.scan.error), true); return; }
    render(d);
  },1500);
}
function setStatus(html,err){ const s=$('#status'); s.innerHTML=html; s.className='status'+(err?' err':''); }

function render(d){
  const s=d.scan, when=new Date(s.finished_at||s.started_at).toLocaleString();
  setStatus('Last check: '+s.ip_count+' IPs · '+esc(s.source)+' · '+when);
  $('#s-ips').textContent=s.ip_count; $('#s-ports').textContent=s.exposed_port_count;
  $('#s-crit').textContent=s.crit_count; $('#s-cve').textContent=s.cve_count;
  $('#hostHdr').textContent='Public IPs — '+s.ip_count+' checked';
  renderHosts(d.hosts); renderDeltas(d.deltas); renderCves(d.hosts); renderChart(d.top_ports);
}
function renderHosts(hosts){
  const tb=$('#hosts');
  if(!hosts.length){ tb.innerHTML='<tr><td colspan="3" class="note">No data returned.</td></tr>'; return; }
  tb.innerHTML=hosts.map((h,i)=>{
    const chips=h.ports.map(p=>`<span class="chip sev-${p.severity}" title="${esc(p.reason)}">${p.port}</span>`).join('')||'<span class="sub">none exposed</span>';
    const tags=h.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join('');
    const cve=h.vulns.length?`<span class="cve-chip" title="known CVEs">${h.vulns.length} CVE</span>`:'';
    const det=[
      ...h.ports.map(p=>`<div class="pline sev-${p.severity}"><span class="dot d-${p.severity}"></span><span class="pn">${p.port}</span><span class="reason">${esc(p.reason)}</span></div>`),
      ...(h.cpes.length?[`<div class="meta">Detected: ${h.cpes.map(esc).join(', ')}</div>`]:[]),
      ...(h.vulns.length?[`<div class="meta">CVEs: ${h.vulns.map(esc).join(', ')}</div>`]:[]),
    ].join('')||'<div class="pline reason">Nothing exposed to the internet. Clean.</div>';
    return `<tr data-i="${i}">
      <td><span class="dot d-${h.max_severity}"></span><span class="ip">${esc(h.ip)}</span></td>
      <td>${h.hostnames.length?esc(h.hostnames[0]):'—'}${tags}<div class="sub">${cve}</div></td>
      <td><div class="chips">${chips}</div></td></tr>
      <tr class="detail" id="d-${i}"><td colspan="3"><div class="inner">${det}</div></td></tr>`;
  }).join('');
  tb.querySelectorAll('tr[data-i]').forEach(tr=>tr.addEventListener('click',()=>$('#d-'+tr.dataset.i).classList.toggle('open')));
}
function renderDeltas(d){
  const el=$('#deltas');
  if(d.baseline){ el.innerHTML='<div class="note">First check of this IP set — this becomes the baseline. Run it again later and changes show here.</div>'; return; }
  if(!d.items.length){ el.innerHTML='<div class="note">No changes since the previous check.</div>'; return; }
  el.innerHTML=d.items.map(it=>`<div class="delta ${it.severity}"><div class="bar"></div><div><div class="t">${esc(it.text)}</div><div class="k">${esc(it.kind)}</div></div></div>`).join('');
}
function renderCves(hosts){
  const el=$('#cves'); const rows=[];
  hosts.forEach(h=>h.vulns.forEach(c=>rows.push({c, ip:h.ip})));
  if(!rows.length){ el.innerHTML='<div class="note">No known CVEs reported for these IPs.</div>'; return; }
  el.innerHTML=rows.map(r=>`<div class="cve-row"><span class="c">${esc(r.c)}</span><span class="ip">${esc(r.ip)}</span></div>`).join('');
}
function renderChart(rows){
  const el=$('#chart');
  if(!rows||!rows.length){ el.innerHTML='<div class="note">No exposed ports to chart.</div>'; return; }
  const max=Math.max(...rows.map(r=>r.count));
  el.innerHTML=rows.map(r=>{const w=Math.round(r.count/max*100);
    return `<div class="bar-row"><span class="lbl">${r.port}</span><div class="track"><div class="fill sev-${r.severity}" style="width:${w}%"></div></div><span class="cnt">${r.count}</span></div>`;}).join('');
}
boot();
</script>
</body>
</html>
"""


def main():
    global DEMO, ALLOW_ACTIVE
    ap = argparse.ArgumentParser(description="ExtScope - external exposure checker")
    ap.add_argument("--demo", action="store_true", help="seed synthetic data, disable live lookups")
    ap.add_argument("--allow-active", action="store_true", help="enable active nmap source (run from a VPS)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8788)
    args = ap.parse_args()
    DEMO = args.demo
    ALLOW_ACTIVE = args.allow_active
    init_db()
    if DEMO:
        seed_demo()
        print("ExtScope running in DEMO mode (synthetic data, lookups disabled).")
    print(f"ExtScope -> http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()