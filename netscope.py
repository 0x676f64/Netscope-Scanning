#!/usr/bin/env python3
"""
NetScope - self-contained internal network discovery + port dashboard.

One file. Runs nmap on a box on your network, stores results in SQLite,
and serves its own dashboard. Open it in a browser.

  Real scan mode:   python3 netscope.py
  Demo / preview:   python3 netscope.py --demo     (synthetic data, no nmap needed)

Then visit http://127.0.0.1:8787

Requires: Flask  (pip install flask)  and the `nmap` binary for real scans.
Only scan ranges and assets you own or are authorized to test.
"""

import argparse
import json
import os
import sqlite3
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from flask import Flask, request, jsonify, Response

DB_PATH = os.environ.get("NETSCOPE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "netscope.db"))
DEMO = False
_db_lock = threading.Lock()

app = Flask(__name__)

# --------------------------------------------------------------------------
# Risk model: which open ports are worth flagging, and why.
# Severity drives the colour coding in the dashboard.
# --------------------------------------------------------------------------
RISK_PORTS = {
    23:    ("critical", "Telnet - cleartext remote admin, no encryption"),
    3389:  ("high",     "RDP - top ransomware entry vector, never expose broadly"),
    445:   ("high",     "SMB - lateral movement / ransomware spread"),
    5900:  ("high",     "VNC - remote desktop, often weak or no auth"),
    21:    ("high",     "FTP - cleartext credentials"),
    6379:  ("high",     "Redis - frequently exposed with no auth"),
    27017: ("high",     "MongoDB - frequently exposed with no auth"),
    9200:  ("high",     "Elasticsearch - often unauthenticated"),
    139:   ("medium",   "NetBIOS - legacy SMB session service"),
    135:   ("medium",   "MSRPC - endpoint mapper, enumeration surface"),
    161:   ("medium",   "SNMP - often default community strings"),
    111:   ("medium",   "rpcbind - service enumeration"),
    1433:  ("medium",   "MSSQL - database exposed to network"),
    3306:  ("medium",   "MySQL - database exposed to network"),
    5432:  ("medium",   "PostgreSQL - database exposed to network"),
    22:    ("low",      "SSH - expected on servers; confirm it should be open here"),
    8080:  ("low",      "HTTP-alt - confirm intended service"),
    80:    ("info",     "HTTP"),
    443:   ("info",     "HTTPS"),
}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1}

SCAN_PROFILES = {
    # name -> (nmap args list, needs_root, human label)
    "quick":    (["-T4", "-F"],                          False, "Quick - top 100 ports"),
    "standard": ["-T4", "--top-ports", "1000", "-sV"],   # filled below
    "deep":     (["-T4", "-p-", "-sV", "-O"],            True,  "Deep - all ports + service/OS (needs root)"),
}
SCAN_PROFILES["standard"] = (["-T4", "--top-ports", "1000", "-sV"], False, "Standard - top 1000 ports + service versions")


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock, db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            profile TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            error TEXT,
            host_count INTEGER DEFAULT 0,
            open_port_count INTEGER DEFAULT 0,
            risk_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            mac TEXT,
            vendor TEXT,
            hostname TEXT,
            os_guess TEXT,
            state TEXT
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            severity TEXT,
            reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
        """)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------
def run_nmap(target, profile):
    """Run nmap, return parsed hosts. Raises on failure."""
    args, needs_root, _ = SCAN_PROFILES[profile]
    cmd = ["nmap"] + args + ["-oX", "-", target]
    # -sn is implied off; we want port data. Connect scan (-sT) is used
    # automatically when unprivileged, which is fine for an internal sweep.
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or "nmap failed")
    return parse_nmap_xml(proc.stdout)


def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        if h.find("status") is not None and h.find("status").get("state") == "down":
            continue
        ip = mac = vendor = hostname = os_guess = None
        for addr in h.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                ip = addr.get("addr")
            elif atype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        osmatch = h.find("os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name")
        ports = []
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = int(p.get("portid"))
            svc = p.find("service")
            service = svc.get("name") if svc is not None else None
            product = svc.get("product") if svc is not None else None
            version = svc.get("version") if svc is not None else None
            sev, reason = RISK_PORTS.get(portid, ("none", ""))
            ports.append({
                "port": portid, "protocol": p.get("protocol"), "state": "open",
                "service": service, "product": product, "version": version,
                "severity": sev, "reason": reason,
            })
        if ip:
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
                          "os_guess": os_guess, "state": "up", "ports": ports})
    return hosts


def persist(scan_id, hosts):
    open_ports = 0
    risks = 0
    with _db_lock, db() as conn:
        for host in hosts:
            conn.execute(
                "INSERT INTO hosts(scan_id,ip,mac,vendor,hostname,os_guess,state) VALUES (?,?,?,?,?,?,?)",
                (scan_id, host["ip"], host["mac"], host["vendor"], host["hostname"],
                 host["os_guess"], host["state"]))
            for p in host["ports"]:
                open_ports += 1
                if SEV_RANK.get(p["severity"], -1) >= SEV_RANK["medium"]:
                    risks += 1
                conn.execute(
                    "INSERT INTO ports(scan_id,ip,port,protocol,state,service,product,version,severity,reason)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, host["ip"], p["port"], p["protocol"], p["state"],
                     p["service"], p["product"], p["version"], p["severity"], p["reason"]))
        conn.execute(
            "UPDATE scans SET status='done', finished_at=?, host_count=?, open_port_count=?, risk_count=? WHERE id=?",
            (now_iso(), len(hosts), open_ports, risks, scan_id))


def scan_worker(scan_id, target, profile):
    try:
        hosts = run_nmap(target, profile)
        persist(scan_id, hosts)
    except Exception as e:  # noqa: BLE001
        with _db_lock, db() as conn:
            conn.execute("UPDATE scans SET status='error', finished_at=?, error=? WHERE id=?",
                         (now_iso(), str(e), scan_id))


def start_scan(target, profile):
    if profile not in SCAN_PROFILES:
        raise ValueError("unknown profile")
    with _db_lock, db() as conn:
        cur = conn.execute(
            "INSERT INTO scans(target,profile,started_at,status) VALUES (?,?,?,?)",
            (target, profile, now_iso(), "running"))
        scan_id = cur.lastrowid
    threading.Thread(target=scan_worker, args=(scan_id, target, profile), daemon=True).start()
    return scan_id


# --------------------------------------------------------------------------
# Deltas - the whole point: what changed since the previous scan of this target
# --------------------------------------------------------------------------
def previous_done_scan(conn, target, before_id):
    row = conn.execute(
        "SELECT * FROM scans WHERE target=? AND status='done' AND id<? ORDER BY id DESC LIMIT 1",
        (target, before_id)).fetchone()
    return row


def open_port_set(conn, scan_id):
    rows = conn.execute("SELECT ip,port,severity,service FROM ports WHERE scan_id=?", (scan_id,)).fetchall()
    return {(r["ip"], r["port"]): r for r in rows}


def host_set(conn, scan_id):
    rows = conn.execute("SELECT ip,hostname FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
    return {r["ip"]: r for r in rows}


def compute_deltas(conn, scan):
    prev = previous_done_scan(conn, scan["target"], scan["id"])
    if not prev:
        return {"baseline": True, "prev_scan_id": None, "items": []}
    items = []
    cur_hosts, prev_hosts = host_set(conn, scan["id"]), host_set(conn, prev["id"])
    for ip in cur_hosts.keys() - prev_hosts.keys():
        items.append({"kind": "host_new", "severity": "medium", "ip": ip,
                      "text": f"New device appeared: {ip}"})
    for ip in prev_hosts.keys() - cur_hosts.keys():
        items.append({"kind": "host_gone", "severity": "info", "ip": ip,
                      "text": f"Device no longer responding: {ip}"})
    cur_ports, prev_ports = open_port_set(conn, scan["id"]), open_port_set(conn, prev["id"])
    for key in cur_ports.keys() - prev_ports.keys():
        r = cur_ports[key]
        sev = r["severity"] if SEV_RANK.get(r["severity"], -1) >= SEV_RANK["low"] else "low"
        items.append({"kind": "port_open", "severity": sev, "ip": key[0], "port": key[1],
                      "text": f"New open port {key[1]} ({r['service'] or '?'}) on {key[0]}"})
    for key in prev_ports.keys() - cur_ports.keys():
        items.append({"kind": "port_closed", "severity": "info", "ip": key[0], "port": key[1],
                      "text": f"Port {key[1]} now closed on {key[0]}"})
    items.sort(key=lambda i: SEV_RANK.get(i["severity"], -1), reverse=True)
    return {"baseline": False, "prev_scan_id": prev["id"], "items": items}


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------
def scan_payload(conn, scan):
    hosts = []
    host_rows = conn.execute("SELECT * FROM hosts WHERE scan_id=? ORDER BY ip", (scan["id"],)).fetchall()
    for h in host_rows:
        prows = conn.execute(
            "SELECT * FROM ports WHERE scan_id=? AND ip=? ORDER BY port", (scan["id"], h["ip"])).fetchall()
        ports = [dict(p) for p in prows]
        max_sev = max((SEV_RANK.get(p["severity"], -1) for p in ports), default=-1)
        max_sev_name = next((k for k, v in SEV_RANK.items() if v == max_sev), "none")
        hosts.append({**dict(h), "ports": ports, "max_severity": max_sev_name})
    hosts.sort(key=lambda h: SEV_RANK.get(h["max_severity"], -1), reverse=True)

    # fleet-wide port frequency for the chart
    freq = {}
    for h in hosts:
        for p in h["ports"]:
            freq.setdefault(p["port"], {"port": p["port"], "service": p["service"],
                                        "severity": p["severity"], "count": 0})
            freq[p["port"]]["count"] += 1
    top_ports = sorted(freq.values(), key=lambda x: x["count"], reverse=True)[:12]

    return {
        "scan": dict(scan),
        "hosts": hosts,
        "top_ports": top_ports,
        "deltas": compute_deltas(conn, scan),
    }


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
@app.post("/api/scan")
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    profile = data.get("profile", "standard")
    if not target:
        return jsonify({"error": "target is required (e.g. 192.168.1.0/24)"}), 400
    if DEMO:
        return jsonify({"error": "Running in demo mode - live scanning is disabled. "
                                 "Restart without --demo to scan."}), 400
    try:
        scan_id = start_scan(target, profile)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"scan_id": scan_id})


@app.get("/api/scan/<int:scan_id>")
def api_scan_get(scan_id):
    with db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return jsonify({"error": "not found"}), 404
        if scan["status"] != "done":
            return jsonify({"scan": dict(scan)})
        return jsonify(scan_payload(conn, scan))


@app.get("/api/latest")
def api_latest():
    with db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE status='done' ORDER BY id DESC LIMIT 1").fetchone()
        if not scan:
            return jsonify({"empty": True})
        return jsonify(scan_payload(conn, scan))


@app.get("/api/scans")
def api_scans():
    with db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall()
        return jsonify({"scans": [dict(r) for r in rows], "demo": DEMO,
                        "profiles": {k: v[2] for k, v in SCAN_PROFILES.items()}})


@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# --------------------------------------------------------------------------
# Demo seed - two scans so the delta feed has something to show
# --------------------------------------------------------------------------
def seed_demo():
    with _db_lock, db() as conn:
        existing = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        if existing:
            return
    target = "192.168.10.0/24"
    scan1 = [
        {"ip": "192.168.10.1", "mac": "24:5A:4C:11:22:33", "vendor": "Ubiquiti", "hostname": "udm-pro",
         "os_guess": "Linux 4.x", "state": "up",
         "ports": [_p(80, "http"), _p(443, "https"), _p(22, "ssh")]},
        {"ip": "192.168.10.20", "mac": "B8:27:EB:AA:BB:CC", "vendor": "Dell", "hostname": "ws-accounting",
         "os_guess": "Windows 11", "state": "up",
         "ports": [_p(135, "msrpc"), _p(139, "netbios-ssn"), _p(445, "microsoft-ds")]},
        {"ip": "192.168.10.55", "mac": "00:11:32:44:55:66", "vendor": "Sharp", "hostname": "mx-3071",
         "os_guess": "embedded", "state": "up",
         "ports": [_p(80, "http"), _p(443, "https"), _p(515, "printer"), _p(9100, "jetdirect")]},
    ]
    scan2 = [
        {"ip": "192.168.10.1", "mac": "24:5A:4C:11:22:33", "vendor": "Ubiquiti", "hostname": "udm-pro",
         "os_guess": "Linux 4.x", "state": "up",
         "ports": [_p(80, "http"), _p(443, "https"), _p(22, "ssh")]},
        {"ip": "192.168.10.20", "mac": "B8:27:EB:AA:BB:CC", "vendor": "Dell", "hostname": "ws-accounting",
         "os_guess": "Windows 11", "state": "up",
         "ports": [_p(135, "msrpc"), _p(139, "netbios-ssn"), _p(445, "microsoft-ds"),
                   _p(3389, "ms-wbt-server")]},  # NEW risky port
        {"ip": "192.168.10.55", "mac": "00:11:32:44:55:66", "vendor": "Sharp", "hostname": "mx-3071",
         "os_guess": "embedded", "state": "up",
         "ports": [_p(80, "http"), _p(443, "https"), _p(515, "printer"), _p(9100, "jetdirect")]},
        {"ip": "192.168.10.77", "mac": "DC:A6:32:77:88:99", "vendor": "Raspberry Pi", "hostname": "unknown",
         "os_guess": "Linux", "state": "up",
         "ports": [_p(22, "ssh"), _p(23, "telnet")]},  # NEW device + critical port
    ]
    _seed_scan(target, "standard", scan1, minutes_ago=180)
    _seed_scan(target, "standard", scan2, minutes_ago=5)


def _p(port, service):
    sev, reason = RISK_PORTS.get(port, ("none", ""))
    return {"port": port, "protocol": "tcp", "state": "open", "service": service,
            "product": None, "version": None, "severity": sev, "reason": reason}


def _seed_scan(target, profile, hosts, minutes_ago):
    ts = now_iso()
    with _db_lock, db() as conn:
        cur = conn.execute(
            "INSERT INTO scans(target,profile,started_at,status) VALUES (?,?,?,?)",
            (target, profile, ts, "running"))
        sid = cur.lastrowid
    persist(sid, hosts)


# Build the dashboard HTML (no f-string: keep CSS/JS braces literal)
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScope</title>
<style>
  :root{
    --bg:#0a1424; --bg2:#0d1b30; --panel:#12233e; --panel2:#16294a;
    --line:#1f3a5f; --line2:#274a78;
    --ink:#e8eef7; --muted:#8aa0c0; --faint:#5d769a;
    --accent:#3b82f6;
    --crit:#ff3b5c; --high:#ff6b4a; --med:#f5a623; --low:#5db0ff; --info:#4a6b94; --ok:#33c27f;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased}
  a{color:var(--accent)}
  .wrap{max-width:1240px;margin:0 auto;padding:20px 22px 60px}

  /* Header */
  header{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;
    border-bottom:1px solid var(--line);padding-bottom:16px;flex-wrap:wrap}
  .brand{display:flex;align-items:baseline;gap:12px}
  .brand h1{font-size:20px;letter-spacing:.14em;margin:0;font-weight:700;text-transform:uppercase}
  .brand .v{font-family:var(--mono);font-size:11px;color:var(--faint)}
  .demo-tag{font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--med);
    border:1px solid var(--med);border-radius:3px;padding:2px 7px;text-transform:uppercase}
  .controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  input,select,button{font-family:var(--mono);font-size:13px;border-radius:5px;border:1px solid var(--line2);
    background:var(--panel);color:var(--ink);padding:8px 11px;outline:none}
  input{min-width:190px}
  input:focus,select:focus{border-color:var(--accent)}
  button{background:var(--accent);border-color:var(--accent);color:#fff;cursor:pointer;font-weight:600;
    letter-spacing:.02em}
  button:hover{filter:brightness(1.1)}
  button:disabled{opacity:.5;cursor:default}

  /* Stat strip */
  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
  .stat .n{font-family:var(--mono);font-size:26px;font-weight:700;line-height:1}
  .stat .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:7px}
  .stat.risk .n{color:var(--high)}

  .grid{display:grid;grid-template-columns:1fr 360px;gap:18px}
  @media(max-width:920px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
  .card>h2{font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);
    margin:0;padding:13px 16px;border-bottom:1px solid var(--line);font-weight:600}

  /* Host table */
  table{width:100%;border-collapse:collapse;font-size:13px}
  thead th{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);
    text-align:left;padding:9px 16px;border-bottom:1px solid var(--line);font-weight:600}
  tbody tr{border-bottom:1px solid var(--bg2);cursor:pointer}
  tbody tr:hover{background:var(--panel2)}
  td{padding:11px 16px;vertical-align:top}
  .ip{font-family:var(--mono);font-weight:600}
  .sub{color:var(--faint);font-family:var(--mono);font-size:11px}
  .chips{display:flex;flex-wrap:wrap;gap:5px}
  .chip{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:4px;
    border:1px solid var(--line2);background:var(--bg2);color:var(--muted)}
  .chip.sev-critical{border-color:var(--crit);color:var(--crit)}
  .chip.sev-high{border-color:var(--high);color:var(--high)}
  .chip.sev-medium{border-color:var(--med);color:var(--med)}
  .chip.sev-low{border-color:var(--low);color:var(--low)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;vertical-align:middle}
  .sev-critical .dot,.d-critical{background:var(--crit)}
  .sev-high .dot,.d-high{background:var(--high)}
  .sev-medium .dot,.d-medium{background:var(--med)}
  .sev-low .dot,.d-low{background:var(--low)}
  .sev-none .dot,.sev-info .dot,.d-info{background:var(--info)}
  .detail{display:none;background:var(--bg2)}
  .detail.open{display:table-row}
  .detail td{padding:0}
  .detail .inner{padding:12px 16px}
  .pline{font-family:var(--mono);font-size:12px;padding:6px 0;border-bottom:1px solid var(--panel);
    display:flex;gap:14px;align-items:baseline}
  .pline:last-child{border-bottom:0}
  .pline .pn{width:64px;font-weight:700}
  .pline .reason{color:var(--faint)}

  /* Delta feed - the signature element */
  .delta-card{border-color:var(--line2)}
  .delta-list{max-height:340px;overflow:auto}
  .delta{display:flex;gap:11px;align-items:flex-start;padding:11px 16px;border-bottom:1px solid var(--bg2)}
  .delta:last-child{border-bottom:0}
  .delta .bar{width:3px;align-self:stretch;border-radius:2px;flex:0 0 auto}
  .delta.critical .bar{background:var(--crit)} .delta.high .bar{background:var(--high)}
  .delta.medium .bar{background:var(--med)} .delta.low .bar{background:var(--low)}
  .delta.info .bar{background:var(--info)}
  .delta .t{font-size:13px;line-height:1.4}
  .delta .k{font-family:var(--mono);font-size:10px;color:var(--faint);text-transform:uppercase;
    letter-spacing:.06em;margin-top:3px}
  .baseline-note,.empty-note{padding:22px 16px;color:var(--muted);font-size:13px;line-height:1.5}

  /* Chart */
  .bar-row{display:flex;align-items:center;gap:10px;padding:6px 16px;font-family:var(--mono);font-size:12px}
  .bar-row .lbl{width:108px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .bar-row .track{flex:1;background:var(--bg2);border-radius:3px;height:14px;overflow:hidden}
  .bar-row .fill{height:100%;border-radius:3px;background:var(--accent)}
  .bar-row .fill.sev-critical{background:var(--crit)} .bar-row .fill.sev-high{background:var(--high)}
  .bar-row .fill.sev-medium{background:var(--med)} .bar-row .fill.sev-low{background:var(--low)}
  .bar-row .cnt{width:24px;text-align:right;color:var(--ink)}

  .status{font-family:var(--mono);font-size:12px;color:var(--muted);margin:14px 0;min-height:16px}
  .status.err{color:var(--high)}
  .foot{color:var(--faint);font-size:11px;margin-top:28px;line-height:1.6;border-top:1px solid var(--line);padding-top:14px}
  .spin{display:inline-block;width:12px;height:12px;border:2px solid var(--line2);
    border-top-color:var(--accent);border-radius:50%;animation:s .7s linear infinite;vertical-align:-1px;margin-right:7px}
  @keyframes s{to{transform:rotate(360deg)}}
  @media(prefers-reduced-motion:reduce){.spin{animation:none}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <h1>NetScope</h1><span class="v">v1 · internal discovery</span>
      <span id="demoTag" class="demo-tag" style="display:none">demo data</span>
    </div>
    <div class="controls">
      <input id="target" placeholder="192.168.1.0/24" />
      <select id="profile"></select>
      <button id="run">Run scan</button>
    </div>
  </header>

  <div id="status" class="status"></div>

  <div class="stats">
    <div class="stat"><div class="n" id="s-hosts">—</div><div class="l">Devices up</div></div>
    <div class="stat"><div class="n" id="s-ports">—</div><div class="l">Open ports</div></div>
    <div class="stat risk"><div class="n" id="s-risks">—</div><div class="l">Risk findings</div></div>
    <div class="stat"><div class="n" id="s-changes">—</div><div class="l">Changes since last</div></div>
  </div>

  <div class="grid">
    <div class="card">
      <h2 id="hostHdr">Devices</h2>
      <table>
        <thead><tr><th>Host</th><th>Identity</th><th>Open ports</th></tr></thead>
        <tbody id="hosts"></tbody>
      </table>
    </div>

    <div style="display:flex;flex-direction:column;gap:18px">
      <div class="card delta-card">
        <h2>Changes since last scan</h2>
        <div id="deltas" class="delta-list"></div>
      </div>
      <div class="card">
        <h2>Most common open ports</h2>
        <div id="chart" style="padding:10px 0"></div>
      </div>
    </div>
  </div>

  <div class="foot">
    NetScope runs nmap on this host and stores results locally in SQLite. The value over a one-shot
    scanner is history: each run is diffed against the previous scan of the same target, so new devices
    and newly opened ports surface on their own. Only scan ranges and assets you own or are authorized to test.
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const SEV = {critical:4,high:3,medium:2,low:1,info:0,none:-1};
let pollTimer = null;

function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

async function boot(){
  const meta = await (await fetch('/api/scans')).json();
  const sel = $('#profile');
  sel.innerHTML = Object.entries(meta.profiles).map(([k,v])=>`<option value="${k}">${esc(v)}</option>`).join('');
  sel.value = 'standard';
  if(meta.demo){ $('#demoTag').style.display='inline-block'; $('#run').disabled=true; $('#target').disabled=true; }
  loadLatest();
}

async function loadLatest(){
  const data = await (await fetch('/api/latest')).json();
  if(data.empty){
    $('#status').textContent = 'No scans yet. Enter a target range and run your first scan.';
    return;
  }
  render(data);
}

$('#run').addEventListener('click', async ()=>{
  const target = $('#target').value.trim();
  if(!target){ setStatus('Enter a target, e.g. 192.168.1.0/24', true); return; }
  $('#run').disabled = true;
  setStatus('<span class="spin"></span>Starting scan of '+esc(target)+' …');
  const res = await fetch('/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target, profile: $('#profile').value})});
  const j = await res.json();
  if(j.error){ setStatus(j.error, true); $('#run').disabled=false; return; }
  poll(j.scan_id);
});

function poll(id){
  clearInterval(pollTimer);
  pollTimer = setInterval(async ()=>{
    const data = await (await fetch('/api/scan/'+id)).json();
    const st = data.scan.status;
    if(st === 'running'){ setStatus('<span class="spin"></span>Scanning '+esc(data.scan.target)+' — nmap working …'); return; }
    clearInterval(pollTimer);
    $('#run').disabled = false;
    if(st === 'error'){ setStatus('Scan failed: '+esc(data.scan.error), true); return; }
    render(data);
  }, 1500);
}

function setStatus(html, err){ const s=$('#status'); s.innerHTML=html; s.className='status'+(err?' err':''); }

function render(data){
  const scan = data.scan;
  const when = new Date(scan.finished_at || scan.started_at).toLocaleString();
  setStatus('Last scan: '+esc(scan.target)+' · '+esc(scan.profile)+' · '+when);
  $('#s-hosts').textContent = scan.host_count;
  $('#s-ports').textContent = scan.open_port_count;
  $('#s-risks').textContent = scan.risk_count;
  $('#s-changes').textContent = data.deltas.baseline ? '—' : data.deltas.items.length;
  $('#hostHdr').textContent = 'Devices — ' + scan.host_count + ' up';
  renderHosts(data.hosts);
  renderDeltas(data.deltas);
  renderChart(data.top_ports);
}

function renderHosts(hosts){
  const tb = $('#hosts');
  if(!hosts.length){ tb.innerHTML='<tr><td colspan="3" class="baseline-note">No live hosts found.</td></tr>'; return; }
  tb.innerHTML = hosts.map((h,i)=>{
    const ports = h.ports.map(p=>`<span class="chip sev-${p.severity}" title="${esc(p.reason||p.service||'')}">${p.port}${p.service?'/'+esc(p.service):''}</span>`).join('');
    const detail = h.ports.map(p=>`<div class="pline sev-${p.severity}"><span class="dot"></span><span class="pn">${p.port}</span><span>${esc(p.service||'?')}${p.product?' · '+esc(p.product):''}${p.version?' '+esc(p.version):''}</span><span class="reason">${esc(p.reason||'')}</span></div>`).join('') || '<div class="pline reason">No open ports.</div>';
    return `<tr data-i="${i}">
        <td><span class="dot d-${h.max_severity==='none'?'info':h.max_severity}"></span><span class="ip">${esc(h.ip)}</span></td>
        <td>${esc(h.hostname||'—')}<div class="sub">${esc(h.vendor||'')}${h.os_guess?' · '+esc(h.os_guess):''}</div></td>
        <td><div class="chips">${ports||'<span class="sub">none</span>'}</div></td>
      </tr>
      <tr class="detail" id="d-${i}"><td colspan="3"><div class="inner">${detail}</div></td></tr>`;
  }).join('');
  tb.querySelectorAll('tr[data-i]').forEach(tr=>tr.addEventListener('click',()=>{
    $('#d-'+tr.dataset.i).classList.toggle('open');
  }));
}

function renderDeltas(d){
  const el = $('#deltas');
  if(d.baseline){ el.innerHTML='<div class="baseline-note">First scan of this target — this run becomes the baseline. Run it again later and changes will show up here.</div>'; return; }
  if(!d.items.length){ el.innerHTML='<div class="baseline-note">No changes since the previous scan of this target.</div>'; return; }
  el.innerHTML = d.items.map(it=>`<div class="delta ${it.severity}"><div class="bar"></div><div><div class="t">${esc(it.text)}</div><div class="k">${esc(it.kind.replace('_',' '))}</div></div></div>`).join('');
}

function renderChart(rows){
  const el = $('#chart');
  if(!rows||!rows.length){ el.innerHTML='<div class="baseline-note">No open ports to chart.</div>'; return; }
  const max = Math.max(...rows.map(r=>r.count));
  el.innerHTML = rows.map(r=>{
    const w = Math.round(r.count/max*100);
    return `<div class="bar-row"><span class="lbl">${r.port}${r.service?' '+esc(r.service):''}</span><div class="track"><div class="fill sev-${r.severity}" style="width:${w}%"></div></div><span class="cnt">${r.count}</span></div>`;
  }).join('');
}

boot();
</script>
</body>
</html>
"""


def main():
    global DEMO
    ap = argparse.ArgumentParser(description="NetScope - internal network discovery + port dashboard")
    ap.add_argument("--demo", action="store_true", help="seed synthetic data, disable live scanning")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    DEMO = args.demo
    init_db()
    if DEMO:
        seed_demo()
        print("NetScope running in DEMO mode (synthetic data, scanning disabled).")
    print(f"NetScope -> http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()