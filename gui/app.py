#!/usr/bin/env python3
"""
HomeSOC Wazuh Lab - Minimal Dashboard GUI
Serves a clean, low-color web UI for the Wazuh lab.
"""

import json
import os
import subprocess
from collections import Counter
from datetime import datetime

from flask import Flask, jsonify, render_template

app = Flask(__name__)


def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return result.stdout.strip(), result.returncode
    except Exception:
        return "", 1


def get_container_status():
    containers = ["wazuh.manager", "wazuh.indexer", "wazuh.dashboard", "wazuh.agent.ubuntu"]
    status = {}
    for name in containers:
        out, rc = run_cmd(["docker", "inspect", "--format", "{{.State.Status}}", name])
        status[name] = out if rc == 0 else "not found"
    return status


def get_manager_services():
    out, rc = run_cmd([
        "docker", "exec", "wazuh.manager",
        "/var/ossec/bin/wazuh-control", "status"
    ])
    services = {}
    if rc == 0:
        for line in out.splitlines():
            if "is running" in line or "not running" in line:
                parts = line.replace("is running", "").replace("not running", "").strip().rsplit("...", 1)
                if len(parts) == 2:
                    svc = parts[0].strip()
                    state = "running" if "is running" in line else "stopped"
                    services[svc] = state
    return services


def get_alerts(limit=500):
    out, rc = run_cmd([
        "docker", "exec", "wazuh.manager",
        "cat", "/var/ossec/logs/alerts/alerts.json"
    ])
    if rc != 0:
        return []
    alerts = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts[-limit:]


def summarize(alerts):
    total = len(alerts)
    severity = Counter()
    rules = Counter()
    mitre = Counter()
    agents = Counter()

    for a in alerts:
        rule = a.get("rule", {})
        level = rule.get("level", 0)
        rid = rule.get("id", "N/A")
        desc = rule.get("description", "Unknown")
        agent = a.get("agent", {}).get("name", "manager")

        severity[level] += 1
        rules[f"[{rid}] {desc}"] += 1
        agents[agent] += 1

        mitre_ids = rule.get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, str):
            mitre_ids = [mitre_ids]
        for mid in mitre_ids:
            mitre[mid] += 1

    recent = []
    for a in alerts[-20:]:
        rule = a.get("rule", {})
        recent.append({
            "timestamp": a.get("timestamp", "N/A"),
            "level": rule.get("level", 0),
            "rule_id": rule.get("id", "N/A"),
            "description": rule.get("description", "Unknown"),
            "agent": a.get("agent", {}).get("name", "manager"),
            "mitre": rule.get("mitre", {}).get("id", []),
        })

    return {
        "total": total,
        "severity": dict(sorted(severity.items())),
        "top_rules": rules.most_common(10),
        "top_mitre": mitre.most_common(10),
        "agents": dict(agents),
        "recent": list(reversed(recent)),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify({
        "containers": get_container_status(),
        "services": get_manager_services(),
        "generated_at": datetime.now().isoformat(),
    })


@app.route("/api/alerts")
def api_alerts():
    alerts = get_alerts(limit=500)
    return jsonify(summarize(alerts))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
