#!/usr/bin/env python3
"""
HomeSOC CLI Alert Dashboard
Queries Wazuh API or alerts log and displays a terminal dashboard
highlighting recent alerts, MITRE techniques, severity levels, and agents.
"""

import argparse
import datetime
import json
import os
import sys
import time

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None


# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def color_level(level):
    if level >= 12:
        return f"{RED}{BOLD}{level:2d}{RESET}"
    elif level >= 8:
        return f"{YELLOW}{BOLD}{level:2d}{RESET}"
    elif level >= 4:
        return f"{CYAN}{level:2d}{RESET}"
    else:
        return f"{GREEN}{level:2d}{RESET}"


def fetch_from_api(api_url, user, password, limit=10):
    if not requests:
        return None
    try:
        auth_resp = requests.post(
            f"{api_url.rstrip('/')}/security/user/authenticate",
            auth=(user, password),
            verify=False,
            timeout=3
        )
        if auth_resp.status_code != 200:
            return None
        token = auth_resp.json().get("data", {}).get("token")
        headers = {"Authorization": f"Bearer {token}"}
        alerts_resp = requests.get(
            f"{api_url.rstrip('/')}/alerts",
            headers=headers,
            params={"limit": limit, "sort": "-timestamp"},
            verify=False,
            timeout=3
        )
        if alerts_resp.status_code == 200:
            return alerts_resp.json().get("data", {}).get("affected_items", [])
    except Exception:
        return None
    return None


def fetch_from_file(file_path, limit=10):
    if not os.path.exists(file_path):
        return []
    alerts = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts[-limit:]


def render_dashboard(alerts, source_desc):
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\033[2J\033[H", end="")  # Clear screen and move cursor to home
    print(f"{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                     HOMESOC WAZUH SIEM LIVE DASHBOARD                                ║{RESET}")
    print(f"{BOLD}{CYAN}║ Source: {source_desc:25s}   Updated: {now_str:20s}             ║{RESET}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"{BOLD}{'LVL':<5} {'RULE ID':<9} {'MITRE':<12} {'AGENT':<20} {'DESCRIPTION':<38}{RESET}")
    print("=" * 86)

    if not alerts:
        print(f"{YELLOW}No recent alerts found. Waiting for events...{RESET}")
        return

    for a in alerts:
        rule = a.get("rule", {})
        lvl = rule.get("level", 0)
        rid = str(rule.get("id", "N/A"))
        desc = rule.get("description", "Unknown")[:37]
        agent_name = a.get("agent", {}).get("name", "manager")[:19]

        mitre_ids = rule.get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, str):
            mitre_str = mitre_ids
        elif mitre_ids:
            mitre_str = mitre_ids[0]
        else:
            mitre_str = "-"

        colored_lvl = color_level(lvl)
        print(f"{colored_lvl:<14} {rid:<9} {MAGENTA}{mitre_str:<12}{RESET} {agent_name:<20} {desc:<38}")

    print("-" * 86)
    print(f"Total Visible Alerts: {len(alerts)}")


def main():
    parser = argparse.ArgumentParser(description="HomeSOC CLI Alert Dashboard")
    parser.add_argument("--api-url", default=os.getenv("WAZUH_API_URL", "https://localhost:55000"), help="Wazuh API endpoint")
    parser.add_argument("--api-user", default=os.getenv("API_USERNAME", "wazuh-wui"), help="API user")
    parser.add_argument("--api-password", default=os.getenv("API_PASSWORD", "MyS3cr37P450r.*-"), help="API password")
    parser.add_argument("--file", default="logs/alerts.json", help="Local fallback alerts log file")
    parser.add_argument("--limit", type=int, default=15, help="Number of recent alerts to display")
    parser.add_argument("--watch", action="store_true", help="Continuously poll and refresh dashboard")
    parser.add_argument("--interval", type=int, default=3, help="Polling interval in seconds")

    args = parser.parse_args()

    while True:
        alerts = fetch_from_api(args.api_url, args.api_user, args.api_password, limit=args.limit)
        source_desc = "Wazuh REST API"

        if alerts is None:
            alerts = fetch_from_file(args.file, limit=args.limit)
            source_desc = f"File: {args.file}"

        render_dashboard(alerts, source_desc)

        if not args.watch:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
