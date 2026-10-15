#!/usr/bin/env python3
"""
HomeSOC Wazuh Alerts Log Parser
Parses Wazuh alerts.json, computes metrics, severity distributions,
and MITRE ATT&CK mappings.
"""

import argparse
import collections
import json
import os
import sys


def parse_alerts_file(file_path, min_level=0, rule_filter=None, mitre_filter=None, agent_filter=None):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Alerts log file not found at: {file_path}")

    alerts = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            rule = alert.get("rule", {})
            level = rule.get("level", 0)
            rule_id = str(rule.get("id", ""))
            agent = alert.get("agent", {})
            agent_name = agent.get("name", "manager")

            # Check MITRE IDs
            mitre_info = rule.get("mitre", {})
            mitre_ids = mitre_info.get("id", [])
            if isinstance(mitre_ids, str):
                mitre_ids = [mitre_ids]

            # Filters
            if level < min_level:
                continue
            if rule_filter and rule_id != str(rule_filter):
                continue
            if agent_filter and agent_filter.lower() not in agent_name.lower():
                continue
            if mitre_filter:
                match = any(mitre_filter.upper() in mid.upper() for mid in mitre_ids)
                if not match:
                    continue

            alerts.append(alert)

    return alerts


def generate_summary(alerts):
    total = len(alerts)
    level_counts = collections.Counter()
    rule_counts = collections.Counter()
    mitre_counts = collections.Counter()
    agent_counts = collections.Counter()

    for a in alerts:
        rule = a.get("rule", {})
        level = rule.get("level", 0)
        rule_desc = f"[{rule.get('id', 'N/A')}] {rule.get('description', 'Unknown')}"
        agent_name = a.get("agent", {}).get("name", "manager")

        level_counts[level] += 1
        rule_counts[rule_desc] += 1
        agent_counts[agent_name] += 1

        mitre_ids = rule.get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, str):
            mitre_ids = [mitre_ids]
        for mid in mitre_ids:
            mitre_counts[mid] += 1

    return {
        "total_alerts": total,
        "severity_distribution": dict(sorted(level_counts.items())),
        "top_rules": rule_counts.most_common(10),
        "top_mitre_techniques": mitre_counts.most_common(10),
        "agents": dict(agent_counts)
    }


def print_report(summary, alerts, show_details=False):
    print("=" * 70)
    print("                HomeSOC Wazuh Alerts Analysis Report")
    print("=" * 70)
    print(f"Total Filtered Alerts : {summary['total_alerts']}")
    print("-" * 70)

    print("\n[+] Severity Distribution (Level -> Count):")
    for lvl, count in sorted(summary['severity_distribution'].items()):
        bar = "█" * min(count, 40)
        print(f"  Level {lvl:2d} : {count:5d}  {bar}")

    print("\n[+] Top Triggered Rules:")
    for desc, count in summary['top_rules']:
        print(f"  {count:4d}x  {desc}")

    print("\n[+] Top MITRE ATT&CK Techniques:")
    if summary['top_mitre_techniques']:
        for mid, count in summary['top_mitre_techniques']:
            print(f"  {count:4d}x  {mid}")
    else:
        print("  None tagged in matched alerts")

    print("\n[+] Endpoint Breakdown:")
    for agent, count in summary['agents'].items():
        print(f"  {agent:25s} : {count:5d} alerts")

    if show_details and alerts:
        print("\n" + "=" * 70)
        print("                        Recent Alerts Log")
        print("=" * 70)
        for a in alerts[-15:]:
            ts = a.get("timestamp", "N/A")
            rule = a.get("rule", {})
            rid = rule.get("id", "N/A")
            lvl = rule.get("level", 0)
            desc = rule.get("description", "Unknown")
            agent = a.get("agent", {}).get("name", "manager")
            mitre = ",".join(rule.get("mitre", {}).get("id", [])) if rule.get("mitre") else "-"
            print(f"[{ts}] Lvl {lvl:2d} (Rule {rid:6s}) [{mitre:10s}] {agent}: {desc[:40]}")


def main():
    parser = argparse.ArgumentParser(description="HomeSOC Wazuh Alerts JSON Parser")
    parser.add_argument("--file", default="/var/ossec/logs/alerts/alerts.json", help="Path to alerts.json")
    parser.add_argument("--min-level", type=int, default=0, help="Minimum alert severity level")
    parser.add_argument("--rule", type=int, default=None, help="Filter by specific rule ID")
    parser.add_argument("--mitre", default=None, help="Filter by MITRE technique ID (e.g. T1059)")
    parser.add_argument("--agent", default=None, help="Filter by agent name")
    parser.add_argument("--details", action="store_true", help="Print recent alert entries")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")

    args = parser.parse_args()

    # Fallback to local sample or current directory if default path doesn't exist
    target_file = args.file
    if not os.path.exists(target_file):
        fallbacks = ["logs/alerts.json", "alerts.json", "logs/sample_alerts.json"]
        for fb in fallbacks:
            if os.path.exists(fb):
                target_file = fb
                break

    try:
        alerts = parse_alerts_file(
            target_file,
            min_level=args.min_level,
            rule_filter=args.rule,
            mitre_filter=args.mitre,
            agent_filter=args.agent
        )
    except FileNotFoundError:
        # If no alerts.json exists yet, create an empty demonstration structure
        alerts = []
        if not args.json:
            print(f"[-] Alerts file not found at '{args.file}'. Showing empty summary structure.")

    summary = generate_summary(alerts)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_report(summary, alerts, show_details=args.details)


if __name__ == "__main__":
    main()
