# HomeSOC-Wazuh: Home Security Operations Center Lab

A beginner-friendly Security Operations Center (SOC) lab built on **Wazuh 4.11.2** SIEM/XDR, running on Ubuntu with Docker. Designed for hands-on practice in **log analysis**, **detection engineering**, **incident triage**, and **MITRE ATT&CK® mapping**.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Host["Host Environment (Ubuntu / Docker)"]
        subgraph WazuhStack["Wazuh Core SIEM Stack"]
            Manager["Wazuh Manager 4.11.2\n• Decoders & Rules\n• Analysis Engine\n• Ports: 1514, 1515, 514, 55000"]
            Indexer["Wazuh Indexer 4.11.2\n• OpenSearch-based\n• Port: 9200"]
            Dashboard["Wazuh Dashboard 4.11.2\n• Web UI & Visualizations\n• Port: 443 (HTTPS)"]
            Manager -->|Filebeat (TLS)| Indexer
            Dashboard -->|REST (TLS)| Indexer
            Dashboard -->|API (HTTPS)| Manager
        end

        subgraph LinuxEndpoint["Linux Endpoint"]
            UbuntuAgent["Ubuntu Agent Container\n• wazuh-agent 4.11.2\n• FIM: /monitored\n• SCA Baseline"]
            UbuntuAgent -->|Agent Protocol: 1514/1515| Manager
        end

        subgraph WindowsSimulation["Windows Endpoint Simulation"]
            WinSim["Python Windows Simulator\n• Sysmon Process Creation (T1059)\n• Scheduled Tasks (T1053)\n• Privileged Logon (T1078)\n• LSASS Memory Dump (T1003)"]
            WinSim -->|JSON / Syslog (514)| Manager
        end

        subgraph Automation["SOC Automation & Testing"]
            LogGen["scripts/log_generator.py\n(Synthetic Log Replay)"]
            LogParser["scripts/log_parser.py\n(Alerts Parser)"]
            TestAlerts["scripts/test_alerts.py\n(E2E Alert Verification)"]
            AlertDash["scripts/alert_dashboard.py\n(CLI Live Dashboard)"]
            TestAlerts -->|API (55000)| Manager
            AlertDash -->|API (55000)| Manager
        end
    end
```

---

## Repository Layout

```text
HomeSOC-Wazuh/
├── .env.example                 # Template for stack environment variables
├── .gitignore                   # Ignores sensitive certificates, keys, and runtime artifacts
├── AGY_TASK.md                  # Project task specification
├── Dockerfile.ubuntu-agent      # Ubuntu endpoint agent container definition
├── README.md                    # Main documentation & lab guide
├── SETUP_NOTES.md               # Host-specific fixes & operational notes
├── docker-compose.yml           # Core Wazuh stack (Manager, Indexer, Dashboard)
├── docker-compose.agents.yml    # Endpoint agent stack
├── requirements.txt             # Python automation dependencies
├── config/
│   ├── agent/                   # Agent configuration & SCA policies
│   ├── certs.yml                # Certificate generator configuration
│   ├── wazuh_cluster/           # Manager configuration
│   ├── wazuh_dashboard/         # Dashboard configuration
│   ├── wazuh_decoders/          # Custom Wazuh decoders for simulated events
│   ├── wazuh_indexer/           # Indexer configuration
│   └── wazuh_rules/             # Custom detection rules with MITRE mappings
├── docs/
│   ├── architecture.md          # In-depth architectural details
│   ├── mitre_mapping.csv        # Comprehensive MITRE ATT&CK mapping table
│   └── runbook.md               # SOC incident triage and investigation runbook
├── scripts/
│   ├── alert_dashboard.py       # Terminal dashboard querying Wazuh API
│   ├── entrypoint-agent.sh      # Agent container startup and auto-enrollment
│   ├── log_generator.py         # Synthetic log generator for auth/sysmon/fim
│   ├── log_parser.py            # Parser for Wazuh alerts.json
│   ├── test_alerts.py           # Automated test harness verifying rule alerts
│   └── windows_event_simulator.py # Windows Security & Sysmon event simulator
├── secrets/
│   ├── .gitkeep                 # Preserves directory in git
│   └── credentials.md.template  # Template for local credential tracking
└── tests/
    └── test_scripts_syntax.py   # Automated syntax & validation tests
```

---

## Lab Credentials & Access

> [!NOTE]
> The single-node Wazuh stack ships with default lab credentials for initial setup. For a production deployment, customize passwords in `.env` and `config/wazuh_indexer/internal_users.yml`.

| Service | Endpoint | Username | Default Password | Purpose |
|---|---|---|---|---|
| **Wazuh Dashboard** | `https://localhost:443` | `admin` | `SecretPassword` | Primary SOC Analyst Web UI |
| **Wazuh Indexer** | `https://localhost:9200` | `admin` | `SecretPassword` | Elasticsearch/OpenSearch indexing |
| **Wazuh API** | `https://localhost:55000` | `wazuh-wui` | `MyS3cr37P450r.*-` | Python automation & Dashboard API |
| **Indexer Internal** | `Internal` | `kibanaserver` | `kibanaserver` | Dashboard internal authentication |

---

## MITRE ATT&CK® Mapping Matrix

| Rule ID | Technique Name | MITRE ID | Tactic | Description |
|---|---|---|---|---|
| `100100` | Generic Windows Simulation | — | Execution / Discovery | Ingestion base rule for simulated Windows logs |
| `100101` | PowerShell / Command-Line Interface | `T1059.001` | Execution | Encoded PowerShell / suspicious CLI execution detected |
| `100102` | Scheduled Task / Job | `T1053.005` | Persistence / Privilege Escalation | Malicious persistence created via `schtasks` |
| `100103` | Valid Accounts / Admin Logon | `T1078` | Initial Access / Defense Evasion | Anomalous privileged account logon (Type 10 Remote) |
| `100104` | OS Credential Dumping: LSASS Memory | `T1003.001` | Credential Access | Suspicious process reading `lsass.exe` memory |
| `100105` | System Information Discovery | `T1082` | Discovery | Reconnaissance commands (`systeminfo`, `whoami /all`) |
| `100110` | File Integrity Monitoring (FIM) Alert | `T1565.001` | Impact / Defense Evasion | Unauthorized modification to `/monitored` or `/etc` |

A full CSV table is maintained at [`docs/mitre_mapping.csv`](file:///home/honeysh/Projects/HomeSOC-Wazuh/docs/mitre_mapping.csv).

---

## Quickstart Guide

### 1. Host Requirements & Prerequisites
Ensure kernel memory limits are set for Wazuh Indexer (OpenSearch):
```bash
sudo sysctl -w vm.max_map_count=262144
```
Ensure Docker and Docker Compose (v2.20+) are installed.

### 2. Generate TLS Certificates
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 3. Start Wazuh SIEM Stack
```bash
docker compose up -d
docker compose ps
```
Wait ~60 seconds for OpenSearch indices to initialize, then navigate to `https://localhost:443`. Accept the self-signed TLS certificate and log in with `admin` / `SecretPassword`.

### 4. Deploy Ubuntu Endpoint Agent
```bash
docker compose -f docker-compose.agents.yml up -d
```
Verify the agent is connected:
```bash
docker exec -it wazuh.manager /var/ossec/bin/agent_control -l
```

### 5. Run Windows Event Simulator
```bash
python3 scripts/windows_event_simulator.py --count 10 --technique T1059 --output syslog
```

### 6. Run Test Automation & CLI Dashboard
```bash
pip install -r requirements.txt
python3 scripts/test_alerts.py
python3 scripts/alert_dashboard.py
```

---

## Next Steps (Phases 2 & 3)
1. Integrate Suricata IDS for network-based anomaly detection.
2. Deploy Shuffle SOAR for automated incident playbooks and containment.
3. Attach a dedicated Windows 11 Enterprise evaluation VM with real Sysmon & Splunk forwarder.
