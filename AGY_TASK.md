# Home SOC using Wazuh — Phase 1 (Weeks 1–4)

Project root: `/home/honeysh/Projects/HomeSOC-Wazuh`

## Context

We are building a beginner-friendly Security Operations Center (SOC) lab using Wazuh 4.11.2 as the SIEM/XDR platform. The lab runs on an Ubuntu 26.04 host with Docker. Core learning outcomes: log analysis, detection engineering, incident triage, MITRE ATT&CK mapping.

- **Wazuh server + dashboard**: deployed via official Wazuh Docker single-node stack (`wazuh-docker` repo, tag `v4.11.2`).
- **Linux endpoint**: an Ubuntu Docker agent container enrolled to the Wazuh manager.
- **Windows endpoint**: simulated via Python log/event generators that emit EVTX-like JSON/sysmon-style events forwarded to Wazuh. A real Windows VM will be added later if the user supplies an ISO/license.
- **Detection engineering**: custom Wazuh rules, decoders, active response, and MITRE mapping.
- **Automation**: Python scripts for log generation, parsing, test execution, and alert verification.

## Goals

### Goal 1 — Project scaffold and documentation
Create a clean repository structure and a README that explains the lab architecture, setup steps, credentials, and URLs.

Expected files:
- `README.md` (architecture diagram in Mermaid, setup, credentials, MITRE mapping table, next steps)
- `.gitignore`
- `docs/`
- `configs/`
- `scripts/`
- `detections/`
- `tests/`

Acceptance: `tree -L 2` shows the layout and README renders without broken Mermaid.

### Goal 2 — Docker-based Wazuh stack
Use the official `wazuh/wazuh-docker` repository at tag `v4.11.2`. Configure the single-node deployment with persistent volumes and sensible resource limits. Provide a `docker-compose.yml` (or a wrapper script that generates it) plus an `.env` template.

Acceptance:
- `docker compose up -d` brings up `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`.
- `docker compose ps` shows all containers healthy.
- Dashboard reachable at `https://localhost:443` or the host IP with self-signed TLS.
- Default admin credentials are documented in `README.md` and `secrets/credentials.md`.

### Goal 3 — Ubuntu endpoint agent
Provide a containerized Ubuntu agent (`Dockerfile.ubuntu-agent`) that auto-enrolls to the manager using the manager IP and an enrollment key. Provide a `docker-compose.agents.yml` for the agent(s). Add a FIM (file integrity monitoring) rule set and SCA (security configuration assessment) policy stub.

Acceptance:
- Agent container starts and registers with the Wazuh manager.
- `docker exec -it wazuh.manager /var/ossec/bin/agent_control -l` shows the agent as active.
- Agent triggers a test FIM alert when a watched file changes.

### Goal 4 — Windows endpoint simulation
Build a Python-based Windows event simulator (`scripts/windows_event_simulator.py`) that writes Sysmon-like / Windows Security log events in JSON or syslog format. Provide a Wazuh localfile/integration that ingests these simulated events.

Acceptance:
- Running the simulator produces events that show up in the Wazuh archives/alerts.
- At least 3 MITRE techniques are represented (e.g., T1059 Command-Line Interface, T1053 Scheduled Task, T1078 Valid Accounts).

### Goal 5 — Custom rules, decoders, and MITRE mapping
Create custom Wazuh rules in `detections/custom_rules.xml` and decoders in `configs/decoders/custom_decoders.xml`. Map detections to MITRE ATT&CK techniques. Provide a CSV mapping table.

Acceptance:
- Custom rules load without syntax errors (`/var/ossec/bin/wazuh-logtest` validates a sample).
- Alerts fire for the Linux FIM test and Windows simulated events.
- `docs/mitre_mapping.csv` lists rule ID, description, MITRE ID, tactic, technique.

### Goal 6 — Python log analysis and test automation
Create:
- `scripts/log_generator.py` — generates synthetic auth/sysmon/fim logs for replay.
- `scripts/log_parser.py` — parses Wazuh alerts.json and prints a summary.
- `scripts/test_alerts.py` — triggers test events and asserts that corresponding alerts appear via the Wazuh API.
- `scripts/alert_dashboard.py` — simple CLI dashboard that queries the Wazuh API and prints recent alerts (MITRE, level, agent).

Acceptance:
- All scripts run with only Python stdlib plus `requests` (provide `requirements.txt`).
- `python3 scripts/test_alerts.py` returns exit code 0 after the stack is up and test events are injected.

### Goal 7 — Git hygiene and commit
Stage, commit, and push the work to a GitHub repository. Use descriptive commits. Do not commit secrets. Provide a `SETUP_NOTES.md` with any host-specific fixes discovered.

Acceptance:
- `git log --oneline` shows clear commits.
- Repository exists on GitHub under the user's account.
- No passwords/API tokens in committed files.

## Rules

- Do NOT install Wazuh server packages directly on the host; use Docker.
- Do NOT require Windows if an ISO is unavailable; simulate with Python.
- Keep secrets (passwords, tokens) out of Git. Use `.env` and `secrets/.gitkeep`.
- Use only MITRE ATT&CK mappings that are accurate; if unsure, mark as “TBD” rather than guess.
- All code must run on Python 3.12+ (Ubuntu 26.04 default).
- Document every step so a beginner can reproduce it.
