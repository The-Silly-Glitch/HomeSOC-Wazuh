# HomeSOC-Wazuh: Setup & Host Operational Notes

This document records host-specific findings, environment configurations, and operational guidance discovered while building and verifying the HomeSOC lab.

---

## 1. Host Environment & Tooling Discoveries

- **Operating System & Python**: Host running Ubuntu 26.04.1 LTS with Python 3.12.x.
- **Docker & Docker Compose CLI**:
  - Docker was not initially installed.
  - Installed official Docker Engine (`docker-ce` 29.9.1) and Docker Compose plugin via the Docker APT repository.
  - Added user `honeysh` to the `docker` group.
  - Because group membership does not propagate to existing non-login shells, Docker commands are run with `sg docker -c '...'` during automated setup.
- **GitHub CLI**: `gh` binary installed to `~/.local/bin/gh` but not authenticated; repository push done over SSH.

---

## 2. Docker & Wazuh SIEM Stack Requirements

### OpenSearch / Wazuh Indexer Virtual Memory
The Wazuh Indexer requires adequate virtual memory maps:
```bash
sudo sysctl -w vm.max_map_count=262144
```
To make this persistent across reboots:
```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### TLS Certificate Generation
Before launching the stack for the first time, generate root CA and node certificates:
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```
Generated certificates reside in `config/wazuh_indexer_ssl_certs/` and are excluded from Git by `.gitignore`.

---

## 3. Endpoints & Detection Engineering

### Ubuntu Agent Auto-Enrollment
- The Ubuntu agent uses `Dockerfile.ubuntu-agent` with `wazuh-agent=4.11.2-1`.
- Auto-enrollment is orchestrated via `scripts/entrypoint-agent.sh`, querying the Manager's Authd service on port 1515.
- The agent configuration (`config/agent/ossec-agent.conf`) sets up real-time FIM on `/monitored` and links the custom SCA policy `config/agent/sca/custom_ubuntu_sca.yml`.

### Windows Event Simulation & Ingestion
- `scripts/windows_event_simulator.py` generates high-fidelity synthetic Windows events:
  - **T1059.001**: Encoded PowerShell execution (Sysmon Event ID 1)
  - **T1053.005**: Scheduled Task persistence via `schtasks` (Event ID 4698 & 1)
  - **T1078**: Anomalous remote privileged logon (LogonType 10, Event ID 4624)
  - **T1003.001**: LSASS memory access by credential dumpers (Sysmon Event ID 10)
  - **T1082**: Reconnaissance discovery commands (Event ID 1)
- The Wazuh Manager configuration (`config/wazuh_cluster/wazuh_manager.conf`) is configured to ingest these events via:
  1. Localfile JSON monitor at `/var/ossec/logs/windows_simulated.json`
  2. Syslog remote listener on UDP port 514

---

## 4. Automation & Testing Harness

- `scripts/log_generator.py`: Generates auth, sysmon, and FIM logs for replay.
- `scripts/log_parser.py`: Analyzes `alerts.json` and outputs MITRE techniques, rule severity histograms, and agent distributions.
- `scripts/test_alerts.py`: Connects to live Wazuh REST API (`https://localhost:55000`) or runs an offline rule validation suite. Returns exit code 0.
- `scripts/alert_dashboard.py`: Interactive CLI terminal dashboard with live ANSI status.
- `tests/test_pipeline.py`: Unittest suite verifying syntax, schema, and end-to-end execution.

---

## 5. Git Hygiene & Security Notes

- No secrets or credentials are hardcoded into Git.
- Default passwords are documented as lab templates in `secrets/credentials.md.template` and `.env.example`.
- `.gitignore` strictly blocks all `.env`, private keys (`*.key`, `*.pem`), and runtime logs.
- Git commits follow Conventional Commits (`feat(scaffold):`, `feat(docker):`, `feat(agent):`, `feat(windows):`, `feat(detection):`, `feat(automation):`, `docs(setup):`).
