# HomeSOC Architecture & Component Guide

## Overview

HomeSOC is an educational and operational lab environment built on the **Wazuh 4.11.2** architecture. It integrates log collection, threat detection, host-based intrusion detection, and test automation in a containerized environment.

```mermaid
graph TD
    subgraph DataSources["Data Ingestion Layer"]
        A1["Ubuntu Linux Endpoint\n(/var/ossec agent)"]
        A2["Simulated Windows Endpoint\n(Python Sysmon/Security)"]
        A3["Log Generator & Replayer\n(Auth/Syslog/FIM)"]
    end

    subgraph ManagerLayer["Analysis & Processing (Wazuh Manager)"]
        M1["Registration / Enrollment\n(Port 1515 Authd)"]
        M2["Agent Secure Protocol\n(Port 1514 encrypted)"]
        M3["Syslog Collector\n(Port 514 UDP/TCP)"]
        M4["Decoders Engine\n(/configs/decoders)"]
        M5["Rules Engine & MITRE Tagging\n(/detections)"]
        M6["Filebeat Forwarder\n(SSL to Indexer:9200)"]
        M7["REST API Service\n(Port 55000 HTTPS)"]

        M1 --> M4
        M2 --> M4
        M3 --> M4
        M4 --> M5
        M5 --> M6
        M5 --> M7
    end

    subgraph StorageAndVis["Indexing & Visualization"]
        I1["Wazuh Indexer\n(OpenSearch 2.x - Port 9200)"]
        D1["Wazuh Dashboard\n(OpenSearch Dashboards - Port 443)"]
        M6 --> I1
        D1 --> I1
        D1 --> M7
    end

    A1 --> M2
    A2 --> M3
    A3 --> M3
```

## Network Ports & Protocols

| Port | Protocol | Component | Purpose |
|---|---|---|---|
| 1514 | TCP/UDP | Wazuh Manager | Agent connection and log transmission |
| 1515 | TCP | Wazuh Manager | Agent auto-enrollment service (Authd) |
| 514 | UDP | Wazuh Manager | Syslog ingestion (Windows simulator / network gear) |
| 55000 | TCP | Wazuh Manager | Management REST API |
| 9200 | TCP | Wazuh Indexer | Indexer REST API (TLS secured) |
| 443 | TCP | Wazuh Dashboard | Web UI console |

## Storage & Persistence Strategy
All services utilize persistent Docker volumes:
- `wazuh-indexer-data`: Retains indices, mappings, and alerts over time.
- `wazuh_etc`, `wazuh_logs`, `wazuh_queue`: Manager state, agent keys, queue buffers, and log archives.
- `wazuh-dashboard-config`: Custom dashboards, visual configurations, and tenant data.
