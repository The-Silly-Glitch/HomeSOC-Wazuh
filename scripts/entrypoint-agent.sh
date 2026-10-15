#!/usr/bin/env bash
set -e

# HomeSOC Wazuh Agent Auto-Enrollment & Startup Script
WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-ubuntu-endpoint-01}"
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-default}"
WAZUH_REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER:-$WAZUH_MANAGER}"
WAZUH_REGISTRATION_PORT="${WAZUH_REGISTRATION_PORT:-1515}"

echo "[+] Starting Wazuh Agent entrypoint..."
echo "    Manager:             ${WAZUH_MANAGER}"
echo "    Agent Name:          ${WAZUH_AGENT_NAME}"
echo "    Registration Server: ${WAZUH_REGISTRATION_SERVER}:${WAZUH_REGISTRATION_PORT}"

# Configure manager IP/hostname in ossec.conf if present
if [ -f /var/ossec/etc/ossec.conf ]; then
    sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" /var/ossec/etc/ossec.conf
fi

# Auto-enrollment using agent-auth if not already enrolled
if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[+] Waiting for Wazuh Manager registration service on ${WAZUH_REGISTRATION_SERVER}:${WAZUH_REGISTRATION_PORT}..."
    MAX_RETRIES=30
    COUNT=0
    until /var/ossec/bin/agent-auth -m "${WAZUH_REGISTRATION_SERVER}" -p "${WAZUH_REGISTRATION_PORT}" -A "${WAZUH_AGENT_NAME}" -G "${WAZUH_AGENT_GROUP}" || [ $COUNT -ge $MAX_RETRIES ]; do
        COUNT=$((COUNT+1))
        echo "[-] Wazuh Manager not ready yet (attempt $COUNT/$MAX_RETRIES). Waiting 5 seconds..."
        sleep 5
    done

    if [ -s /var/ossec/etc/client.keys ]; then
        echo "[+] Successfully enrolled agent '${WAZUH_AGENT_NAME}' with manager!"
    else
        echo "[!] Auto-enrollment did not complete within timeout. Will retry in background."
    fi
else
    echo "[+] Existing client.keys detected. Skipping re-registration."
fi

# Setup cleanup traps
stop_agent() {
    echo "[+] Stopping Wazuh Agent..."
    /var/ossec/bin/wazuh-control stop
    exit 0
}
trap stop_agent SIGTERM SIGINT

# Start Wazuh Agent service
echo "[+] Starting Wazuh Agent service..."
/var/ossec/bin/wazuh-control start

# Keep container alive by tailing the log
echo "[+] Wazuh Agent is running. Streaming ossec.log..."
touch /var/ossec/logs/ossec.log
tail -F /var/ossec/logs/ossec.log &
wait $!
