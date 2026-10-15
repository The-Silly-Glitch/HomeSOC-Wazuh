#!/usr/bin/env python3
"""
HomeSOC Pipeline Verification Suite
Runs automated unit and integration checks across Docker configs,
XML definitions, and Python automation tools.
"""

import csv
import json
import os
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestHomeSOCPipeline(unittest.TestCase):

    def test_01_docker_compose_config(self):
        cmd = ["docker", "compose", "config"]
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"docker compose config failed:\n{result.stderr}")

    def test_02_docker_compose_agents_config(self):
        cmd = ["docker", "compose", "-f", "docker-compose.agents.yml", "config"]
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"agents compose config failed:\n{result.stderr}")

    def test_03_xml_validity(self):
        rules_path = os.path.join(REPO_ROOT, "detections", "custom_rules.xml")
        decoders_path = os.path.join(REPO_ROOT, "configs", "decoders", "custom_decoders.xml")

        ET.parse(rules_path)
        ET.parse(decoders_path)

    def test_04_mitre_csv_mapping(self):
        csv_path = os.path.join(REPO_ROOT, "docs", "mitre_mapping.csv")
        self.assertTrue(os.path.exists(csv_path))
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertGreaterEqual(len(rows), 5)
            technique_ids = [r["MITRE ID"] for r in rows]
            self.assertIn("T1059.001", technique_ids)
            self.assertIn("T1053.005", technique_ids)
            self.assertIn("T1078", technique_ids)

    def test_05_windows_simulator(self):
        cmd = [sys.executable, "scripts/windows_event_simulator.py", "--count", "5", "--output", "stdout"]
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        lines = [l for l in result.stdout.strip().split("\n") if l.startswith("{")]
        self.assertEqual(len(lines), 5)
        for l in lines:
            event = json.loads(l)
            self.assertIn("EventID", event)
            self.assertIn("mitre_technique", event)

    def test_06_test_alerts_harness(self):
        cmd = [sys.executable, "scripts/test_alerts.py", "--offline"]
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"test_alerts harness failed:\n{result.stderr}")


if __name__ == "__main__":
    unittest.main()
