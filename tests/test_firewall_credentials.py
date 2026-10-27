import json
import sys
import tempfile
import unittest
from pathlib import Path

import ansible_runner
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/usg6000e_trade_access"


class FirewallCredentialTests(unittest.TestCase):
    def test_tracked_connection_config_contains_only_placeholders(self):
        profiles = yaml.safe_load((ROOT / "group_vars/all.yml").read_text())["firewall_profiles"]
        for code, profile in profiles.items():
            for field in ("device_host", "device_user", "device_password"):
                value = profile["firewall_device"].get(field, "")
                self.assertTrue(value.startswith("<") and value.endswith(">"), "Non-placeholder connection field: " + code + "." + field)

    def test_protected_override_is_loaded_and_kept_out_of_events(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credential = root / "devices.yml"
            sentinel = "TEST_ONLY_DEVICE_PASSWORD_SENTINEL"
            credential.write_text(yaml.safe_dump({"TEST-FW": {
                "device_host": "192.0.2.10", "device_user": "fixture-user",
                "device_password": sentinel,
            }}))
            credential.chmod(0o600)
            playbook = root / "resolve.yml"
            playbook.write_text(yaml.safe_dump([{
                "hosts": "localhost", "connection": "local", "gather_facts": False,
                "vars": {
                    "firewall_device_credentials_file": str(credential),
                    "firewall_code": "TEST-FW",
                    "firewall_profiles": {"TEST-FW": {
                        "firewall_device": {"device_host": "<HOST>", "device_user": "<USER>", "device_password": "<PASSWORD>", "auth_type": "password", "device_port": 22},
                        "address_vsystems": [{"name": "public", "address_set_name": "fixture-address-set", "switch_required": False}],
                        "application_vsystem": "public",
                        "user_defined_application": {"name_prefix": "UD_Test_", "application_group_name": "UDG_Test"},
                    }},
                },
                "tasks": [
                    {"ansible.builtin.include_role": {"name": str(ROLE), "tasks_from": "resolve_firewall"}},
                    {"ansible.builtin.assert": {"that": [
                        "firewall_device.device_host == '192.0.2.10'",
                        "firewall_device.device_user == 'fixture-user'",
                        "firewall_device.device_password == '" + sentinel + "'",
                        "firewall_device.device_port == 22",
                        "application_vsystem == 'public'",
                    ]}, "no_log": True},
                ],
            }]))
            result = ansible_runner.run(private_data_dir=str(root), project_dir=str(root), playbook=str(playbook), inventory="localhost,", quiet=True)
            self.assertEqual(result.rc, 0)
            for event in result.events:
                self.assertNotIn(sentinel, json.dumps(event))
            credential.chmod(0o644)
            result = ansible_runner.run(private_data_dir=str(root), project_dir=str(root), playbook=str(playbook), inventory="localhost,", quiet=True)
            self.assertNotEqual(result.rc, 0)


if __name__ == "__main__":
    unittest.main()
