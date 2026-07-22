import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api.config import Settings, load_firewall_orchestration_defaults


class ConfigTests(unittest.TestCase):
    def test_firewall_orchestration_defaults_are_loaded_from_all_yml(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "all.yml"
            config_path.write_text(
                """
trade_access_api:
  firewall_targets:
    - PG-FW
    - PG-FW-1
    - IDC-FW
  firewall_parallel_workers: 3
  firewall_child_max_attempts: 2
  firewall_reconcile_retry_seconds: 45
""".strip(),
                encoding="utf-8",
            )

            defaults = load_firewall_orchestration_defaults(config_path)

        self.assertEqual(defaults["firewall_targets"], "PG-FW,PG-FW-1,IDC-FW")
        self.assertEqual(defaults["firewall_parallel_workers"], 3)
        self.assertEqual(defaults["firewall_child_max_attempts"], 2)
        self.assertEqual(defaults["firewall_reconcile_retry_seconds"], 45)

    def test_environment_can_override_all_yml_compatibility_defaults(self) -> None:
        overrides = {
            "TRADE_ACCESS_API_FIREWALL_TARGETS": "PG-FW,IDC-FW",
            "TRADE_ACCESS_API_FIREWALL_PARALLEL_WORKERS": "2",
            "TRADE_ACCESS_API_FIREWALL_CHILD_MAX_ATTEMPTS": "4",
            "TRADE_ACCESS_API_FIREWALL_RECONCILE_RETRY_SECONDS": "60",
        }
        with patch.dict(os.environ, overrides, clear=False):
            configured = Settings()

        self.assertEqual(configured.firewall_target_codes, ("PG-FW", "IDC-FW"))
        self.assertEqual(configured.firewall_parallel_workers, 2)
        self.assertEqual(configured.firewall_child_max_attempts, 4)
        self.assertEqual(configured.firewall_reconcile_retry_seconds, 60)

    def test_empty_firewall_target_list_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "all.yml"
            config_path.write_text(
                "trade_access_api:\n  firewall_targets: []\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "non-empty strings"):
                load_firewall_orchestration_defaults(config_path)


if __name__ == "__main__":
    unittest.main()
