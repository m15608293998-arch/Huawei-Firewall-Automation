import sys
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from api.config import settings
from api.runner_service import AnsibleRunnerService, SnapshotRunnerResult


class RunnerServiceTests(unittest.TestCase):
    def test_firewall_target_codes_are_normalized_and_validated(self) -> None:
        original_targets = settings.firewall_targets
        try:
            settings.firewall_targets = " PG-FW,PG-FW-1,IDC-FW,PG-FW "
            self.assertEqual(
                settings.firewall_target_codes,
                ("PG-FW", "PG-FW-1", "IDC-FW"),
            )
            settings.firewall_targets = "PG-FW,bad target"
            with self.assertRaises(ValueError):
                settings.firewall_target_codes
        finally:
            settings.firewall_targets = original_targets

    def test_port_actions_are_passed_to_ansible_and_full_deny_does_not_need_ports(self) -> None:
        captured_calls = []

        def fake_run(**kwargs):
            captured_calls.append(kwargs)
            return types.SimpleNamespace(status="successful", rc=0)

        fake_runner = types.SimpleNamespace(run=fake_run)
        original_private_data_dir = settings.runner_private_data_dir

        with tempfile.TemporaryDirectory() as temp_dir:
            settings.runner_private_data_dir = Path(temp_dir) / "runner"
            try:
                with patch.dict(sys.modules, {"ansible_runner": fake_runner}):
                    service = AnsibleRunnerService()
                    service.run_trade_access(
                        {
                            "job_id": "allow-job",
                            "action": "allow",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [12001, 12002],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "allow-job"),
                        }
                    )
                    service.run_trade_access(
                        {
                            "job_id": "deny-job",
                            "action": "deny",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "deny-job"),
                        }
                    )
                    service.run_trade_access(
                        {
                            "job_id": "deny-ports-job",
                            "action": "deny_ports",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [12001],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "deny-ports-job"),
                        }
                    )
            finally:
                settings.runner_private_data_dir = original_private_data_dir

        self.assertEqual(
            captured_calls[0]["extravars"]["application_ports"],
            [12001, 12002],
        )
        self.assertNotIn("application_ports", captured_calls[1]["extravars"])
        self.assertEqual(captured_calls[2]["extravars"]["application_ports"], [12001])

    def test_snapshot_mode_is_passed_to_ansible(self) -> None:
        captured_calls = []

        def fake_run(**kwargs):
            captured_calls.append(kwargs)
            output_path = Path(kwargs["extravars"]["snapshot_output_path"])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps({"generated_at": "2026-07-03T10:30:00+08:00", "items": []}),
                encoding="utf-8",
            )
            return types.SimpleNamespace(status="successful", rc=0)

        fake_runner = types.SimpleNamespace(run=fake_run)
        original_private_data_dir = settings.runner_private_data_dir
        original_job_tmp_root = settings.job_tmp_root

        with tempfile.TemporaryDirectory() as temp_dir:
            settings.runner_private_data_dir = Path(temp_dir) / "runner"
            settings.job_tmp_root = Path(temp_dir) / "jobs"
            try:
                with patch.dict(sys.modules, {"ansible_runner": fake_runner}):
                    result = AnsibleRunnerService().run_firewall_snapshot("ips")
            finally:
                settings.runner_private_data_dir = original_private_data_dir
                settings.job_tmp_root = original_job_tmp_root

        self.assertEqual(result.rc, 0)
        self.assertEqual(result.payload["items"], [])
        self.assertEqual(captured_calls[0]["playbook"], str(settings.project_root / settings.playbook_path))
        self.assertNotIn("trade_access_tasks_from", captured_calls[0]["extravars"])
        self.assertEqual(
            captured_calls[0]["extravars"]["firewall_workflow_mode"],
            "snapshot",
        )
        self.assertEqual(captured_calls[0]["extravars"]["snapshot_mode"], "ips")
        self.assertEqual(captured_calls[0]["extravars"]["firewall_code"], "TEST-FW")
        self.assertIn("firewall_ips_snapshot.json", captured_calls[0]["extravars"]["snapshot_output_path"])
        self.assertTrue(captured_calls[0]["suppress_env_files"])

    def test_explicit_firewall_code_gets_isolated_runner_directory(self) -> None:
        captured_calls = []

        def fake_run(**kwargs):
            captured_calls.append(kwargs)
            return types.SimpleNamespace(status="successful", rc=0)

        fake_runner = types.SimpleNamespace(run=fake_run)
        original_private_data_dir = settings.runner_private_data_dir

        with tempfile.TemporaryDirectory() as temp_dir:
            settings.runner_private_data_dir = Path(temp_dir) / "runner"
            try:
                with patch.dict(sys.modules, {"ansible_runner": fake_runner}):
                    result = AnsibleRunnerService().run_trade_access(
                        {
                            "job_id": "multi-job",
                            "action": "allow_ip",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "multi-job"),
                        },
                        "PG-FW-1",
                    )
            finally:
                settings.runner_private_data_dir = original_private_data_dir

        self.assertEqual(result.rc, 0)
        self.assertEqual(captured_calls[0]["extravars"]["firewall_code"], "PG-FW-1")
        self.assertEqual(
            captured_calls[0]["extravars"]["firewall_workflow_mode"],
            "access",
        )
        self.assertEqual(
            Path(captured_calls[0]["private_data_dir"]).parent.parent.name,
            "PG-FW-1",
        )
        self.assertEqual(
            Path(captured_calls[0]["private_data_dir"]).parent.name,
            "runs",
        )
        artifact_dir = Path(captured_calls[0]["artifact_dir"])
        self.assertEqual(artifact_dir.name, "artifacts")
        self.assertEqual(artifact_dir.parent.name, "PG-FW-1")
        self.assertTrue(captured_calls[0]["suppress_env_files"])
        self.assertEqual(
            Path(captured_calls[0]["extravars"]["local_tmp_dir"]).name,
            "PG-FW-1",
        )

    def test_snapshot_extravars_cannot_leak_into_following_access_run(self) -> None:
        captured_calls = []

        def fake_run(**kwargs):
            captured_calls.append(kwargs)
            if kwargs["extravars"]["firewall_workflow_mode"] == "snapshot":
                output_path = Path(kwargs["extravars"]["snapshot_output_path"])
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(
                    json.dumps({"ip_items": [], "port_items": []}),
                    encoding="utf-8",
                )
            return types.SimpleNamespace(status="successful", rc=0)

        fake_runner = types.SimpleNamespace(run=fake_run)
        original_private_data_dir = settings.runner_private_data_dir
        original_job_tmp_root = settings.job_tmp_root

        with tempfile.TemporaryDirectory() as temp_dir:
            settings.runner_private_data_dir = Path(temp_dir) / "runner"
            settings.job_tmp_root = Path(temp_dir) / "jobs"
            stale_env_dir = settings.runner_private_data_dir / "TEST-FW" / "env"
            stale_env_dir.mkdir(parents=True)
            stale_extravars = stale_env_dir / "extravars"
            stale_extravars.write_text(
                json.dumps({"snapshot_mode": "state"}),
                encoding="utf-8",
            )
            try:
                with patch.dict(sys.modules, {"ansible_runner": fake_runner}):
                    service = AnsibleRunnerService()
                    snapshot_result = service.run_firewall_snapshot("state", "TEST-FW")
                    access_result = service.run_trade_access(
                        {
                            "job_id": "allow-after-snapshot",
                            "action": "allow_ip",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "allow-after-snapshot"),
                        },
                        "TEST-FW",
                    )
            finally:
                settings.runner_private_data_dir = original_private_data_dir
                settings.job_tmp_root = original_job_tmp_root

        self.assertEqual(snapshot_result.rc, 0)
        self.assertEqual(access_result.rc, 0)
        self.assertEqual(len(captured_calls), 2)
        snapshot_call, access_call = captured_calls
        self.assertNotEqual(
            snapshot_call["private_data_dir"],
            access_call["private_data_dir"],
        )
        self.assertEqual(
            snapshot_call["extravars"]["firewall_workflow_mode"],
            "snapshot",
        )
        self.assertEqual(
            access_call["extravars"]["firewall_workflow_mode"],
            "access",
        )
        self.assertNotIn("snapshot_mode", access_call["extravars"])
        self.assertTrue(snapshot_call["suppress_env_files"])
        self.assertTrue(access_call["suppress_env_files"])

    def test_reconciled_snapshot_returns_clean_items_when_all_targets_match(self) -> None:
        service = AnsibleRunnerService()

        def fake_snapshot(snapshot_mode, firewall_code=None):
            self.assertEqual(snapshot_mode, "ips")
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/{0}".format(firewall_code),
                payload={
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    "items": [{"ip": "192.168.66.22"}],
                },
            )

        service.run_firewall_snapshot = fake_snapshot
        result = service.run_reconciled_snapshot(
            "ips",
            ("PG-FW", "PG-FW-1", "IDC-FW"),
        )

        self.assertEqual(result.rc, 0)
        self.assertEqual(result.payload["consistency_status"], "consistent")
        self.assertEqual(
            result.payload["firewall_codes"],
            ["PG-FW", "PG-FW-1", "IDC-FW"],
        )
        self.assertEqual(result.payload["items"], [{"ip": "192.168.66.22"}])

    def test_reconciled_snapshot_returns_per_target_diff_on_drift(self) -> None:
        service = AnsibleRunnerService()
        payloads = {
            "PG-FW": [{"ip": "192.168.66.22", "port": 12001}],
            "PG-FW-1": [{"ip": "192.168.66.22", "port": 12001}],
            "IDC-FW": [],
        }

        def fake_snapshot(snapshot_mode, firewall_code=None):
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/{0}".format(firewall_code),
                payload={
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    "items": payloads[str(firewall_code)],
                },
            )

        service.run_firewall_snapshot = fake_snapshot
        result = service.run_reconciled_snapshot(
            "ports",
            ("PG-FW", "PG-FW-1", "IDC-FW"),
        )

        self.assertEqual(result.rc, 2)
        self.assertEqual(result.status, "drifted")
        self.assertEqual(result.payload["consistency_status"], "drifted")
        self.assertEqual(
            result.payload["differences"]["IDC-FW"]["missing"],
            [{"ip": "192.168.66.22", "port": 12001}],
        )

    def test_reconciled_snapshot_never_returns_partial_data_as_success(self) -> None:
        service = AnsibleRunnerService()

        def fake_snapshot(snapshot_mode, firewall_code=None):
            if firewall_code == "IDC-FW":
                return SnapshotRunnerResult(
                    status="failed",
                    rc=1,
                    artifact_dir="/tmp/IDC-FW",
                    error_message="connection timed out",
                )
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/{0}".format(firewall_code),
                payload={
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    "items": [{"ip": "192.168.66.22"}],
                },
            )

        service.run_firewall_snapshot = fake_snapshot
        result = service.run_reconciled_snapshot(
            "ips",
            ("PG-FW", "PG-FW-1", "IDC-FW"),
        )

        self.assertEqual(result.rc, 1)
        self.assertEqual(result.payload["consistency_status"], "incomplete")
        self.assertNotIn("items", result.payload)
        self.assertEqual(
            result.payload["firewalls"]["IDC-FW"]["error_message"],
            "connection timed out",
        )

    def test_consistency_check_returns_per_node_manual_correction_hints(self) -> None:
        service = AnsibleRunnerService()
        payloads = {
            "PG-FW": {
                "ip_items": [{"ip": "192.168.66.22"}],
                "port_items": [{"ip": "192.168.66.22", "port": 12001}],
            },
            "PG-FW-1": {
                "ip_items": [{"ip": "192.168.66.22"}],
                "port_items": [{"ip": "192.168.66.22", "port": 12001}],
            },
            "IDC-FW": {
                "ip_items": [{"ip": "192.168.66.33"}],
                "port_items": [{"ip": "192.168.66.33", "port": 443}],
            },
        }
        calls = []

        def fake_snapshot(snapshot_mode, firewall_code=None):
            calls.append((snapshot_mode, firewall_code))
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/{0}".format(firewall_code),
                payload={
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    **payloads[str(firewall_code)],
                },
            )

        service.run_firewall_snapshot = fake_snapshot
        result = service.run_firewall_consistency_check(
            ("PG-FW", "PG-FW-1", "IDC-FW")
        )

        self.assertEqual(result.rc, 0)
        self.assertEqual(result.status, "drifted")
        self.assertEqual(result.payload["overall_status"], "drifted")
        self.assertCountEqual(
            calls,
            [
                ("state", "PG-FW"),
                ("state", "PG-FW-1"),
                ("state", "IDC-FW"),
            ],
        )
        self.assertEqual(result.payload["summary"]["ip_drift_item_count"], 2)
        self.assertEqual(result.payload["summary"]["port_drift_item_count"], 2)
        self.assertEqual(result.payload["summary"]["suggested_action_count"], 4)
        idc = result.payload["firewalls"]["IDC-FW"]
        self.assertEqual(idc["ip_missing"], [{"ip": "192.168.66.22"}])
        self.assertEqual(idc["ip_extra"], [{"ip": "192.168.66.33"}])
        self.assertEqual(
            [item["action"] for item in idc["suggested_actions"]],
            ["add_ip", "add_port", "remove_port", "remove_ip"],
        )
        self.assertEqual(
            result.payload["differences"]["ips"][0]["reference_state"],
            "present",
        )
        self.assertEqual(
            result.payload["differences"]["ips"][1]["reference_state"],
            "absent",
        )

    def test_consistency_check_returns_consistent_for_single_test_firewall(self) -> None:
        service = AnsibleRunnerService()

        def fake_snapshot(snapshot_mode, firewall_code=None):
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/{0}".format(firewall_code),
                payload={
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    "ip_items": [{"ip": "192.168.66.22"}],
                    "port_items": [{"ip": "192.168.66.22", "port": 12001}],
                },
            )

        service.run_firewall_snapshot = fake_snapshot
        result = service.run_firewall_consistency_check(("TEST-FW",))

        self.assertEqual(result.rc, 0)
        self.assertEqual(result.payload["overall_status"], "consistent")
        self.assertEqual(result.payload["summary"]["suggested_action_count"], 0)
        self.assertEqual(result.payload["differences"], {"ips": [], "ports": []})

    def test_consistency_check_does_not_suggest_actions_when_a_query_fails(self) -> None:
        service = AnsibleRunnerService()

        def fake_snapshot(snapshot_mode, firewall_code=None):
            if firewall_code == "IDC-FW":
                return SnapshotRunnerResult(
                    status="failed",
                    rc=1,
                    artifact_dir="/tmp/IDC-FW",
                    error_message="connection timed out",
                )
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/{0}".format(firewall_code),
                payload={
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    "ip_items": [{"ip": "192.168.66.22"}],
                    "port_items": [{"ip": "192.168.66.22", "port": 12001}],
                },
            )

        service.run_firewall_snapshot = fake_snapshot
        result = service.run_firewall_consistency_check(
            ("PG-FW", "PG-FW-1", "IDC-FW")
        )

        self.assertEqual(result.rc, 1)
        self.assertEqual(result.payload["overall_status"], "incomplete")
        self.assertEqual(result.payload["summary"]["successful_firewall_count"], 2)
        self.assertIsNone(result.payload["summary"]["ip_consistent"])
        self.assertEqual(
            result.payload["firewalls"]["IDC-FW"]["error_message"],
            "connection timed out",
        )
        self.assertTrue(
            all(
                not node["suggested_actions"]
                for node in result.payload["firewalls"].values()
            )
        )

    def test_consistency_check_marks_even_split_as_ambiguous(self) -> None:
        service = AnsibleRunnerService()

        def fake_snapshot(snapshot_mode, firewall_code=None):
            has_item = firewall_code == "PG-FW"
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/{0}".format(firewall_code),
                payload={
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    "ip_items": [{"ip": "192.168.66.22"}] if has_item else [],
                    "port_items": [],
                },
            )

        service.run_firewall_snapshot = fake_snapshot
        result = service.run_firewall_consistency_check(("PG-FW", "IDC-FW"))

        self.assertEqual(result.payload["overall_status"], "drifted")
        self.assertEqual(result.payload["summary"]["ambiguous_item_count"], 1)
        self.assertEqual(
            result.payload["differences"]["ips"][0]["reference_state"],
            "ambiguous",
        )
        self.assertEqual(result.payload["summary"]["suggested_action_count"], 0)


if __name__ == "__main__":
    unittest.main()
