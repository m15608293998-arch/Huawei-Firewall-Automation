import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

import ansible_runner
import yaml

from api.runner_service import SnapshotRunnerResult
from api.worker import JobWorker


ROOT = Path(__file__).resolve().parents[1]


def load_helper(name):
    path = ROOT / "roles/usg6000e_trade_access/files" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SNAPSHOT = load_helper("extract_usg_trade_snapshot")
APPLICATION = load_helper("extract_usg_application_names")
CLI = load_helper("run_usg_cli")
IP = "203.0.113.10"
BASE = "UD_TServe_" + IP


def application_text(ports, target_ip=IP):
    return (
        "user-defined-application name " + BASE + "\n"
        " rule name 1\n"
        "  ip-address " + target_ip + " 32\n"
        + "".join("  port {0}\n".format(port) for port in ports)
        + "#\napplication-group name UDG_TradeServers\n"
        " add application " + BASE + "\n#\n"
    )


class RawStateTests(unittest.TestCase):
    def snapshot(self, present_vsystems, applications=""):
        with tempfile.TemporaryDirectory() as directory:
            sources = []
            for vsystem in ("public", "Internet", "private"):
                path = Path(directory) / vsystem
                path.write_text(
                    "address 1 {0} mask 32\n".format(IP)
                    if vsystem in present_vsystems else ""
                )
                sources.append({"vsystem": vsystem, "path": str(path)})
            return SNAPSHOT.build_state_snapshot(
                sources, applications, "", applications,
                "UD_TServe_", "private", "UDG_TradeServers",
            )

    def state(self, payload):
        class Runner:
            def run_firewall_snapshot(self, *args, **kwargs):
                return SnapshotRunnerResult("successful", 0, "", payload)

        return JobWorker(None, Runner())._query_target_state({"target_ip": IP}, "FW")[0]

    def test_deny_rejects_partial_vsystem_residue(self):
        state = self.state(self.snapshot({"Internet", "private"}))
        self.assertFalse(JobWorker._state_matches(state, {"ip_present": False, "ports": []}))
        self.assertEqual(state["address_membership"], {"public": None, "Internet": 32, "private": 32})

    def test_deny_rejects_orphan_application_after_all_addresses_removed(self):
        state = self.state(self.snapshot(set(), application_text([443])))
        self.assertEqual(state["ports"], [443])
        self.assertFalse(JobWorker._state_matches(state, {"ip_present": False, "ports": []}))

    def test_deny_rejects_empty_application_or_group_residue(self):
        for text in ("user-defined-application name " + BASE, "add application " + BASE):
            with self.subTest(text=text):
                state = self.state(self.snapshot(set(), text))
                self.assertFalse(JobWorker._state_matches(state, {"ip_present": False, "ports": []}))

    def test_allow_rejects_missing_group_membership(self):
        text = application_text([443]).replace(" add application " + BASE, "")
        state = self.state(self.snapshot({"public", "Internet", "private"}, text))
        self.assertFalse(JobWorker._state_matches(state, {"ip_present": True, "ports": [443]}))

    def test_empty_complete_raw_state_proves_absence(self):
        state = self.state(self.snapshot(set()))
        self.assertTrue(JobWorker._state_matches(state, {"ip_present": False, "ports": []}))

    def test_effective_items_alone_cannot_prove_absence(self):
        with self.assertRaisesRegex(RuntimeError, "raw|Raw|incomplete"):
            self.state({"ip_items": [], "port_items": []})

    def test_wrong_ip_application_cannot_pass_allow_validation(self):
        state = self.state(self.snapshot({"public", "Internet", "private"}, application_text([443], "203.0.113.20")))
        self.assertFalse(JobWorker._state_matches(state, {"ip_present": True, "ports": [443]}))


class RecoveryPlanTests(unittest.TestCase):
    def test_reconcile_reuses_capacity_of_removed_port_in_full_application(self):
        text = "user-defined-application name " + BASE + "\n"
        for index in range(8):
            text += "rule name {0}\nip-address {1} 32\n".format(index + 1, IP)
            text += "".join("port {0}\n".format(port) for port in range(index * 4 + 1, index * 4 + 5))
        text += "add application " + BASE + "\n"
        parsed = APPLICATION.extract_application_config(text, BASE, IP, 32)
        plan = APPLICATION.build_application_plan(parsed, BASE, list(range(1, 32)) + [443], mode="reconcile")
        self.assertFalse(any(operation["type"] == "create_application" for operation in plan["operations"]))
        self.assertEqual(plan["desired_names"], [BASE])
        self.assertEqual(plan["operations"][0]["type"], "remove_ports")
        self.assertEqual(plan["operations"][-1]["ports"], [443])

    def test_reconcile_recreates_removed_rule_with_its_ip_binding(self):
        text = "user-defined-application name " + BASE + "\n"
        for index in range(8):
            text += "rule name {0}\nip-address {1} 32\n".format(index + 1, IP)
            text += "".join("port {0}\n".format(port) for port in range(index * 4 + 1, index * 4 + 5))
        text += "add application " + BASE + "\n"
        parsed = APPLICATION.extract_application_config(text, BASE, IP, 32)
        plan = APPLICATION.build_application_plan(parsed, BASE, list(range(1, 29)) + [443], mode="reconcile")
        self.assertFalse(any(operation["type"] == "create_application" for operation in plan["operations"]))
        self.assertIn({"type": "add_rule", "app_name": BASE, "rule_name": "8", "ports": [443]}, plan["operations"])

    def test_reconcile_deletes_empty_application_before_reusing_its_name(self):
        parsed = APPLICATION.extract_application_config(application_text([80]), BASE, IP, 32)
        plan = APPLICATION.build_application_plan(parsed, BASE, [443], mode="reconcile")
        operations = plan["operations"]
        remove_index = next(index for index, operation in enumerate(operations) if operation["type"] == "remove_application")
        create_index = next(index for index, operation in enumerate(operations) if operation["type"] == "create_application")
        self.assertLess(remove_index, create_index)
        self.assertEqual(operations[create_index]["app_name"], BASE)
        self.assertEqual(plan["desired_names"], [BASE])

    def test_reconcile_restores_retained_ports_after_interrupted_middle_delete(self):
        parsed = APPLICATION.extract_application_config(application_text([12002, 12003]), BASE, IP, 32)
        plan = APPLICATION.build_application_plan(parsed, BASE, [12001, 12003], mode="reconcile")
        self.assertEqual(plan["effective_ports"], [12001, 12003])
        self.assertEqual(plan["new_ports"], [12001])
        self.assertEqual(plan["removed_ports"], [12002])
        self.assertTrue(plan["change_needed"])

    def test_reconcile_reuses_empty_rule_and_repairs_its_ip(self):
        parsed = APPLICATION.extract_application_config(application_text([]), BASE, IP, 32)
        plan = APPLICATION.build_application_plan(parsed, BASE, [443], mode="reconcile")
        self.assertTrue(any(op["type"] == "add_ports" and op["ports"] == [443] for op in plan["operations"]))

    def test_reconcile_removes_empty_ungrouped_objects(self):
        parsed = APPLICATION.extract_application_config(application_text([]).replace(" add application " + BASE, ""), BASE, IP, 32)
        plan = APPLICATION.build_application_plan(parsed, BASE, [], mode="reconcile")
        self.assertIn({"type": "remove_application", "app_name": BASE, "in_group": False}, plan["operations"])

    def test_reconcile_removes_group_only_residue(self):
        parsed = APPLICATION.extract_application_config("add application " + BASE, BASE, IP, 32)
        plan = APPLICATION.build_application_plan(parsed, BASE, [], mode="reconcile")
        self.assertEqual(plan["operations"], [{
            "type": "remove_application", "app_name": BASE,
            "in_group": True, "object_exists": False,
        }])

    def test_wrong_ip_is_rejected_even_without_any_ports(self):
        parsed = APPLICATION.extract_application_config(application_text([], "203.0.113.20"), BASE, IP, 32)
        self.assertFalse(parsed["all_target_ips_match"])

    def test_detail_header_alone_cannot_prove_an_application_is_empty(self):
        for text in (
            "Application " + BASE + " Information:\n",
            "Application " + BASE + " Information:\nTotal Rule Number : 1\n",
            "Application " + BASE + " Information:\nTotal Rule Number : 1\nRule Name : 1\n",
            "Application " + BASE + " Information:\nTotal Rule Number : 1\nRule Name : 1\nDestination : " + IP + "/32\n",
        ):
            parsed = APPLICATION.extract_application_config(text, BASE, IP, 32)
            self.assertFalse(parsed["all_details_complete"])
        parsed = APPLICATION.extract_application_config(
            "Application " + BASE + " Information:\nTotal Rule Number : 0\n", BASE, IP, 32,
        )
        self.assertTrue(parsed["all_details_complete"])

    def test_save_requires_positive_completion_message(self):
        for output in ("<FW>", "Info: Saving configuration failed.\n<FW>", "Info: Save request accepted.\n<FW>"):
            with self.subTest(output=output):
                with self.assertRaises(RuntimeError):
                    CLI.ensure_save_completed(output)
        CLI.ensure_save_completed("Info: Save the configuration successfully.\n<FW>")


class FinalizationExecutionTests(unittest.TestCase):
    def test_no_op_worker_runs_finalize_but_ip_action_does_not_commit_applications(self):
        tasks = yaml.safe_load((ROOT / "roles/usg6000e_trade_access/tasks/access/main.yml").read_text())
        start = next(index for index, task in enumerate(tasks) if task["name"] == "Resolve required finalization steps")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "record_cli.py"
            fixture.write_text(
                "import sys\nfrom pathlib import Path\n"
                "path=Path(sys.argv[-1])\npath.with_suffix('.sent').write_text(path.read_text())\n"
                "print('Info: Save the configuration successfully.')\n"
            )
            plays = []
            for label, action, force in (("ports", "allow_ports", True), ("ip", "allow_ip", True), ("unchanged", "allow_ports", False)):
                local = root / label
                local.mkdir()
                plays.append({
                    "hosts": "localhost", "connection": "local", "gather_facts": False,
                    "vars": {
                        "local_tmp_dir": str(local), "access_request": {"action": action},
                        "application_vsystem": "private", "force_finalize": force,
                        "enable_application_config": True, "commit_security_engine": True,
                        "save_config": True, "application_mutated": False, "firewall_mutated": False,
                        "firewall_cli_command_prefix": [sys.executable, str(fixture)],
                        "firewall_cli_environment": {},
                    },
                    "tasks": tasks[start:],
                })
            playbook = root / "finalize.yml"
            playbook.write_text(yaml.safe_dump(plays))
            result = ansible_runner.run(
                private_data_dir=str(root), project_dir=str(root),
                playbook=str(playbook), inventory="localhost,", quiet=True,
            )
            self.assertEqual(result.rc, 0)
            ports = (root / "ports/final_commit_save.sent").read_text()
            self.assertIn("engine configuration commit", ports)
            self.assertIn("switch vsys private", ports)
            self.assertIn("\nsave\n", ports)
            ip = (root / "ip/final_commit_save.sent").read_text()
            self.assertEqual(ip.strip(), "save")
            self.assertFalse((root / "unchanged/final_commit_save.sent").exists())


class RemovalOwnershipExecutionTests(unittest.TestCase):
    def test_role_rejects_wrong_or_incomplete_details_before_any_delete(self):
        role = ROOT / "roles/usg6000e_trade_access"
        for details in (
            "Application " + BASE + " Information:\nTotal Rule Number : 1\n"
            "Rule Name : 1\nDestination : 203.0.113.20/32\nPort : 443\n",
            "Info: Incomplete application response.\n",
        ):
            with self.subTest(details=details), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                log = root / "calls.jsonl"
                fixture = root / "cli_fixture.py"
                fixture.write_text(
                    "import json,sys\nfrom pathlib import Path\n"
                    "cli=Path(sys.argv[-1])\n"
                    "with Path({0!r}).open('a') as handle: handle.write(json.dumps(cli.name)+'\\n')\n"
                    "print({1!r} if cli.name.startswith('query_removal_details_') else {2!r})\n".format(
                        str(log), details,
                        "user-defined-application name " + BASE + "\n add application " + BASE + "\n",
                    )
                )
                playbook = root / "ownership.yml"
                playbook.write_text(yaml.safe_dump([{
                    "hosts": "localhost", "connection": "local", "gather_facts": False,
                    "vars": {
                        "local_tmp_dir": str(root), "local_python_interpreter": sys.executable,
                        "base_app_name": BASE, "application_vsystem": "private",
                        "access_request": {"action": "deny", "target_ip": IP, "mask": 32},
                        "user_defined_application": {"application_group_name": "UDG_TradeServers"},
                        "firewall_cli_command_prefix": [sys.executable, str(fixture)],
                        "firewall_cli_environment": {},
                    },
                    "tasks": [{"ansible.builtin.include_role": {
                        "name": str(role), "tasks_from": "application/remove_all_for_ip",
                    }}],
                }]))
                result = ansible_runner.run(
                    private_data_dir=str(root), project_dir=str(root),
                    playbook=str(playbook), inventory="localhost,", quiet=True,
                )
                self.assertNotEqual(result.rc, 0)
                failures = [event["event_data"].get("res", {}).get("msg", "")
                            for event in result.events if event["event"] == "runner_on_failed"]
                self.assertTrue(any("Refusing full removal" in failure for failure in failures), failures)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertTrue(any(name.startswith("query_removal_details_") for name in calls))
                self.assertFalse(any(name.startswith("remove_application_") for name in calls))


if __name__ == "__main__":
    unittest.main()
