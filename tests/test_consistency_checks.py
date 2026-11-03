import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api.runner_service import AnsibleRunnerService, SnapshotRunnerResult
from api.schemas import FirewallConsistencyCheckResponse


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "check_snapshot_parser", ROOT / "roles/usg6000e_trade_access/files/extract_usg_trade_snapshot.py",
)
PARSER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PARSER)
IP = "203.0.113.10"
SECOND_IP = "198.51.100.10"
BASE = "UD_TServe_" + IP
GROUP = "UDG_TradeServers"


def application(name=BASE, bindings=((IP, 32, 443),), grouped=True):
    text = "user-defined-application name " + name + "\n"
    for index, (ip, mask, port) in enumerate(bindings, 1):
        text += " rule name {0}\n  ip-address {1} {2}\n  port {3}\n".format(index, ip, mask, port)
    text += "#\n"
    if grouped:
        text += "application-group name " + GROUP + "\n add application " + name + "\n#\n"
    return text


def state_payload(config, masks=None):
    with tempfile.TemporaryDirectory() as directory:
        sources = []
        for vsystem in ("public", "Internet", "private"):
            path = Path(directory) / vsystem
            addresses = (masks or {}).get(vsystem, {IP: 32, SECOND_IP: 32})
            path.write_text("".join(
                "address {0} {1} mask {2}\n".format(index, ip, mask)
                for index, (ip, mask) in enumerate(addresses.items(), 1)
            ))
            sources.append({"vsystem": vsystem, "path": str(path)})
        return PARSER.build_state_snapshot(sources, config, "", config, "UD_TServe_", "private", GROUP)


def check_payload(payload, second=None):
    service = AnsibleRunnerService()
    results = {"TEST-FW": SnapshotRunnerResult("successful", 0, "/tmp/check-test", payload)}
    if second is not None:
        results["SECOND-FW"] = second
    with patch.object(service, "_query_snapshots_parallel", return_value=results):
        result = service._run_firewall_consistency_check_unlocked(tuple(results))
    FirewallConsistencyCheckResponse.model_validate(result.payload)
    return result


class ConsistencyRawStateTests(unittest.TestCase):
    def test_valid_legacy_and_multi_ip_group_members_are_not_drift(self):
        for name, bindings in (
            (BASE, ((IP, 32, 443),)),
            ("UD_TServe_legacy", ((IP, 32, 443),)),
            ("Legacy_Trade", ((IP, 32, 443),)),
            ("UD_TServe_" + IP + "/" + SECOND_IP, ((IP, 32, 443), (SECOND_IP, 32, 8443))),
        ):
            with self.subTest(name=name):
                result = check_payload(state_payload(application(name, bindings)))
                self.assertEqual(result.payload["overall_status"], "consistent")
                self.assertEqual(result.payload["summary"]["config_issue_count"], 0)
                self.assertEqual(result.payload["firewalls"]["TEST-FW"]["suggested_actions"], [])

    def test_unrelated_applications_are_outside_the_business_check(self):
        config = application() + application("Corporate_DNS", (("192.0.2.53", 32, 53),), grouped=False)
        result = check_payload(state_payload(config))
        self.assertEqual(result.payload["overall_status"], "consistent")

    def test_managed_and_group_residue_remain_detectable(self):
        configs = {
            "wrong_named_target": application(bindings=((SECOND_IP, 32, 443),)),
            "wrong_mask": application(bindings=((IP, 24, 443),)),
            "ungrouped_object": application(grouped=False),
            "empty_object": "user-defined-application name " + BASE + "\n#\n",
            "missing_object": "application-group name " + GROUP + "\n add application Legacy_Missing\n#\n",
            "legacy_orphan_ip": application("Legacy_Trade", (("192.0.2.10", 32, 443),)),
        }
        for label, config in configs.items():
            with self.subTest(label=label):
                result = check_payload(state_payload(config))
                node = result.payload["firewalls"]["TEST-FW"]
                self.assertEqual(result.payload["overall_status"], "drifted")
                self.assertGreater(result.payload["summary"]["config_issue_count"], 0)
                self.assertTrue(node["config_issues"])
                self.assertTrue(all(action["application_name"] for action in node["suggested_actions"]))

    def test_legacy_non32_binding_keeps_observed_ip_and_port_in_suggestion(self):
        for mask in (0, 24, 31):
            with self.subTest(mask=mask):
                result = check_payload(state_payload(application("Legacy_Trade", ((IP, mask, 443),))))
                self.assertEqual(result.payload["overall_status"], "drifted")
                action = result.payload["firewalls"]["TEST-FW"]["suggested_actions"][0]
                self.assertEqual(action["ip"], IP)
                self.assertEqual(action["port"], 443)
                self.assertEqual(action["application_name"], "Legacy_Trade")
                self.assertIn("invalid or mismatched rule IP/mask binding", action["reason"])

    def test_partial_vsystem_and_wrong_masks_report_the_affected_context(self):
        for addresses in ({}, {IP: 24}):
            with self.subTest(addresses=addresses):
                result = check_payload(state_payload("", {"public": addresses}))
                self.assertEqual(result.payload["overall_status"], "drifted")
                node = result.payload["firewalls"]["TEST-FW"]
                self.assertIn("public", " ".join(node["config_issues"]))
                self.assertIn("repair_ip", [action["action"] for action in node["suggested_actions"]])

    def test_incomplete_query_retains_known_issues_without_repair_suggestions(self):
        failed = SnapshotRunnerResult("failed", 1, "/tmp/failed", error_message="query failed")
        result = check_payload(state_payload(application(grouped=False)), failed)
        self.assertEqual(result.payload["overall_status"], "incomplete")
        self.assertTrue(result.payload["firewalls"]["TEST-FW"]["config_issues"])
        self.assertFalse(any(node["suggested_actions"] for node in result.payload["firewalls"].values()))

    def test_missing_or_malformed_raw_fields_cannot_report_consistency(self):
        payload = state_payload(application())
        for key, value in (("application_state", None), ("application_group_members", None),
                           ("application_state", {"applications": [{"name": BASE, "rules": ["invalid"]}]})):
            with self.subTest(key=key, value=value):
                broken = copy.deepcopy(payload)
                broken[key] = value
                result = check_payload(broken)
                self.assertEqual(result.payload["overall_status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
