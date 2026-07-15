import importlib.util
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PARSER_PATH = (
    PROJECT_ROOT
    / "roles/usg6000e_trade_access/files/extract_usg_application_names.py"
)
SPEC = importlib.util.spec_from_file_location("extract_usg_application_names", PARSER_PATH)
PARSER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PARSER)


class ApplicationNameParserTests(unittest.TestCase):
    def test_extracts_base_and_numbered_applications(self) -> None:
        output = """
         user-defined-application name UDA_TS_192.168.5.225
         user-defined-application name UDA_TS_192.168.5.225_2
          add application UDA_TS_192.168.5.225
          add application UDA_TS_192.168.5.225_2
         user-defined-application name UDA_TS_192.168.5.225_backup
         user-defined-application name UDA_TS_192.168.5.224
        """

        result = PARSER.extract_application_names(
            output,
            "UDA_TS_192.168.5.225",
        )

        self.assertEqual(
            result["names"],
            ["UDA_TS_192.168.5.225", "UDA_TS_192.168.5.225_2"],
        )

    def test_handles_device_crlf_and_ansi_output(self) -> None:
        output = (
            "\x1b[0;32m user-defined-application name "
            "UDA_TS_192.168.5.225_10\x1b[0m\r\n"
        )

        result = PARSER.extract_application_names(
            output,
            "UDA_TS_192.168.5.225",
        )

        self.assertEqual(result["names"], ["UDA_TS_192.168.5.225_10"])

    def test_parses_ports_ip_and_pager_markers(self) -> None:
        output = """
         user-defined-application name UDA_TS_192.168.5.225
          rule name 1
           ip-address 192.168.5.225 32
           port 12001
          ---- More ----\x1b[42D                    \x1b[42D   port 12002
         user-defined-application name UDA_TS_192.168.5.225_2
          rule name 1
           ip-address 192.168.5.225 32
           port 12033
          add application UDA_TS_192.168.5.225
          add application UDA_TS_192.168.5.225_2
        """

        result = PARSER.extract_application_config(
            output,
            "UDA_TS_192.168.5.225",
            target_ip="192.168.5.225",
            mask=32,
        )

        self.assertEqual(result["all_ports"], [12001, 12002, 12033])
        self.assertEqual(
            result["applications"][0]["rules"],
            [
                {
                    "name": "1",
                    "ports": [12001, 12002],
                    "ip_addresses": [{"ip": "192.168.5.225", "mask": 32}],
                },
            ],
        )
        self.assertTrue(result["all_target_ips_match"])
        self.assertEqual(
            result["group_names"],
            ["UDA_TS_192.168.5.225", "UDA_TS_192.168.5.225_2"],
        )

    def test_additive_plan_ignores_overlapping_ports_and_splits_capacity(self) -> None:
        parsed = {
            "object_names": ["UDA_TS_192.168.5.225"],
            "group_names": ["UDA_TS_192.168.5.225"],
            "all_ports": list(range(1, 33)),
            "applications": [
                {
                    "name": "UDA_TS_192.168.5.225",
                    "ports": list(range(1, 33)),
                    "rules": [
                        {
                            "name": str(index),
                            "ports": list(range((index - 1) * 4 + 1, index * 4 + 1)),
                        }
                        for index in range(1, 9)
                    ],
                },
            ],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UDA_TS_192.168.5.225",
            [31, 32, 33, 34],
        )

        self.assertEqual(plan["new_ports"], [33, 34])
        self.assertEqual(
            plan["operations"],
            [
                {
                    "type": "create_application",
                    "app_name": "UDA_TS_192.168.5.225_2",
                },
                {
                    "type": "add_rule",
                    "app_name": "UDA_TS_192.168.5.225_2",
                    "rule_name": "1",
                    "ports": [33],
                },
                {
                    "type": "add_ports",
                    "app_name": "UDA_TS_192.168.5.225_2",
                    "rule_name": "1",
                    "ports": [34],
                },
                {
                    "type": "add_to_group",
                    "app_name": "UDA_TS_192.168.5.225_2",
                },
            ],
        )
        self.assertTrue(plan["change_needed"])

    def test_additive_plan_numbers_applications_after_each_32_ports(self) -> None:
        parsed = {
            "object_names": [],
            "group_names": [],
            "all_ports": [],
            "applications": [],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UDA_TS_192.168.66.1",
            list(range(1, 66)),
            rule_port_limit=4,
            application_rule_limit=8,
        )

        self.assertEqual(
            plan["desired_names"],
            [
                "UDA_TS_192.168.66.1",
                "UDA_TS_192.168.66.1_2",
                "UDA_TS_192.168.66.1_3",
            ],
        )
        add_rule_counts = {
            name: sum(
                1
                for operation in plan["operations"]
                if operation["type"] == "add_rule"
                and operation["app_name"] == name
            )
            for name in plan["desired_names"]
        }
        self.assertEqual(
            add_rule_counts,
            {
                "UDA_TS_192.168.66.1": 8,
                "UDA_TS_192.168.66.1_2": 8,
                "UDA_TS_192.168.66.1_3": 1,
            },
        )
        self.assertEqual(
            [
                operation["app_name"]
                for operation in plan["operations"]
                if operation["type"] == "add_to_group"
            ],
            plan["desired_names"],
        )

    def test_additive_plan_fills_existing_rule_slots_before_new_rules(self) -> None:
        parsed = {
            "object_names": ["UDA_TS_192.168.5.225"],
            "group_names": ["UDA_TS_192.168.5.225"],
            "all_ports": [12001, 12002, 12010, 12011, 12012, 12013],
            "applications": [
                {
                    "name": "UDA_TS_192.168.5.225",
                    "ports": [12001, 12002, 12010, 12011, 12012, 12013],
                    "rules": [
                        {"name": "1", "ports": [12001, 12002]},
                        {"name": "3", "ports": [12010, 12011, 12012, 12013]},
                    ],
                },
            ],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UDA_TS_192.168.5.225",
            [13001, 13002, 13003],
        )

        self.assertEqual(
            plan["operations"],
            [
                {
                    "type": "add_ports",
                    "app_name": "UDA_TS_192.168.5.225",
                    "rule_name": "1",
                    "ports": [13001],
                },
                {
                    "type": "add_ports",
                    "app_name": "UDA_TS_192.168.5.225",
                    "rule_name": "1",
                    "ports": [13002],
                },
                {
                    "type": "add_rule",
                    "app_name": "UDA_TS_192.168.5.225",
                    "rule_name": "2",
                    "ports": [13003],
                },
            ],
        )

    def test_additive_plan_is_idempotent_when_ports_already_exist(self) -> None:
        parsed = {
            "object_names": ["UDA_TS_192.168.5.225"],
            "group_names": ["UDA_TS_192.168.5.225"],
            "all_ports": [12001, 12002, 12003],
            "applications": [
                {
                    "name": "UDA_TS_192.168.5.225",
                    "ports": [12001, 12002, 12003],
                    "rules": [{"name": "1", "ports": [12001, 12002, 12003]}],
                },
            ],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UDA_TS_192.168.5.225",
            [12002, 12003],
        )

        self.assertEqual(plan["effective_ports"], [12001, 12002, 12003])
        self.assertEqual(plan["new_ports"], [])
        self.assertFalse(plan["change_needed"])

    def test_empty_ungrouped_application_does_not_block_future_port_changes(self) -> None:
        output = """
         user-defined-application name UDA_TS_192.168.66.19
          rule name 1
           ip-address 192.168.66.19 32
           port 10001
           port 10002
           port 10003
           port 10004
          add application UDA_TS_192.168.66.19
         user-defined-application name UDA_TS_192.168.66.19_2
        """

        result = PARSER.extract_application_config(
            output,
            "UDA_TS_192.168.66.19",
            target_ip="192.168.66.19",
            mask=32,
        )

        self.assertTrue(result["all_target_ips_match"])
        self.assertEqual(result["invalid_target_applications"], [])

        plan = PARSER.build_application_plan(
            result,
            "UDA_TS_192.168.66.19",
            [10005],
        )

        self.assertEqual(
            plan["operations"],
            [
                {
                    "type": "add_rule",
                    "app_name": "UDA_TS_192.168.66.19",
                    "rule_name": "2",
                    "ports": [10005],
                },
            ],
        )

    def test_additive_plan_reuses_empty_numbered_application_when_base_is_full(self) -> None:
        parsed = {
            "object_names": ["UDA_TS_192.168.66.19", "UDA_TS_192.168.66.19_2"],
            "group_names": ["UDA_TS_192.168.66.19"],
            "all_ports": list(range(1, 33)),
            "applications": [
                {
                    "name": "UDA_TS_192.168.66.19",
                    "ports": list(range(1, 33)),
                    "rules": [
                        {
                            "name": str(index),
                            "ports": list(range((index - 1) * 4 + 1, index * 4 + 1)),
                        }
                        for index in range(1, 9)
                    ],
                },
                {"name": "UDA_TS_192.168.66.19_2", "ports": [], "rules": []},
            ],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UDA_TS_192.168.66.19",
            [33],
        )

        self.assertEqual(
            plan["operations"],
            [
                {
                    "type": "add_rule",
                    "app_name": "UDA_TS_192.168.66.19_2",
                    "rule_name": "1",
                    "ports": [33],
                },
                {
                    "type": "add_to_group",
                    "app_name": "UDA_TS_192.168.66.19_2",
                },
            ],
        )

    def test_remove_plan_deletes_requested_ports_and_keeps_remaining_ports(self) -> None:
        parsed = {
            "object_names": ["UDA_TS_192.168.5.225"],
            "group_names": ["UDA_TS_192.168.5.225"],
            "all_ports": [12001, 12002, 12003],
            "applications": [
                {
                    "name": "UDA_TS_192.168.5.225",
                    "ports": [12001, 12002, 12003],
                    "rules": [
                        {
                            "name": "1",
                            "ports": [12001, 12002, 12003],
                            "ip_addresses": [{"ip": "192.168.5.225", "mask": 32}],
                        },
                    ],
                },
            ],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UDA_TS_192.168.5.225",
            [12002, 13000],
            mode="remove",
        )

        self.assertEqual(plan["mode"], "remove")
        self.assertEqual(plan["removed_ports"], [12002])
        self.assertEqual(plan["effective_ports"], [12001, 12003])
        self.assertEqual(
            plan["operations"],
            [
                {
                    "type": "replace_rule_ports",
                    "app_name": "UDA_TS_192.168.5.225",
                    "rule_name": "1",
                    "old_ports": [12001, 12002, 12003],
                    "ports": [12001, 12003],
                },
            ],
        )
        self.assertTrue(plan["change_needed"])

    def test_remove_plan_uses_simple_undo_for_tail_port_deletes(self) -> None:
        parsed = {
            "object_names": ["UDA_TS_192.168.5.225"],
            "group_names": ["UDA_TS_192.168.5.225"],
            "all_ports": [12001, 12002, 12003],
            "applications": [
                {
                    "name": "UDA_TS_192.168.5.225",
                    "ports": [12001, 12002, 12003],
                    "rules": [
                        {
                            "name": "1",
                            "ports": [12001, 12002, 12003],
                            "ip_addresses": [{"ip": "192.168.5.225", "mask": 32}],
                        },
                    ],
                },
            ],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UDA_TS_192.168.5.225",
            [12003],
            mode="remove",
        )

        self.assertEqual(
            plan["operations"],
            [
                {
                    "type": "remove_ports",
                    "app_name": "UDA_TS_192.168.5.225",
                    "rule_name": "1",
                    "ports": [12003],
                },
            ],
        )

    def test_parses_display_application_destination_output(self) -> None:
        output = """
        Application UDA_TS_10.237.30.32 Information:
          Application Name    : UDA_TS_10.237.30.32
          Total Rule Number   : 1
            Rule Name         : 1
            Destination       : 10.237.30.32/32
            Port              : 8010
         add application UDA_TS_10.237.30.32
        """

        result = PARSER.extract_application_config(
            output,
            "UDA_TS_10.237.30.32",
            target_ip="10.237.30.32",
            mask=32,
        )

        self.assertEqual(result["all_ports"], [8010])
        self.assertEqual(
            result["applications"][0]["rules"],
            [
                {
                    "name": "1",
                    "ports": [8010],
                    "ip_addresses": [{"ip": "10.237.30.32", "mask": 32}],
                },
            ],
        )
        self.assertTrue(result["all_target_ips_match"])

    def test_marks_invalid_display_ports(self) -> None:
        output = """
        Application UDA_TS_192.168.66.19 Information:
          Application Name    : UDA_TS_192.168.66.19
          Total Rule Number   : 1
            Rule Name         : 1
            IP Address        : 192.168.66.19/32
            Port              : 0 12001
        """

        result = PARSER.extract_application_config(
            output,
            "UDA_TS_192.168.66.19",
            target_ip="192.168.66.19",
            mask=32,
        )

        self.assertFalse(result["all_ports_valid"])
        self.assertEqual(
            result["invalid_ports"],
            [
                {
                    "application": "UDA_TS_192.168.66.19",
                    "rule": "1",
                    "port": 0,
                },
            ],
        )

    def test_parses_display_application_output(self) -> None:
        output = """
        user-defined-application name UDA_TS_192.168.5.224
         add application UDA_TS_192.168.5.224
        Application UDA_TS_192.168.5.224 Information:
          Application Name    : UDA_TS_192.168.5.224
          Total Rule Number   : 2
            Rule Name         : 1
            IP Address        : 192.168.5.224/32
            Port              : 12001 12002 12003 12004
            Rule Name         : 2
            IP Address        : 192.168.5.224/32
            Port              : 12005 12006
        """

        result = PARSER.extract_application_config(
            output,
            "UDA_TS_192.168.5.224",
            target_ip="192.168.5.224",
            mask=32,
        )

        self.assertEqual(result["all_ports"], [12001, 12002, 12003, 12004, 12005, 12006])
        self.assertEqual(
            result["applications"][0]["rules"],
            [
                {
                    "name": "1",
                    "ports": [12001, 12002, 12003, 12004],
                    "ip_addresses": [{"ip": "192.168.5.224", "mask": 32}],
                },
                {
                    "name": "2",
                    "ports": [12005, 12006],
                    "ip_addresses": [{"ip": "192.168.5.224", "mask": 32}],
                },
            ],
        )
        self.assertTrue(result["all_target_ips_match"])
        self.assertEqual(result["group_names"], ["UDA_TS_192.168.5.224"])


if __name__ == "__main__":
    unittest.main()
