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
         user-defined-application name UD_TS_192.168.5.225
         user-defined-application name UD_TS_192.168.5.225_2
          add application UD_TS_192.168.5.225
          add application UD_TS_192.168.5.225_2
         user-defined-application name UD_TS_192.168.5.225_backup
         user-defined-application name UD_TS_192.168.5.224
        """

        result = PARSER.extract_application_names(
            output,
            "UD_TS_192.168.5.225",
        )

        self.assertEqual(
            result["names"],
            ["UD_TS_192.168.5.225", "UD_TS_192.168.5.225_2"],
        )

    def test_handles_device_crlf_and_ansi_output(self) -> None:
        output = (
            "\x1b[0;32m user-defined-application name "
            "UD_TS_192.168.5.225_10\x1b[0m\r\n"
        )

        result = PARSER.extract_application_names(
            output,
            "UD_TS_192.168.5.225",
        )

        self.assertEqual(result["names"], ["UD_TS_192.168.5.225_10"])

    def test_parses_ports_ip_and_pager_markers(self) -> None:
        output = """
         user-defined-application name UD_TS_192.168.5.225
          rule name 1
           ip-address 192.168.5.225 32
           port 12001
          ---- More ----\x1b[42D                    \x1b[42D   port 12002
         user-defined-application name UD_TS_192.168.5.225_2
          rule name 1
           ip-address 192.168.5.225 32
           port 12033
          add application UD_TS_192.168.5.225
          add application UD_TS_192.168.5.225_2
        """

        result = PARSER.extract_application_config(
            output,
            "UD_TS_192.168.5.225",
            target_ip="192.168.5.225",
            mask=32,
        )

        self.assertEqual(result["all_ports"], [12001, 12002, 12033])
        self.assertTrue(result["all_target_ips_match"])
        self.assertEqual(
            result["group_names"],
            ["UD_TS_192.168.5.225", "UD_TS_192.168.5.225_2"],
        )

    def test_additive_plan_ignores_overlapping_ports_and_splits_capacity(self) -> None:
        parsed = {
            "object_names": ["UD_TS_192.168.5.225"],
            "group_names": ["UD_TS_192.168.5.225"],
            "all_ports": list(range(1, 33)),
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UD_TS_192.168.5.225",
            [31, 32, 33, 34],
        )

        self.assertEqual(plan["new_ports"], [33, 34])
        self.assertEqual(len(plan["units"][0]["ports"]), 32)
        self.assertEqual(plan["units"][1]["app_name"], "UD_TS_192.168.5.225_2")
        self.assertEqual(plan["units"][1]["ports"], [33, 34])
        self.assertTrue(plan["rebuild_needed"])

    def test_additive_plan_is_idempotent_when_ports_already_exist(self) -> None:
        parsed = {
            "object_names": ["UD_TS_192.168.5.225"],
            "group_names": ["UD_TS_192.168.5.225"],
            "all_ports": [12001, 12002, 12003],
            "all_target_ips_match": True,
        }

        plan = PARSER.build_application_plan(
            parsed,
            "UD_TS_192.168.5.225",
            [12002, 12003],
        )

        self.assertEqual(plan["effective_ports"], [12001, 12002, 12003])
        self.assertEqual(plan["new_ports"], [])
        self.assertFalse(plan["rebuild_needed"])

    def test_parses_display_application_output(self) -> None:
        output = """
        user-defined-application name UD_TS_192.168.5.224
         add application UD_TS_192.168.5.224
        Application UD_TS_192.168.5.224 Information:
          Application Name    : UD_TS_192.168.5.224
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
            "UD_TS_192.168.5.224",
            target_ip="192.168.5.224",
            mask=32,
        )

        self.assertEqual(result["all_ports"], [12001, 12002, 12003, 12004, 12005, 12006])
        self.assertTrue(result["all_target_ips_match"])
        self.assertEqual(result["group_names"], ["UD_TS_192.168.5.224"])


if __name__ == "__main__":
    unittest.main()
