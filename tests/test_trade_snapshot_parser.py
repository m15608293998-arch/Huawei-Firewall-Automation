import importlib.util
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_SCRIPT = (
    PROJECT_ROOT
    / "roles/usg6000e_trade_access/files/extract_usg_trade_snapshot.py"
)

spec = importlib.util.spec_from_file_location("extract_usg_trade_snapshot", SNAPSHOT_SCRIPT)
snapshot_parser = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(snapshot_parser)


class TradeSnapshotParserTests(unittest.TestCase):
    def write_file(self, root: Path, name: str, content: str) -> str:
        path = root / name
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_build_snapshot_returns_one_item_per_ip_port(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public = self.write_file(
                root,
                "public.out",
                "address 1 192.168.66.22 mask 32 description server\n"
                "address 2 192.168.66.44 mask 32 description ssh-only\n",
            )
            internet = self.write_file(
                root,
                "internet.out",
                "address 3 192.168.66.22 mask 32 description server\n"
                "address 4 192.168.66.44 mask 32 description ssh-only\n",
            )
            private = self.write_file(
                root,
                "private.out",
                "address 5 192.168.66.22 mask 32 description server\n"
                "address 6 192.168.66.44 mask 32 description ssh-only\n",
            )
            application_inventory = (
                "user-defined-application name UD_TS_192.168.66.22\n"
                "user-defined-application name UD_TS_192.168.66.22_2\n"
            )
            application_details = (
                "Application UD_TS_192.168.66.22 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12001 12002\n"
                "Application UD_TS_192.168.66.22_2 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12003\n"
            )
            application_group = (
                "application-group name UD_TradeGroup_Internet\n"
                "add application UD_TS_192.168.66.22\n"
                "add application UD_TS_192.168.66.22_2\n"
                "application-group name Another_Group\n"
                "add application UD_TS_192.168.66.99\n"
            )

            payload = snapshot_parser.build_snapshot(
                [
                    {"vsystem": "public", "path": public},
                    {"vsystem": "Internet", "path": internet},
                    {"vsystem": "private", "path": private},
                ],
                application_inventory,
                application_details,
                application_group,
                "UD_TS_",
                "private",
                "UD_TradeGroup_Internet",
            )

        self.assertIn("+08:00", payload["generated_at"])
        items = payload["items"]
        allowed_ports = [
            item["port"]
            for item in items
            if item["target_ip"] == "192.168.66.22"
        ]
        self.assertEqual(allowed_ports, [12001, 12002, 12003])
        first = items[0]
        self.assertEqual(first["state"], "allowed")
        self.assertEqual(
            first["address_presence"],
            {"public": True, "Internet": True, "private": True},
        )
        self.assertTrue(first["in_application_group"])
        self.assertEqual(first["application_group"], "UD_TradeGroup_Internet")

        ip_only = items[-1]
        self.assertEqual(ip_only["target_ip"], "192.168.66.44")
        self.assertIsNone(ip_only["port"])
        self.assertEqual(ip_only["state"], "ip_only")
        self.assertIsNone(ip_only["application"])

    def test_build_ip_and_port_snapshots_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public = self.write_file(
                root,
                "public.out",
                "address 1 192.168.66.22 mask 32\n"
                "address 2 192.168.66.44 mask 32\n",
            )
            internet = self.write_file(
                root,
                "internet.out",
                "address 3 192.168.66.22 mask 32\n"
                "address 4 192.168.66.44 mask 32\n",
            )
            private = self.write_file(
                root,
                "private.out",
                "address 5 192.168.66.22 mask 32\n"
                "address 6 192.168.66.44 mask 32\n",
            )
            address_sources = [
                {"vsystem": "public", "path": public},
                {"vsystem": "Internet", "path": internet},
                {"vsystem": "private", "path": private},
            ]

            ip_payload = snapshot_parser.build_ip_snapshot(address_sources)
            port_payload = snapshot_parser.build_port_snapshot(
                address_sources,
                "user-defined-application name UD_TS_192.168.66.22\n",
                "Application UD_TS_192.168.66.22 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12001\n",
                "application-group name UD_TradeGroup_Internet\n"
                "add application UD_TS_192.168.66.22\n",
                "UD_TS_",
                "private",
                "UD_TradeGroup_Internet",
            )

        self.assertEqual(
            [item["target_ip"] for item in ip_payload["items"]],
            ["192.168.66.22", "192.168.66.44"],
        )
        self.assertNotIn("port", ip_payload["items"][0])
        self.assertEqual(
            [item["target_ip"] for item in port_payload["items"]],
            ["192.168.66.22"],
        )
        self.assertEqual(port_payload["items"][0]["port"], 12001)

    def test_combined_address_cli_output_is_split_by_cli_file_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            combined = self.write_file(
                root,
                "address_inventory_all.out",
                "===== CLI FILE: /tmp/query_public.cli =====\n"
                "address 1 192.168.66.22 mask 32\n"
                "===== CLI FILE: /tmp/query_private.cli =====\n"
                "address 2 192.168.66.44 mask 32\n",
            )
            payload = snapshot_parser.build_ip_snapshot(
                [
                    {
                        "vsystem": "public",
                        "path": combined,
                        "cli_file": "/tmp/query_public.cli",
                    },
                    {
                        "vsystem": "private",
                        "path": combined,
                        "cli_file": "/tmp/query_private.cli",
                    },
                ]
            )

        by_ip = {item["target_ip"]: item for item in payload["items"]}
        self.assertEqual(
            by_ip["192.168.66.22"]["address_presence"],
            {"public": True, "private": False},
        )
        self.assertEqual(
            by_ip["192.168.66.44"]["address_presence"],
            {"public": False, "private": True},
        )

    def test_group_missing_is_reported_per_application(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public = self.write_file(root, "public.out", "address 1 192.168.66.22 mask 32\n")
            internet = self.write_file(root, "internet.out", "address 2 192.168.66.22 mask 32\n")
            private = self.write_file(root, "private.out", "address 3 192.168.66.22 mask 32\n")
            payload = snapshot_parser.build_snapshot(
                [
                    {"vsystem": "public", "path": public},
                    {"vsystem": "Internet", "path": internet},
                    {"vsystem": "private", "path": private},
                ],
                "user-defined-application name UD_TS_192.168.66.22\n",
                "Application UD_TS_192.168.66.22 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12001\n",
                "",
                "UD_TS_",
                "private",
                "UD_TradeGroup_Internet",
            )

        self.assertEqual(payload["items"][0]["state"], "group_missing")
        self.assertFalse(payload["items"][0]["in_application_group"])

    def test_invalid_application_declaration_resets_current_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public = self.write_file(root, "public.out", "address 1 192.168.66.22 mask 32\n")
            internet = self.write_file(root, "internet.out", "address 2 192.168.66.22 mask 32\n")
            private = self.write_file(root, "private.out", "address 3 192.168.66.22 mask 32\n")
            full_config = (
                "user-defined-application name UD_TS_192.168.66.22\n"
                " rule name 1\n"
                "  ip-address 192.168.66.22 32\n"
                "  port 12001\n"
                "user-defined-application name \"UD_TS_ 192.168.66.23\"\n"
                " rule name 1\n"
                "  ip-address 192.168.66.23 32\n"
                "  port 12002\n"
                "application-group name UD_TradeGroup_Internet\n"
                " add application UD_TS_192.168.66.22\n"
            )

            payload = snapshot_parser.build_port_snapshot(
                [
                    {"vsystem": "public", "path": public},
                    {"vsystem": "Internet", "path": internet},
                    {"vsystem": "private", "path": private},
                ],
                full_config,
                "",
                full_config,
                "UD_TS_",
                "private",
                "UD_TradeGroup_Internet",
            )

        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["target_ip"], "192.168.66.22")
        self.assertEqual(payload["items"][0]["port"], 12001)


if __name__ == "__main__":
    unittest.main()
