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

    def test_build_snapshot_returns_only_effective_ip_ports(self) -> None:
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
                "user-defined-application name UDA_TS_192.168.66.22\n"
                "user-defined-application name UDA_TS_192.168.66.22_2\n"
            )
            application_details = (
                "Application UDA_TS_192.168.66.22 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12001 12002\n"
                "Application UDA_TS_192.168.66.22_2 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12003\n"
            )
            application_group = (
                "application-group name UDG_TradeServers\n"
                "add application UDA_TS_192.168.66.22\n"
                "add application UDA_TS_192.168.66.22_2\n"
                "application-group name Another_Group\n"
                "add application UDA_TS_192.168.66.99\n"
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
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertIn("+08:00", payload["generated_at"])
        items = payload["items"]
        allowed_ports = [
            item["port"]
            for item in items
            if item["ip"] == "192.168.66.22"
        ]
        self.assertEqual(allowed_ports, [12001, 12002, 12003])
        first = items[0]
        self.assertEqual(first, {"ip": "192.168.66.22", "port": 12001})
        self.assertNotIn({"ip": "192.168.66.44", "port": None}, items)

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
                "user-defined-application name UDA_TS_192.168.66.22\n",
                "Application UDA_TS_192.168.66.22 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12001\n",
                "application-group name UDG_TradeServers\n"
                "add application UDA_TS_192.168.66.22\n",
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(
            [item["ip"] for item in ip_payload["items"]],
            ["192.168.66.22", "192.168.66.44"],
        )
        self.assertNotIn("port", ip_payload["items"][0])
        self.assertEqual(
            [item["ip"] for item in port_payload["items"]],
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
                "address 2 192.168.66.22 mask 32\n",
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

        by_ip = {item["ip"]: item for item in payload["items"]}
        self.assertEqual(by_ip, {"192.168.66.22": {"ip": "192.168.66.22"}})

    def test_group_missing_is_not_exposed_as_effective_port(self) -> None:
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
                "user-defined-application name UDA_TS_192.168.66.22\n",
                "Application UDA_TS_192.168.66.22 Information:\n"
                "IP Address : 192.168.66.22/32\n"
                "Port : 12001\n",
                "",
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(payload["items"], [])

    def test_invalid_application_declaration_resets_current_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public = self.write_file(root, "public.out", "address 1 192.168.66.22 mask 32\n")
            internet = self.write_file(root, "internet.out", "address 2 192.168.66.22 mask 32\n")
            private = self.write_file(root, "private.out", "address 3 192.168.66.22 mask 32\n")
            full_config = (
                "user-defined-application name UDA_TS_192.168.66.22\n"
                " rule name 1\n"
                "  ip-address 192.168.66.22 32\n"
                "  port 12001\n"
                "user-defined-application name \"UDA_TS_ 192.168.66.23\"\n"
                " rule name 1\n"
                "  ip-address 192.168.66.23 32\n"
                "  port 12002\n"
                "application-group name UDG_TradeServers\n"
                " add application UDA_TS_192.168.66.22\n"
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
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["ip"], "192.168.66.22")
        self.assertEqual(payload["items"][0]["port"], 12001)

    def test_ports_snapshot_uses_rule_destination_not_application_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            address_text = (
                "address 1 139.196.241.63 mask 255.255.255.255\n"
                "address 2 10.237.30.32 mask 32\n"
            )
            public = self.write_file(root, "public.out", address_text)
            internet = self.write_file(root, "internet.out", address_text)
            private = self.write_file(root, "private.out", address_text)
            full_config = (
                "user-defined-application name UDA_TS_139.196.241.63/10.237.30\n"
                " rule name 1\n"
                "  ip-address 139.196.241.63 32\n"
                "  port 34002\n"
                "  port 34009\n"
                " rule name 2\n"
                "  ip-address 10.237.30.32 32\n"
                "  port 12002\n"
                "  port 12009\n"
                "application-group name UDG_TradeServers\n"
                " add application UDA_TS_139.196.241.63/10.237.30\n"
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
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(
            payload["items"],
            [
                {"ip": "10.237.30.32", "port": 12002},
                {"ip": "10.237.30.32", "port": 12009},
                {"ip": "139.196.241.63", "port": 34002},
                {"ip": "139.196.241.63", "port": 34009},
            ],
        )
        self.assertNotIn({"ip": "139.196.241.63", "port": 12002}, payload["items"])

    def test_display_destination_label_is_parsed_as_rule_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            address_text = "address 1 10.237.30.32 mask 32\n"
            public = self.write_file(root, "public.out", address_text)
            internet = self.write_file(root, "internet.out", address_text)
            private = self.write_file(root, "private.out", address_text)
            application_details = (
                "Application UDA_TS_legacy Information:\n"
                "Rule Name : 1\n"
                "Destination : 10.237.30.32/32\n"
                "Port : 8010\n"
            )
            application_group = (
                "application-group name UDG_TradeServers\n"
                "add application UDA_TS_legacy\n"
            )

            payload = snapshot_parser.build_port_snapshot(
                [
                    {"vsystem": "public", "path": public},
                    {"vsystem": "Internet", "path": internet},
                    {"vsystem": "private", "path": private},
                ],
                "",
                application_details,
                application_group,
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(payload["items"], [{"ip": "10.237.30.32", "port": 8010}])

    def test_non_prefixed_group_member_rules_are_split_by_rule_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            address_text = (
                "address 1 211.95.106.242 mask 32\n"
                "address 2 101.230.216.138 mask 32\n"
            )
            public = self.write_file(root, "public.out", address_text)
            internet = self.write_file(root, "internet.out", address_text)
            private = self.write_file(root, "private.out", address_text)
            full_config = (
                "user-defined-application name UD_211.95.106.242101.230.216.138\n"
                " rule name 1\n"
                "  ip-address 211.95.106.242 32\n"
                "  port 12009\n"
                "  port 12002\n"
                " rule name 4\n"
                "  ip-address 211.95.106.242 32\n"
                "  ip-address 101.230.216.138 32\n"
                "  port 45447\n"
                "  port 45448\n"
                " rule name 5\n"
                "  ip-address 211.95.106.242 32\n"
                "  ip-address 101.230.216.138 32\n"
                "  port 32042\n"
                "  port 32043\n"
                "  port 32047\n"
                "  port 32048\n"
                "application-group name UDG_TradeServers\n"
                " add application UD_211.95.106.242101.230.216.138\n"
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
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(
            payload["items"],
            [
                {"ip": "101.230.216.138", "port": 32042},
                {"ip": "101.230.216.138", "port": 32043},
                {"ip": "101.230.216.138", "port": 32047},
                {"ip": "101.230.216.138", "port": 32048},
                {"ip": "101.230.216.138", "port": 45447},
                {"ip": "101.230.216.138", "port": 45448},
                {"ip": "211.95.106.242", "port": 12002},
                {"ip": "211.95.106.242", "port": 12009},
                {"ip": "211.95.106.242", "port": 32042},
                {"ip": "211.95.106.242", "port": 32043},
                {"ip": "211.95.106.242", "port": 32047},
                {"ip": "211.95.106.242", "port": 32048},
                {"ip": "211.95.106.242", "port": 45447},
                {"ip": "211.95.106.242", "port": 45448},
            ],
        )
        self.assertNotIn({"ip": "101.230.216.138", "port": 12002}, payload["items"])

    def test_standard_application_name_does_not_supply_rule_ip_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            address_text = "address 1 192.168.66.22 mask 32\n"
            public = self.write_file(root, "public.out", address_text)
            internet = self.write_file(root, "internet.out", address_text)
            private = self.write_file(root, "private.out", address_text)
            full_config = (
                "user-defined-application name UDA_TS_192.168.66.22_2\n"
                " rule name 1\n"
                "  port 12003\n"
                "application-group name UDG_TradeServers\n"
                " add application UDA_TS_192.168.66.22_2\n"
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
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(payload["items"], [])

    def test_standard_application_name_still_uses_rule_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            address_text = "address 1 192.168.66.22 mask 32\n"
            public = self.write_file(root, "public.out", address_text)
            internet = self.write_file(root, "internet.out", address_text)
            private = self.write_file(root, "private.out", address_text)
            full_config = (
                "user-defined-application name UDA_TS_192.168.66.22_2\n"
                " rule name 1\n"
                "  ip-address 192.168.66.22 32\n"
                "  port 12003\n"
                "application-group name UDG_TradeServers\n"
                " add application UDA_TS_192.168.66.22_2\n"
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
                "UDA_TS_",
                "private",
                "UDG_TradeServers",
            )

        self.assertEqual(payload["items"], [{"ip": "192.168.66.22", "port": 12003}])


if __name__ == "__main__":
    unittest.main()
