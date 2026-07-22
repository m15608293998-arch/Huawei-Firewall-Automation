from pathlib import Path
import unittest

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_commented_production_config() -> dict:
    source = (PROJECT_ROOT / "group_vars/all.yml").read_text(encoding="utf-8")
    block = source.split("# BEGIN_PRODUCTION_CONFIG", 1)[1].split(
        "# END_PRODUCTION_CONFIG",
        1,
    )[0]
    yaml_lines = []
    for line in block.splitlines():
        if line == "#":
            yaml_lines.append("")
        elif line.startswith("# "):
            yaml_lines.append(line[2:])
    return yaml.safe_load("\n".join(yaml_lines))


class RoleStaticTests(unittest.TestCase):
    def test_role_uses_explicit_workflow_mode(self) -> None:
        main_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/main.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("firewall_workflow_mode_resolved", main_yml)
        self.assertIn("if access_request is defined", main_yml)
        self.assertIn(
            "when: firewall_workflow_mode_resolved == 'snapshot'",
            main_yml,
        )
        self.assertIn(
            "when: firewall_workflow_mode_resolved == 'access'",
            main_yml,
        )

    def test_test_profile_and_application_capacity(self) -> None:
        source = (PROJECT_ROOT / "group_vars/all.yml").read_text(encoding="utf-8")
        config = yaml.safe_load(source)
        test_profile = config["firewall_profiles"]["TEST-FW"]

        self.assertEqual(config["trade_access_api"]["firewall_targets"], ["TEST-FW"])
        self.assertEqual(config["trade_access_api"]["firewall_parallel_workers"], 3)
        self.assertEqual(config["trade_access_api"]["firewall_child_max_attempts"], 2)
        self.assertEqual(
            config["trade_access_api"]["firewall_reconcile_retry_seconds"],
            30,
        )
        self.assertTrue(config["enable_application_config"])
        self.assertTrue(config["commit_security_engine"])
        self.assertTrue(config["save_config"])
        self.assertEqual(
            [context["name"] for context in test_profile["address_vsystems"]],
            ["public", "Internet", "private"],
        )
        self.assertEqual(
            {
                context["address_set_name"]
                for context in test_profile["address_vsystems"]
            },
            {"TraderServers-DirectAccess-IPs"},
        )
        self.assertEqual(test_profile["application_vsystem"], "private")
        self.assertEqual(
            test_profile["user_defined_application"]["name_prefix"],
            "UD_TServe_",
        )
        self.assertEqual(
            test_profile["user_defined_application"]["application_group_name"],
            "UDG_TradeServers",
        )
        self.assertEqual(config["rule_port_limit"], 4)
        self.assertEqual(config["application_rule_limit"], 8)
        self.assertEqual(config["default_firewall_code"], "TEST-FW")
        self.assertNotIn("&test_", source)
        self.assertNotIn("*test_", source)

    def test_production_firewall_profiles_match_required_vsystem_topology(self) -> None:
        config = load_commented_production_config()
        profiles = config["firewall_profiles"]

        self.assertEqual(
            config["trade_access_api"]["firewall_targets"],
            ["PG-FW", "PG-FW-1", "IDC-FW"],
        )
        self.assertEqual(config["trade_access_api"]["firewall_parallel_workers"], 3)
        self.assertEqual(config["trade_access_api"]["firewall_child_max_attempts"], 2)
        self.assertEqual(
            config["trade_access_api"]["firewall_reconcile_retry_seconds"],
            30,
        )
        self.assertEqual(config["rule_port_limit"], 4)
        self.assertEqual(config["application_rule_limit"], 8)
        self.assertTrue(config["enable_application_config"])
        self.assertTrue(config["commit_security_engine"])
        self.assertTrue(config["save_config"])
        self.assertEqual(
            [item["name"] for item in profiles["PG-FW"]["address_vsystems"]],
            ["public", "private", "Internet"],
        )
        self.assertEqual(profiles["PG-FW"]["application_vsystem"], "private")
        self.assertEqual(
            [item["name"] for item in profiles["PG-FW-1"]["address_vsystems"]],
            ["public"],
        )
        self.assertEqual(profiles["PG-FW-1"]["application_vsystem"], "public")
        self.assertEqual(
            [item["name"] for item in profiles["IDC-FW"]["address_vsystems"]],
            ["private", "Internet"],
        )
        self.assertEqual(profiles["IDC-FW"]["application_vsystem"], "private")
        expected_device_values = {
            "PG-FW": ("<PG_FW_MGMT_IP>", "<PG_FW_USER>", "<PG_FW_PASSWORD>"),
            "PG-FW-1": (
                "<PG_FW_1_MGMT_IP>",
                "<PG_FW_1_USER>",
                "<PG_FW_1_PASSWORD>",
            ),
            "IDC-FW": ("<IDC_FW_MGMT_IP>", "<IDC_FW_USER>", "<IDC_FW_PASSWORD>"),
        }
        for firewall_code, expected_values in expected_device_values.items():
            device = profiles[firewall_code]["firewall_device"]
            self.assertEqual(
                (device["device_host"], device["device_user"], device["device_password"]),
                expected_values,
            )

    def test_production_environment_template_excludes_firewall_connections(self) -> None:
        environment_template = (
            PROJECT_ROOT / "config/production/trade-access.env.example"
        ).read_text(encoding="utf-8")
        for variable_name in (
            "PG_FW_DEVICE_HOST",
            "PG_FW_DEVICE_USER",
            "PG_FW_DEVICE_PASSWORD",
            "PG_FW_1_DEVICE_HOST",
            "PG_FW_1_DEVICE_USER",
            "PG_FW_1_DEVICE_PASSWORD",
            "IDC_FW_DEVICE_HOST",
            "IDC_FW_DEVICE_USER",
            "IDC_FW_DEVICE_PASSWORD",
        ):
            self.assertNotIn(variable_name + "=", environment_template)

        self.assertIn("TRADE_ACCESS_API_AUTH_ENABLED=true", environment_template)
        self.assertIn("TRADE_ACCESS_API_KEYCLOAK_SERVER_URL=", environment_template)
        self.assertNotIn("TRADE_ACCESS_API_FIREWALL_TARGETS=", environment_template)
        self.assertNotIn(
            "TRADE_ACCESS_API_FIREWALL_PARALLEL_WORKERS=",
            environment_template,
        )
        self.assertNotIn(
            "TRADE_ACCESS_API_FIREWALL_CHILD_MAX_ATTEMPTS=",
            environment_template,
        )

    def test_application_upper_limit_error_is_not_whitelisted(self) -> None:
        application_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/application/configure_ports.yml"
        ).read_text()

        self.assertNotIn(
            "'upper limit' not in application_config_result.stdout",
            application_yml,
        )
        self.assertIn("regex_replace", application_yml)
        self.assertIn("already exist in the application group", application_yml)

    def test_application_uses_structured_additive_port_plan(self) -> None:
        application_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/application/configure_ports.yml"
        ).read_text()

        self.assertIn("extract_usg_application_names.py", application_yml)
        self.assertIn("application_plan.effective_ports", application_yml)
        self.assertIn("incremental_ports.cli.j2", application_yml)
        self.assertIn("Apply incremental application port changes in one SSH session", application_yml)
        self.assertNotIn("replace_batch.cli.j2", application_yml)
        self.assertIn("display application name", (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/templates/application/query_details.cli.j2"
        ).read_text())

    def test_incremental_port_template_returns_to_sa_after_group_changes(self) -> None:
        template = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/templates/application/incremental_ports.cli.j2"
        ).read_text()

        add_to_group_block = template.split("{% elif operation.type == 'add_to_group' %}", 1)[1]
        add_to_group_block = add_to_group_block.split("{% elif operation.type == 'remove_application' %}", 1)[0]
        remove_application_block = template.split("{% elif operation.type == 'remove_application' %}", 1)[1]
        remove_application_block = remove_application_block.split("{% endif %}", 1)[0]

        self.assertIn("application-group name", add_to_group_block)
        self.assertIn("add application {{ operation.app_name }}\nquit\nsa", add_to_group_block)
        self.assertIn("undo add application {{ operation.app_name }}\nquit\nsa", remove_application_block)
        self.assertIn("sa\nundo user-defined-application name {{ operation.app_name }}", remove_application_block)

    def test_incremental_port_template_can_rewrite_rule_ports(self) -> None:
        template = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/templates/application/incremental_ports.cli.j2"
        ).read_text()

        rewrite_block = template.split("{% elif operation.type == 'replace_rule_ports' %}", 1)[1]
        rewrite_block = rewrite_block.split("{% elif operation.type == 'remove_ports' %}", 1)[0]

        self.assertIn("rule name {{ operation.rule_name }}", rewrite_block)
        self.assertIn("{% for port in operation.old_ports %}\nundo port {{ port }}", rewrite_block)
        self.assertIn("{% for port in operation.ports %}\nport {{ port }}", rewrite_block)

    def test_security_engine_commit_runs_in_application_vsystem(self) -> None:
        main_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/access/main.yml"
        ).read_text()

        self.assertIn("Validate Huawei application naming configuration", main_yml)
        self.assertIn("is match('^UD_')", main_yml)
        self.assertIn("firewall_device.auth_type", main_yml)
        self.assertIn("--password-env-var", main_yml)
        self.assertIn("switch vsys {{ application_vsystem }}", main_yml)
        self.assertIn("engine configuration commit", main_yml)
        self.assertIn("firewall_mutated: false", main_yml)
        self.assertIn("address_mutated: false", main_yml)
        self.assertIn("application_mutated: false", main_yml)
        self.assertIn(
            "application_mutated | default(false) | bool and commit_security_engine",
            main_yml,
        )

    def test_address_post_validation_only_runs_after_mutation(self) -> None:
        address_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/address/add_member.yml"
        ).read_text()
        remove_address_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/address/remove_member.yml"
        ).read_text()

        self.assertIn("Reuse existing address-set state", address_yml)
        self.assertIn("when: not address_exists_before | bool", address_yml)
        self.assertIn("Reuse absent address-set state", remove_address_yml)
        self.assertIn("when: address_exists_before_remove | bool", remove_address_yml)

    def test_remote_mutations_set_scoped_mutation_flags(self) -> None:
        task_files = {
            "address/add_member.yml": "address_mutated: true",
            "address/remove_member.yml": "address_mutated: true",
            "application/configure_ports.yml": "application_mutated: true",
            "application/remove_object.yml": "application_mutated: true",
        }

        for task_file, scoped_flag in task_files.items():
            task_text = (
                PROJECT_ROOT / "roles/usg6000e_trade_access/tasks" / task_file
            ).read_text()
            self.assertIn("firewall_mutated: true", task_text)
            self.assertIn(scoped_flag, task_text)

    def test_full_deny_removes_ports_before_removing_ip(self) -> None:
        deny_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/access/deny.yml"
        ).read_text()
        deny_all_ports_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/application/remove_all_for_ip.yml"
        ).read_text()
        discovery_template = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/templates/application/query_by_ip.cli.j2"
        ).read_text()

        self.assertLess(
            deny_yml.index("application/remove_all_for_ip.yml"),
            deny_yml.index("access/deny_ip.yml"),
        )
        self.assertIn("extract_usg_application_names.py", deny_all_ports_yml)
        self.assertIn("display current-configuration | include {{ base_app_name }}", discovery_template)

    def test_split_actions_have_dedicated_task_files(self) -> None:
        access_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/access/main.yml"
        ).read_text()

        self.assertIn("'allow_ip'", access_yml)
        self.assertIn("'allow_ports'", access_yml)
        self.assertIn("'deny_ports'", access_yml)
        self.assertIn("'deny_ip'", access_yml)
        self.assertIn("access/allow_ip.yml", access_yml)
        self.assertIn("access/allow_ports.yml", access_yml)
        self.assertIn("access/deny_ports.yml", access_yml)
        self.assertIn("access/deny_ip.yml", access_yml)

    def test_ip_deny_requires_ports_to_be_removed_first(self) -> None:
        deny_ip_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/access/deny_ip.yml"
        ).read_text()
        validate_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/application/validate_absent_for_ip.yml"
        ).read_text()

        self.assertLess(
            deny_ip_yml.index("application/validate_absent_for_ip.yml"),
            deny_ip_yml.index("address/remove_member.yml"),
        )
        self.assertIn("Reject IP deny while ports still exist", validate_yml)
        self.assertIn("Remove its ports first or use the full deny workflow", validate_yml)

    def test_port_operation_ip_validation_uses_address_parser_arguments(self) -> None:
        validate_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/address/validate_present.yml"
        ).read_text()

        self.assertIn('"--ip"', validate_yml)
        self.assertNotIn('"--target-ip"', validate_yml)

    def test_snapshot_workflow_is_read_only(self) -> None:
        paths = [
            PROJECT_ROOT / "playbooks/trade_server_access.yml",
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/main.yml",
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/snapshot/main.yml",
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/snapshot/address_vsystem.yml",
            PROJECT_ROOT / "roles/usg6000e_trade_access/templates/snapshot/query_address_inventory.cli.j2",
            PROJECT_ROOT / "roles/usg6000e_trade_access/templates/snapshot/query_application_full_inventory.cli.j2",
        ]

        combined = "\n".join(path.read_text() for path in paths)
        self.assertIn("display this", combined)
        self.assertIn("display current-configuration", combined)
        self.assertNotIn("add application", combined)
        self.assertNotIn("undo ", combined)
        self.assertNotIn("engine configuration commit", combined)
        self.assertNotIn("\nsave\n", combined)

    def test_access_playbook_is_single_role_entrypoint(self) -> None:
        playbook = (
            PROJECT_ROOT / "playbooks/trade_server_access.yml"
        ).read_text()
        self.assertIn("name: usg6000e_trade_access", playbook)
        self.assertNotIn("tasks_from:", playbook)
        self.assertFalse((PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/snapshot.yml").exists())
        self.assertFalse((PROJECT_ROOT / "playbooks/trade_server_snapshot.yml").exists())


if __name__ == "__main__":
    unittest.main()
