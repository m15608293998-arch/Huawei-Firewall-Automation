from pathlib import Path
import unittest

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RoleStaticTests(unittest.TestCase):
    def test_production_resource_names_and_application_capacity(self) -> None:
        config = yaml.safe_load((PROJECT_ROOT / "group_vars/all.yml").read_text())

        self.assertEqual(
            [context["name"] for context in config["address_vsystems"]],
            ["public", "Internet", "private"],
        )
        self.assertEqual(
            {
                context["address_set_name"]
                for context in config["address_vsystems"]
            },
            {"TraderServers-DirectAccess-IPs"},
        )
        self.assertEqual(config["application_vsystem"], "private")
        self.assertEqual(
            config["user_defined_application"]["name_prefix"],
            "UD_TServe_",
        )
        self.assertEqual(
            config["user_defined_application"]["application_group_name"],
            "UDG_TradeServers",
        )
        self.assertEqual(config["rule_port_limit"], 4)
        self.assertEqual(config["application_rule_limit"], 8)

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
        self.assertGreaterEqual(
            main_yml.count("firewall_mutated | default(false) | bool"),
            3,
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

    def test_remote_mutations_set_firewall_mutated(self) -> None:
        task_files = [
            "address/add_member.yml",
            "address/remove_member.yml",
            "application/configure_ports.yml",
            "application/remove_object.yml",
        ]

        for task_file in task_files:
            task_text = (
                PROJECT_ROOT / "roles/usg6000e_trade_access/tasks" / task_file
            ).read_text()
            self.assertIn("firewall_mutated: true", task_text)

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
