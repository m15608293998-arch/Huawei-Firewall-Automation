from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RoleStaticTests(unittest.TestCase):
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
        self.assertIn("Replace old applications with merged port plan in one SSH session", application_yml)
        self.assertIn("display application name", (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/templates/application/query_details.cli.j2"
        ).read_text())

    def test_security_engine_commit_runs_in_application_vsystem(self) -> None:
        main_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/main.yml"
        ).read_text()

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
        main_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/main.yml"
        ).read_text()

        self.assertIn("'allow_ip'", main_yml)
        self.assertIn("'allow_ports'", main_yml)
        self.assertIn("'deny_ports'", main_yml)
        self.assertIn("'deny_ip'", main_yml)
        self.assertIn("access/allow_ip.yml", main_yml)
        self.assertIn("access/allow_ports.yml", main_yml)
        self.assertIn("access/deny_ports.yml", main_yml)
        self.assertIn("access/deny_ip.yml", main_yml)

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
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/snapshot.yml",
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
        self.assertIn("tasks_from: \"{{ trade_access_tasks_from | default('main') }}\"", playbook)
        self.assertFalse((PROJECT_ROOT / "playbooks/trade_server_snapshot.yml").exists())


if __name__ == "__main__":
    unittest.main()
