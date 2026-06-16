from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RoleStaticTests(unittest.TestCase):
    def test_application_upper_limit_error_is_not_whitelisted(self) -> None:
        application_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/application.yml"
        ).read_text()

        self.assertNotIn(
            "'upper limit' not in application_config_result.stdout",
            application_yml,
        )
        self.assertIn("regex_replace", application_yml)
        self.assertIn("already exist in the application group", application_yml)

    def test_application_uses_structured_additive_port_plan(self) -> None:
        application_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/application.yml"
        ).read_text()

        self.assertIn("extract_usg_application_names.py", application_yml)
        self.assertIn("application_plan.effective_ports", application_yml)
        self.assertIn("Replace old applications with merged port plan in one SSH session", application_yml)
        self.assertIn("display application name", (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/templates/query_application_details.cli.j2"
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
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/address_vsystem.yml"
        ).read_text()
        remove_address_yml = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/tasks/remove_address_vsystem.yml"
        ).read_text()

        self.assertIn("Reuse existing address-set state", address_yml)
        self.assertIn("when: not address_exists_before | bool", address_yml)
        self.assertIn("Reuse absent address-set state", remove_address_yml)
        self.assertIn("when: address_exists_before_remove | bool", remove_address_yml)

    def test_remote_mutations_set_firewall_mutated(self) -> None:
        task_files = [
            "address_vsystem.yml",
            "remove_address_vsystem.yml",
            "application.yml",
            "remove_application.yml",
        ]

        for task_file in task_files:
            task_text = (
                PROJECT_ROOT / "roles/usg6000e_trade_access/tasks" / task_file
            ).read_text()
            self.assertIn("firewall_mutated: true", task_text)

    def test_deny_uses_structured_application_name_parser(self) -> None:
        deny_yml = (
            PROJECT_ROOT / "roles/usg6000e_trade_access/tasks/deny.yml"
        ).read_text()
        discovery_template = (
            PROJECT_ROOT
            / "roles/usg6000e_trade_access/templates/query_applications_by_ip.cli.j2"
        ).read_text()

        self.assertIn("extract_usg_application_names.py", deny_yml)
        self.assertIn("display current-configuration | include {{ base_app_name }}", discovery_template)


if __name__ == "__main__":
    unittest.main()
