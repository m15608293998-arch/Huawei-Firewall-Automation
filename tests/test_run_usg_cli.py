import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = PROJECT_ROOT / "roles/usg6000e_trade_access/files/run_usg_cli.py"
SPEC = importlib.util.spec_from_file_location("run_usg_cli", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)


class FakeChild:
    def __init__(self, events: list[tuple[int, str, str]]) -> None:
        self.events = list(events)
        self.before = ""
        self.after = ""
        self.sent = []

    def expect(self, patterns, timeout):
        index, before, after = self.events.pop(0)
        self.before = before
        self.after = after
        return index

    def send(self, value: str) -> None:
        self.sent.append(value)


class SequencedChild(FakeChild):
    def __init__(self, outputs: list[str]) -> None:
        self.outputs = list(outputs)
        super().__init__([])


def make_args(**kwargs):
    defaults = {
        "host": "192.168.6.54",
        "user": "admin",
        "identity_file": "/tmp/firewall_id",
        "password_env_var": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class EngineCommitTests(unittest.TestCase):
    def test_build_ssh_cmd_uses_publickey_auth_when_identity_file_is_set(self) -> None:
        ssh_cmd = RUNNER.build_ssh_cmd(make_args())

        self.assertIn("-i /tmp/firewall_id", ssh_cmd)
        self.assertIn("-o PreferredAuthentications=publickey", ssh_cmd)
        self.assertIn("-o PasswordAuthentication=no", ssh_cmd)

    def test_build_ssh_cmd_uses_password_auth_when_password_env_var_is_set(self) -> None:
        ssh_cmd = RUNNER.build_ssh_cmd(
            make_args(identity_file=None, password_env_var="USG6000E_DEVICE_PASSWORD")
        )

        self.assertIn("-o PreferredAuthentications=password,keyboard-interactive", ssh_cmd)
        self.assertIn("-o PubkeyAuthentication=no", ssh_cmd)
        self.assertIn("-o PasswordAuthentication=yes", ssh_cmd)
        self.assertNotIn("-i /tmp/firewall_id", ssh_cmd)

    def test_load_password_from_env_reads_expected_variable(self) -> None:
        with patch.dict("os.environ", {"USG6000E_DEVICE_PASSWORD": "secret"}, clear=False):
            password = RUNNER.load_password_from_env(
                make_args(identity_file=None, password_env_var="USG6000E_DEVICE_PASSWORD")
            )

        self.assertEqual(password, "secret")

    def test_load_password_from_env_rejects_missing_value(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "not set or empty"):
                RUNNER.load_password_from_env(
                    make_args(identity_file=None, password_env_var="USG6000E_DEVICE_PASSWORD")
                )

    def test_establish_ssh_session_sends_password_once(self) -> None:
        child = FakeChild(
            [
                (3, "", "admin@192.168.6.54's password:"),
                (0, "", "<Huawei>"),
            ]
        )

        with patch.object(RUNNER.time, "sleep"):
            output = RUNNER.establish_ssh_session(child, 60, password="secret")

        self.assertEqual(child.sent, ["secret\r"])
        self.assertIn("<Huawei>", output)

    def test_establish_ssh_session_rejects_unconfigured_password_prompt(self) -> None:
        child = FakeChild([(3, "", "Password:")])

        with self.assertRaisesRegex(RuntimeError, "password authentication was not configured"):
            RUNNER.establish_ssh_session(child, 60, password=None)

    def test_cli_command_delays_are_reduced(self) -> None:
        self.assertEqual(RUNNER.CLI_SEND_DELAY, 0.1)
        self.assertEqual(RUNNER.CLI_COMMAND_SETTLE_DELAY, 0.05)

    def test_engine_commit_uses_default_timeout(self) -> None:
        self.assertEqual(
            RUNNER.command_timeout("engine configuration commit", 60),
            60,
        )

    def test_engine_commit_immediate_failure_raises(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "rejected commit"):
            RUNNER.ensure_engine_commit_accepted(
                "Info: Engine configuration commit failed."
            )

    def test_engine_commit_already_complete_returns_immediately(self) -> None:
        output = RUNNER.wait_for_engine_commit_completion(
            SequencedChild([]),
            "Info: The submission of the compilation is unnecessary.\n[firewall]",
            60,
        )

        self.assertIn("compilation is unnecessary", output)

    def test_engine_commit_pending_is_polled_until_complete(self) -> None:
        child = SequencedChild([])

        with patch.object(
            RUNNER,
            "run_command_with_busy_retry",
            side_effect=[
                "Info: The operation may last several minutes, please wait.\n[firewall]",
                "Info: The submission of the compilation is unnecessary.\n[firewall]",
            ],
        ) as run_command, patch.object(RUNNER.time, "sleep"):
            output = RUNNER.wait_for_engine_commit_completion(
                child,
                "Info: The operation may last several minutes, please wait.\n[firewall]",
                60,
                max_wait=180,
                poll_interval=0,
            )

        self.assertEqual(run_command.call_count, 2)
        self.assertIn("Rechecking firewall security engine", output)
        self.assertIn("compilation is unnecessary", output)

    def test_engine_commit_unknown_state_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unknown commit state"):
            RUNNER.wait_for_engine_commit_completion(
                SequencedChild([]),
                "Info: Commit request accepted.\n[firewall]",
                60,
            )

    def test_engine_commit_timeout_raises(self) -> None:
        pending = (
            "Info: The operation may last several minutes, please wait.\n[firewall]"
        )

        with patch.object(RUNNER.time, "monotonic", side_effect=[0, 0, 0, 2]), patch.object(
            RUNNER.time,
            "sleep",
        ), patch.object(
            RUNNER,
            "run_command_with_busy_retry",
            return_value=pending,
        ):
            with self.assertRaisesRegex(RuntimeError, "did not finish"):
                RUNNER.wait_for_engine_commit_completion(
                    SequencedChild([]),
                    pending,
                    60,
                    max_wait=1,
                    poll_interval=0,
                )

    def test_device_busy_command_is_retried(self) -> None:
        child = SequencedChild([])
        busy = (
            "The system is busy in saving or comparing the current "
            "configuration. Please wait..."
        )

        with patch.object(
            RUNNER,
            "expect_prompt_or_more",
            side_effect=[busy, "[firewall-address-set]"],
        ), patch.object(RUNNER.time, "sleep"):
            output = RUNNER.run_command_with_busy_retry(
                child,
                "ip address-set test type object",
                60,
                max_retries=2,
                retry_delay=0,
            )

        self.assertEqual(len(child.sent), 2)
        self.assertIn("Firewall is busy", output)

    def test_device_busy_retry_exhaustion_fails(self) -> None:
        child = SequencedChild([])
        busy = (
            "The system is busy in saving or comparing the current "
            "configuration. Please wait..."
        )

        with patch.object(
            RUNNER,
            "expect_prompt_or_more",
            side_effect=[busy, busy],
        ), patch.object(RUNNER.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "remained busy"):
                RUNNER.run_command_with_busy_retry(
                    child,
                    "ip address-set test type object",
                    60,
                    max_retries=1,
                    retry_delay=0,
                )


if __name__ == "__main__":
    unittest.main()
