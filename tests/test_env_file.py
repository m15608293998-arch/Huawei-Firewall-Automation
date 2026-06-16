import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api.env_file import EnvironmentFileError, load_runtime_environment


class RuntimeEnvironmentTests(unittest.TestCase):
    def test_secure_environment_file_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / "runtime.env"
            env_file.write_text(
                "TRADE_ACCESS_API_KEYCLOAK_SERVER_URL=http://keycloak:8080\n"
                "TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_SECRET='secret # value'\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            with patch.dict(os.environ, {}, clear=True):
                loaded = load_runtime_environment(env_file)
                self.assertEqual(loaded, env_file)
                self.assertEqual(
                    os.environ["TRADE_ACCESS_API_KEYCLOAK_SERVER_URL"],
                    "http://keycloak:8080",
                )
                self.assertEqual(
                    os.environ["TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_SECRET"],
                    "secret # value",
                )

    def test_existing_environment_value_takes_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / "runtime.env"
            env_file.write_text("SETTING=file-value\n", encoding="utf-8")
            env_file.chmod(0o600)
            with patch.dict(os.environ, {"SETTING": "process-value"}, clear=True):
                load_runtime_environment(env_file)
                self.assertEqual(os.environ["SETTING"], "process-value")

    def test_insecure_environment_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / "runtime.env"
            env_file.write_text("SETTING=value\n", encoding="utf-8")
            env_file.chmod(0o644)
            with self.assertRaises(EnvironmentFileError):
                load_runtime_environment(env_file)


if __name__ == "__main__":
    unittest.main()
