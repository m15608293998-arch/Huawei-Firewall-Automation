import os
import re
import shlex
import stat
from pathlib import Path


ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".runtime" / "trade-access.env"


class EnvironmentFileError(ValueError):
    pass


def runtime_env_file() -> Path:
    configured = os.environ.get("TRADE_ACCESS_ENV_FILE")
    return Path(configured).expanduser() if configured else DEFAULT_ENV_FILE


def load_runtime_environment(path: Path | None = None) -> Path | None:
    env_path = path or runtime_env_file()
    if not env_path.exists():
        return None
    if not env_path.is_file():
        raise EnvironmentFileError(
            "Environment file is not a regular file: {0}".format(env_path)
        )

    mode = stat.S_IMODE(env_path.stat().st_mode)
    if mode & 0o077:
        raise EnvironmentFileError(
            "Environment file must not be accessible by group or others: "
            "{0} (mode {1:o}; expected 600)".format(env_path, mode)
        )

    for line_number, raw_line in enumerate(
        env_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, raw_value = line.partition("=")
        name = name.strip()
        if not separator or not ENV_NAME_PATTERN.fullmatch(name):
            raise EnvironmentFileError(
                "Invalid environment assignment at {0}:{1}".format(
                    env_path,
                    line_number,
                )
            )
        try:
            values = shlex.split(raw_value.strip(), comments=True, posix=True)
        except ValueError as exc:
            raise EnvironmentFileError(
                "Invalid quoted value at {0}:{1}".format(env_path, line_number)
            ) from exc
        if len(values) > 1:
            raise EnvironmentFileError(
                "Environment values containing spaces must be quoted at {0}:{1}".format(
                    env_path,
                    line_number,
                )
            )
        value = values[0] if values else ""
        os.environ.setdefault(name, value)
    return env_path
