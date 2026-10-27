#!/usr/bin/env python3.12
import argparse
import pathlib
import re
import sys
import time
import os
import uuid
import pexpect


os.environ["LANG"] = "en_US.UTF-8"
os.environ["LC_ALL"] = "en_US.UTF-8"

# Login discovers the device identity; subsequent prompts must belong to that
# device and occupy the entire last line, including across view changes.
PROMPT_PATTERN = r"(?m)^(?:HRP_[MS][ \t]*)?(?:<[^<>\[\]\s]+>|\[[^<>\[\]\s]+\])[ \t\r]*\Z"
MORE_PATTERN = r"(---- More ----|More:|<--- More --->|--- More ---)"
CONFIRM_PATTERN = r"(Are you sure.*\([Yy]/[Nn]\).*|Are you sure.*\(y/n\)\[n\]:|Are you sure.*\[Y/N\].*|continue\? \[Y/N\].*)"
PASSWORD_PROMPT_PATTERN = r"(?i)(?:password|passphrase).*:"
AUTH_FAILURE_PATTERN = r"(?i)(Permission denied|Authentication failed|Access denied)"
ENGINE_COMMIT_FAILURE_PATTERN = (
    r"(?i)(Error:.*|(?:engine|configuration|commit|compil).*(?:fail|failed|error))"
)
ENGINE_COMMIT_PENDING_PATTERN = re.compile(
    r"The operation may last several minutes, please wait\.",
    re.IGNORECASE,
)
ENGINE_COMMIT_COMPLETE_PATTERN = re.compile(
    r"The submission of the compilation is unnecessary\.",
    re.IGNORECASE,
)
DEVICE_BUSY_PATTERN = re.compile(
    r"The system is busy in saving or comparing the current configuration\.\s*"
    r"Please wait\.\.\.",
    re.IGNORECASE,
)
DEVICE_BUSY_RETRY_DELAY = 5
DEVICE_BUSY_MAX_RETRIES = 24
ENGINE_COMMIT_POLL_INTERVAL = 2
ENGINE_COMMIT_MAX_WAIT = 180
CLI_SEND_DELAY = 0.1
CLI_COMMAND_SETTLE_DELAY = 0.05
ALLOWED_CLI_ERROR_LINES = {
    "Error: The application is already exist in the application group.",
}
CLI_ERROR_MARKERS = (
    "Unrecognized command found",
    "Too many parameters",
    "Wrong parameter found",
    "Ambiguous command found",
)


def remaining_timeout(child, timeout):
    deadline = getattr(child, "execution_deadline", None)
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("CLI execution deadline exceeded.")
    return min(timeout, remaining)


def sleep_with_deadline(child, seconds):
    time.sleep(remaining_timeout(child, seconds))


def send_with_deadline(child, value):
    sleep_with_deadline(child, CLI_SEND_DELAY)
    remaining_timeout(child, 1)
    child.send(value)


def parse_ssh_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("SSH port must be an integer.") from exc

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("SSH port must be between 1 and 65535.")

    return port


def read_commands(cli_file):
    commands = []
    cli_path = pathlib.Path(cli_file).expanduser()

    for line in cli_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        commands.append((str(cli_path), line))

    return commands


def read_commands_from_files(cli_files):
    all_commands = []

    for cli_file in cli_files:
        all_commands.extend(read_commands(cli_file))

    return all_commands


def read_command_echo(child, cmd, timeout):
    # A wrapped continuation may itself look like a device prompt. Read the
    # entire known command before interpreting any result prompt.
    wrapped_echo = r"(?:\r*\n)?".join(re.escape(char) for char in cmd)
    child.expect(
        r"(?m)(?P<prefix>(?:^|[>\]])[ \t]*)" + wrapped_echo + r"[\r\n]+",
        timeout=remaining_timeout(child, timeout),
    )
    prefix = child.match.group("prefix")
    return child.before + prefix, child.after[len(prefix):]


def remember_device_prompt(child, prompt):
    prompt = re.sub(r"^HRP_[MS][ \t]*", "", prompt.strip())
    identity = prompt[1:-1].lstrip("~*")
    hostname = re.escape(identity)
    view = r"(?:-[^<>\[\]\r\n]+)?"
    child.prompt_pattern = rf"(?m)^(?:HRP_[MS][ \t]*)?(?:<{hostname}{view}>|\[[~*]?{hostname}{view}\])[ \t\r]*\Z"


def prompt_is_settled(child):
    # A prompt-shaped prefix may be only the first chunk of an echoed command.
    # A TIMEOUT-only expect preserves any newly read bytes for the next expect.
    child.expect([pexpect.TIMEOUT], timeout=remaining_timeout(child, CLI_COMMAND_SETTLE_DELAY))
    return not child.before.strip()


def expect_prompt_or_more(child, timeout):
    output = []

    while True:
        # 每次命令都读到设备提示符为止，中途分页或确认直接自动处理。
        index = child.expect(
            [getattr(child, "prompt_pattern", PROMPT_PATTERN), MORE_PATTERN, CONFIRM_PATTERN],
            timeout=remaining_timeout(child, timeout),
        )
        output.append(child.before)
        output.append(child.after)

        if index == 0:
            if prompt_is_settled(child):
                return "".join(output)
            continue

        if index == 1:
            send_with_deadline(child, " ")
            sleep_with_deadline(child, 0.2)
            continue

        if index == 2:
            send_with_deadline(child, "y\r")
            sleep_with_deadline(child, 0.5)
            continue


def build_ssh_cmd(args):
    control_dir = pathlib.Path.home() / ".ssh" / "cm"
    control_dir.mkdir(mode=0o700, exist_ok=True)
    control_path = str(control_dir / "usg6000e-%C")

    if args.identity_file:
        # key 模式关闭密码认证，避免本机 agent 或交互密码影响验证结果。
        identity_file = str(pathlib.Path(args.identity_file).expanduser())
        auth_args = (
            f"-i {identity_file} "
            "-o PreferredAuthentications=publickey "
            "-o PasswordAuthentication=no "
        )
    else:
        # 密码模式关闭公钥认证，确保真正走账号密码登录华为设备。
        auth_args = (
            "-o PreferredAuthentications=password,keyboard-interactive "
            "-o PubkeyAuthentication=no "
            "-o PasswordAuthentication=yes "
            "-o KexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 "
        )

    ssh_cmd = (
        "ssh -tt "
        "-F /dev/null "
        f"-p {args.port} "
        f"{auth_args}"
        "-o ControlMaster=auto "
        f"-o ControlPath={control_path} "
        "-o ControlPersist=120 "
        "-o PubkeyAcceptedKeyTypes=+ssh-rsa "
        "-o HostkeyAlgorithms=+ssh-rsa "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        f"{args.user}@{args.host}"
    )

    return ssh_cmd


def load_password_from_env(args):
    if not args.password_env_var:
        return None

    password = os.environ.get(args.password_env_var)
    if not password:
        raise RuntimeError(
            "SSH password environment variable "
            f"{args.password_env_var} is not set or empty."
        )

    return password


def establish_ssh_session(child, timeout, password=None):
    output = []
    password_sent = False

    while True:
        # 登录阶段比普通命令多处理密码提示和认证失败提示。
        index = child.expect(
            [
                PROMPT_PATTERN,
                MORE_PATTERN,
                CONFIRM_PATTERN,
                PASSWORD_PROMPT_PATTERN,
                AUTH_FAILURE_PATTERN,
            ],
            timeout=remaining_timeout(child, timeout),
        )
        output.append(child.before)
        output.append(child.after)

        if index == 0:
            prompt = child.after
            if prompt_is_settled(child):
                remember_device_prompt(child, prompt)
                return "".join(output)
            continue

        if index == 1:
            send_with_deadline(child, " ")
            sleep_with_deadline(child, 0.2)
            continue

        if index == 2:
            send_with_deadline(child, "y\r")
            sleep_with_deadline(child, 0.5)
            continue

        if index == 3:
            if password is None:
                raise RuntimeError(
                    "SSH requested a password, but password authentication "
                    "was not configured."
                )
            if password_sent:
                raise RuntimeError("SSH password prompt repeated; authentication failed.")
            send_with_deadline(child, password + "\r")
            password_sent = True
            sleep_with_deadline(child, 0.5)
            continue

        raise RuntimeError("SSH authentication failed: " + child.after.strip())


def command_timeout(cmd, default_timeout):
    slow_commands = {"save", "save force"}

    if cmd.strip().lower() in slow_commands:
        return 180

    return default_timeout


def ensure_engine_commit_accepted(command_output):
    if re.search(ENGINE_COMMIT_FAILURE_PATTERN, command_output, re.IGNORECASE):
        raise RuntimeError(
            "Firewall security engine rejected commit: " + command_output.strip()
        )


def ensure_cli_command_accepted(source_file, cmd, command_output):
    for raw_line in command_output.splitlines():
        line = raw_line.strip()
        if not line or line in ALLOWED_CLI_ERROR_LINES:
            continue
        if line.startswith("Error:") or any(
            marker in line for marker in CLI_ERROR_MARKERS
        ):
            raise RuntimeError(
                f"Firewall rejected command {cmd!r} from {source_file}: {line}"
            )


def ensure_save_completed(command_output):
    # A returned prompt alone does not prove startup configuration was saved.
    if not re.search(
        r"(?i)(?:save the configuration successfully|configuration (?:has been |is )?saved successfully)",
        command_output,
    ) or re.search(r"(?i)\b(?:failed|failure)\b|Error:", command_output):
        raise RuntimeError("Firewall configuration save did not complete successfully: " + command_output.strip())


def wait_for_engine_commit_completion(
    child,
    initial_output,
    command_timeout_seconds,
    max_wait=ENGINE_COMMIT_MAX_WAIT,
    poll_interval=ENGINE_COMMIT_POLL_INTERVAL,
):
    output = [initial_output]
    ensure_engine_commit_accepted(initial_output)

    if ENGINE_COMMIT_COMPLETE_PATTERN.search(initial_output):
        return "".join(output)

    if not ENGINE_COMMIT_PENDING_PATTERN.search(initial_output):
        raise RuntimeError(
            "Firewall security engine returned an unknown commit state: "
            + initial_output.strip()
        )

    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        sleep_with_deadline(child, poll_interval)
        remaining = max(1, int(deadline - time.monotonic()))
        # Huawei 编译可能异步进行，用同一条 commit 命令轮询最终状态。
        poll_output = run_command_with_busy_retry(
            child,
            "engine configuration commit",
            min(command_timeout_seconds, remaining),
        )
        output.append(
            "\nINFO: Rechecking firewall security engine compilation state.\n"
        )
        output.append(poll_output)
        ensure_engine_commit_accepted(poll_output)

        if ENGINE_COMMIT_COMPLETE_PATTERN.search(poll_output):
            return "".join(output)

        if not ENGINE_COMMIT_PENDING_PATTERN.search(poll_output):
            raise RuntimeError(
                "Firewall security engine returned an unknown commit state: "
                + poll_output.strip()
            )

    raise RuntimeError(
        "Firewall security engine compilation did not finish within "
        f"{max_wait} seconds."
    )


def run_command_with_busy_retry(
    child,
    cmd,
    timeout,
    max_retries=DEVICE_BUSY_MAX_RETRIES,
    retry_delay=DEVICE_BUSY_RETRY_DELAY,
):
    output = []

    for attempt in range(max_retries + 1):
        send_with_deadline(child, cmd + "\r")
        echo = ""
        if getattr(child, "prompt_pattern", None):
            before, after = read_command_echo(child, cmd, timeout)
            echo = before + after
        command_output = echo + expect_prompt_or_more(child, timeout)
        if getattr(child, "prompt_pattern", None) and cmd.lower().startswith("display "):
            # Query data can contain the exact device prompt after wrapping.
            # The unpredictable echo of a read-only probe proves the preceding
            # query has completed, including any bytes after a false prompt.
            probe = "display current-configuration | include TRADE_ACCESS_BOUNDARY_" + uuid.uuid4().hex
            send_with_deadline(child, probe + "\r")
            pending_output, _ = read_command_echo(child, probe, timeout)
            command_output += pending_output
            probe_output = expect_prompt_or_more(child, timeout)
            ensure_cli_command_accepted("query boundary", probe, probe_output)
        output.append(command_output)

        if not DEVICE_BUSY_PATTERN.search(command_output):
            return "".join(output)

        # 保存/比较配置占用设备时等待重试，避免把临时 busy 当作任务失败。
        if attempt == max_retries:
            break

        output.append(
            f"\nINFO: Firewall is busy; retrying command in {retry_delay} seconds "
            f"({attempt + 1}/{max_retries}).\n"
        )
        sleep_with_deadline(child, retry_delay)

    raise RuntimeError(
        f"Firewall remained busy after {max_retries + 1} attempts while running: {cmd}"
    )


def prepare_cli_session(child, timeout):
    # Session-only setting: probe bytes must never be consumed as pager keys.
    command = "screen-length 0 temporary"
    output = run_command_with_busy_retry(child, command, timeout)
    ensure_cli_command_accepted("session setup", command, output)
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Run Huawei USG CLI commands through SSH."
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=parse_ssh_port, default=22)
    parser.add_argument("--user", required=True)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--identity-file")
    auth_group.add_argument("--password-env-var")

    cli_group = parser.add_mutually_exclusive_group(required=True)
    cli_group.add_argument(
        "--cli-file",
        help="Run commands from one CLI file. Compatible with old playbooks.",
    )
    cli_group.add_argument(
        "--cli-files",
        nargs="+",
        help="Run commands from multiple CLI files in one SSH session.",
    )

    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--total-timeout", type=float, default=900)
    args = parser.parse_args()
    if args.timeout <= 0 or args.total_timeout <= 0:
        parser.error("CLI timeouts must be positive.")
    deadline = time.monotonic() + args.total_timeout
    if os.environ.get("USG6000E_RUN_DEADLINE"):
        deadline = min(deadline, time.monotonic() + float(os.environ["USG6000E_RUN_DEADLINE"]) - time.time())
    if deadline <= time.monotonic():
        print("ERROR: CLI execution deadline exceeded before SSH started.", file=sys.stderr)
        sys.exit(4)

    if args.cli_file:
        cli_files = [args.cli_file]
    else:
        cli_files = args.cli_files

    commands = read_commands_from_files(cli_files)

    if not commands:
        print("ERROR: No CLI commands found.", file=sys.stderr)
        sys.exit(1)

    ssh_cmd = build_ssh_cmd(args)
    password = load_password_from_env(args)

    child = pexpect.spawn(
        ssh_cmd,
        encoding="utf-8",
        codec_errors="ignore",
        timeout=args.timeout,
        echo=False,
    )

    child.delaybeforesend = None
    child.execution_deadline = deadline
    child.setwinsize(200, 200)

    output = []
    current_source = None

    try:
        output.append(establish_ssh_session(child, args.timeout, password=password))

        # 登录后先发空回车，让设备 CLI 完成初始化
        sleep_with_deadline(child, 1)
        send_with_deadline(child, "\r")
        output.append(expect_prompt_or_more(child, args.timeout))
        output.append(prepare_cli_session(child, args.timeout))

        for source_file, cmd in commands:
            if source_file != current_source:
                current_source = source_file
                output.append(f"\n\n===== CLI FILE: {current_source} =====\n")

            wait_timeout = command_timeout(cmd, args.timeout)
            command_output = run_command_with_busy_retry(
                child,
                cmd,
                wait_timeout,
            )

            if cmd.strip().lower() == "engine configuration commit":
                # 安全引擎提交有自己的完成状态，不能只看命令返回提示符。
                command_output = wait_for_engine_commit_completion(
                    child,
                    command_output,
                    wait_timeout,
                )
            else:
                # Stop before later commands are sent in the wrong Huawei CLI view.
                ensure_cli_command_accepted(current_source, cmd, command_output)
                if cmd.strip().lower() in {"save", "save force"}:
                    ensure_save_completed(command_output)

            output.append("\n")
            output.append(command_output)

            sleep_with_deadline(child, CLI_COMMAND_SETTLE_DELAY)

        print("".join(output))
        child.close(force=True)
        sys.exit(0)

    except pexpect.TIMEOUT:
        print("ERROR: Timeout while waiting for Huawei prompt.", file=sys.stderr)
        print("Collected output:", file=sys.stderr)
        print("".join(output), file=sys.stderr)
        print("Last buffer:", file=sys.stderr)
        print(child.before, file=sys.stderr)
        child.close(force=True)
        sys.exit(2)

    except pexpect.EOF:
        print("ERROR: SSH session closed unexpectedly.", file=sys.stderr)
        print("Collected output:", file=sys.stderr)
        print("".join(output), file=sys.stderr)
        print("Last buffer:", file=sys.stderr)
        print(child.before, file=sys.stderr)
        child.close(force=True)
        sys.exit(3)

    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Collected output:", file=sys.stderr)
        print("".join(output), file=sys.stderr)
        child.close(force=True)
        sys.exit(4)


if __name__ == "__main__":
    main()
