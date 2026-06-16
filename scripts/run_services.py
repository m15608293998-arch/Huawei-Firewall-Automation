#!/usr/bin/env python3.12
import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from api.env_file import load_runtime_environment


def stop_processes(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()

    deadline = time.monotonic() + 10
    for process in processes:
        if process.poll() is not None:
            continue
        timeout = max(0, deadline - time.monotonic())
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Start the trade-access API and persistent worker."
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--poll-interval", type=float, default=0.5)
    parser.add_argument(
        "--env-file",
        type=Path,
        help=(
            "Environment file to load. Defaults to "
            ".runtime/trade-access.env when that file exists."
        ),
    )
    args = parser.parse_args()

    loaded_env_file = load_runtime_environment(args.env_file)
    if loaded_env_file is not None:
        print("Loaded environment from {0}.".format(loaded_env_file), flush=True)

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.poll_interval <= 0:
        parser.error("--poll-interval must be greater than zero")

    commands = [
        (
            "api",
            [
                sys.executable,
                "-m",
                "uvicorn",
                "api.main:app",
                "--host",
                args.host,
                "--port",
                str(args.port),
            ],
        ),
        (
            "worker",
            [
                sys.executable,
                "-m",
                "api.worker",
                "--poll-interval",
                str(args.poll_interval),
            ],
        ),
    ]

    stop_requested = False

    def request_stop(signum: int, frame: object) -> None:
        nonlocal stop_requested
        del signum, frame
        stop_requested = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    processes: list[tuple[str, subprocess.Popen[bytes]]] = []
    try:
        for name, command in commands:
            process = subprocess.Popen(command, cwd=PROJECT_ROOT, env=os.environ.copy())
            processes.append((name, process))
            print(
                "Started {0} process with pid {1}.".format(name, process.pid),
                flush=True,
            )

        while not stop_requested:
            for name, process in processes:
                return_code = process.poll()
                if return_code is not None:
                    print(
                        "{0} process exited with code {1}.".format(
                            name,
                            return_code,
                        ),
                        file=sys.stderr,
                    )
                    return return_code if return_code != 0 else 1
            time.sleep(0.5)
        return 0
    finally:
        stop_processes([process for _, process in processes])


if __name__ == "__main__":
    raise SystemExit(main())
