import json
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import fcntl

from api.config import settings


@dataclass(frozen=True)
class RunnerResult:
    status: str
    rc: int
    artifact_dir: str
    error_message: str | None = None


@dataclass(frozen=True)
class SnapshotRunnerResult:
    status: str
    rc: int
    artifact_dir: str
    payload: dict[str, Any] | None = None
    error_message: str | None = None


class AnsibleRunnerService:
    @contextmanager
    def _exclusive_runner_lock(self, private_data_dir: Path):
        private_data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = private_data_dir / "firewall_runner.lock"
        with lock_path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def run_trade_access(self, job: dict[str, Any]) -> RunnerResult:
        try:
            import ansible_runner
        except ImportError as exc:
            return RunnerResult(
                status="failed",
                rc=127,
                artifact_dir=str(job.get("artifact_dir") or ""),
                error_message="ansible-runner is not installed: {0}".format(exc),
            )

        project_root = settings.project_root
        playbook = str(project_root / settings.playbook_path)
        private_data_dir = settings.runner_private_data_dir
        private_data_dir.mkdir(parents=True, exist_ok=True)

        job_id = str(job["job_id"])
        local_tmp_dir = Path(str(job["local_tmp_dir"]))
        local_tmp_dir.mkdir(parents=True, exist_ok=True)

        # API 只组装业务请求，真正的华为设备操作仍交给原 playbook/role 链路。
        extravars = {
            "access_request": {
                "action": job["action"],
                "target_ip": job["target_ip"],
                "mask": job["mask"],
                "requester": job.get("principal_subject") or settings.development_subject,
                "request_id": job_id,
                "description": job.get("description") or "trade-server-{0}".format(job["target_ip"]),
            },
            "local_tmp_dir": str(local_tmp_dir),
            # helper 脚本使用当前 API 解释器，避免系统 python 版本不一致。
            "local_python_interpreter": sys.executable,
        }
        if job["action"] in {"allow", "allow_ports", "deny_ports"}:
            extravars["application_ports"] = job["ports"]

        try:
            with self._exclusive_runner_lock(private_data_dir):
                result = ansible_runner.run(
                    private_data_dir=str(private_data_dir),
                    project_dir=str(project_root),
                    playbook=playbook,
                    ident=job_id,
                    extravars=extravars,
                    envvars={
                        "ANSIBLE_CONFIG": str(project_root / "ansible.cfg"),
                    },
                    rotate_artifacts=20,
                    quiet=True,
                    timeout=settings.runner_timeout_seconds,
                )
        except Exception as exc:
            return RunnerResult(
                status="failed",
                rc=1,
                artifact_dir=str(private_data_dir / "artifacts" / job_id),
                error_message=str(exc),
            )

        return RunnerResult(
            status=getattr(result, "status", "unknown"),
            rc=int(getattr(result, "rc", 1) or 0),
            artifact_dir=str(private_data_dir / "artifacts" / job_id),
            error_message=None,
        )

    def run_firewall_snapshot(self, snapshot_mode: str = "snapshot") -> SnapshotRunnerResult:
        if snapshot_mode not in {"snapshot", "ips", "ports"}:
            return SnapshotRunnerResult(
                status="failed",
                rc=1,
                artifact_dir="",
                error_message="Invalid firewall snapshot mode.",
            )
        try:
            import ansible_runner
        except ImportError as exc:
            return SnapshotRunnerResult(
                status="failed",
                rc=127,
                artifact_dir="",
                error_message="ansible-runner is not installed: {0}".format(exc),
            )

        project_root = settings.project_root
        playbook = str(project_root / settings.playbook_path)
        private_data_dir = settings.runner_private_data_dir
        private_data_dir.mkdir(parents=True, exist_ok=True)

        snapshot_id = "{0}-snapshot-{1}".format(snapshot_mode, uuid.uuid4())
        local_tmp_dir = settings.job_tmp_root / snapshot_id
        local_tmp_dir.mkdir(parents=True, exist_ok=True)
        snapshot_output_path = local_tmp_dir / "firewall_{0}_snapshot.json".format(
            snapshot_mode
        )

        extravars = {
            "local_tmp_dir": str(local_tmp_dir),
            "local_python_interpreter": sys.executable,
            "snapshot_mode": snapshot_mode,
            "snapshot_output_path": str(snapshot_output_path),
        }

        artifact_dir = str(private_data_dir / "artifacts" / snapshot_id)
        try:
            with self._exclusive_runner_lock(private_data_dir):
                result = ansible_runner.run(
                    private_data_dir=str(private_data_dir),
                    project_dir=str(project_root),
                    playbook=playbook,
                    ident=snapshot_id,
                    extravars=extravars,
                    envvars={
                        "ANSIBLE_CONFIG": str(project_root / "ansible.cfg"),
                    },
                    rotate_artifacts=20,
                    quiet=True,
                    timeout=settings.snapshot_runner_timeout_seconds,
                )
        except Exception as exc:
            return SnapshotRunnerResult(
                status="failed",
                rc=1,
                artifact_dir=artifact_dir,
                error_message=str(exc),
            )

        status = getattr(result, "status", "unknown")
        rc = int(getattr(result, "rc", 1) or 0)
        if rc != 0:
            return SnapshotRunnerResult(
                status=status,
                rc=rc,
                artifact_dir=artifact_dir,
                error_message="Firewall snapshot playbook failed.",
            )

        try:
            with snapshot_output_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:
            return SnapshotRunnerResult(
                status="failed",
                rc=1,
                artifact_dir=artifact_dir,
                error_message="Failed to read firewall snapshot output: {0}".format(exc),
            )

        return SnapshotRunnerResult(
            status=status,
            rc=rc,
            artifact_dir=artifact_dir,
            payload=payload,
        )

    def read_events(self, artifact_dir: object) -> list[dict[str, object]]:
        if not artifact_dir:
            return []

        event_dir = Path(str(artifact_dir)) / "job_events"
        if not event_dir.exists():
            return []

        def event_counter(event_file: Path) -> int:
            # ansible-runner 事件文件名前缀是递增序号，用它保持输出顺序。
            try:
                return int(event_file.name.split("-", 1)[0])
            except ValueError:
                return 0

        events: list[dict[str, object]] = []
        for event_file in sorted(event_dir.glob("*.json"), key=event_counter):
            try:
                with event_file.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                # 单个坏事件文件不影响接口返回已有事件。
                continue

            event_data = payload.get("event_data") or {}
            events.append(
                {
                    "counter": payload.get("counter", event_counter(event_file)),
                    "event": payload.get("event"),
                    "task": event_data.get("task"),
                    "created": payload.get("created"),
                }
            )

        return events


runner_service = AnsibleRunnerService()
