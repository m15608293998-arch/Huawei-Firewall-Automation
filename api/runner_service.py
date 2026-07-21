import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    def _parent_orchestration_lock(self):
        # Shared with JobWorker so an all-firewall snapshot cannot observe a
        # transient state halfway through a multi-firewall parent mutation.
        lock_path = settings.database_path.parent / "firewall_parent.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

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

    @staticmethod
    def _firewall_code(firewall_code: str | None) -> str:
        return firewall_code or settings.firewall_target_codes[0]

    def _private_data_dir(self, firewall_code: str) -> Path:
        # Each profile gets a separate ansible-runner env/artifact tree.  This is
        # required because child jobs execute concurrently.
        return settings.runner_private_data_dir / firewall_code

    def run_trade_access(
        self,
        job: dict[str, Any],
        firewall_code: str | None = None,
    ) -> RunnerResult:
        target_code = self._firewall_code(firewall_code)
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
        private_data_dir = self._private_data_dir(target_code)
        private_data_dir.mkdir(parents=True, exist_ok=True)

        job_id = str(job["job_id"])
        local_tmp_dir = Path(
            str(
                job.get("target_local_tmp_dir")
                or (Path(str(job["local_tmp_dir"])) / target_code)
            )
        )
        local_tmp_dir.mkdir(parents=True, exist_ok=True)
        ident = "{0}-{1}-{2}".format(job_id, target_code, uuid.uuid4().hex[:8])

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
            "firewall_code": target_code,
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
                    ident=ident,
                    extravars=extravars,
                    envvars={
                        "ANSIBLE_CONFIG": str(project_root / "ansible.cfg"),
                    },
                    rotate_artifacts=20,
                    quiet=True,
                )
        except Exception as exc:
            return RunnerResult(
                status="failed",
                rc=1,
                artifact_dir=str(private_data_dir / "artifacts" / ident),
                error_message=str(exc),
            )

        return RunnerResult(
            status=getattr(result, "status", "unknown"),
            rc=int(getattr(result, "rc", 1) or 0),
            artifact_dir=str(private_data_dir / "artifacts" / ident),
            error_message=None,
        )

    def run_firewall_snapshot(
        self,
        snapshot_mode: str = "snapshot",
        firewall_code: str | None = None,
    ) -> SnapshotRunnerResult:
        target_code = self._firewall_code(firewall_code)
        if snapshot_mode not in {"snapshot", "ips", "ports", "state"}:
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
        private_data_dir = self._private_data_dir(target_code)
        private_data_dir.mkdir(parents=True, exist_ok=True)

        snapshot_id = "{0}-{1}-snapshot-{2}".format(
            target_code,
            snapshot_mode,
            uuid.uuid4(),
        )
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
            "firewall_code": target_code,
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

    def run_reconciled_snapshot(
        self,
        snapshot_mode: str,
        firewall_codes: tuple[str, ...] | list[str] | None = None,
    ) -> SnapshotRunnerResult:
        with self._parent_orchestration_lock():
            return self._run_reconciled_snapshot_unlocked(
                snapshot_mode,
                firewall_codes,
            )

    def _run_reconciled_snapshot_unlocked(
        self,
        snapshot_mode: str,
        firewall_codes: tuple[str, ...] | list[str] | None = None,
    ) -> SnapshotRunnerResult:
        if snapshot_mode not in {"snapshot", "ips", "ports"}:
            return SnapshotRunnerResult(
                status="failed",
                rc=1,
                artifact_dir="",
                error_message="Invalid reconciled firewall snapshot mode.",
            )
        codes = tuple(firewall_codes or settings.firewall_target_codes)
        results: dict[str, SnapshotRunnerResult] = {}
        worker_count = min(len(codes), settings.firewall_parallel_workers)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(self.run_firewall_snapshot, snapshot_mode, code): code
                for code in codes
            }
            for future in as_completed(futures):
                code = futures[future]
                try:
                    results[code] = future.result()
                except Exception as exc:
                    results[code] = SnapshotRunnerResult(
                        status="failed",
                        rc=1,
                        artifact_dir="",
                        error_message=str(exc),
                    )

        failures = {
            code: result.error_message or "snapshot failed"
            for code, result in results.items()
            if result.rc != 0 or result.payload is None
        }
        if failures:
            payload = {
                "consistency_status": "incomplete",
                "firewall_codes": list(codes),
                "firewalls": {
                    code: {
                        "status": results[code].status,
                        "error_message": results[code].error_message,
                    }
                    for code in codes
                },
            }
            return SnapshotRunnerResult(
                status="failed",
                rc=1,
                artifact_dir="",
                payload=payload,
                error_message="One or more firewall snapshot queries failed.",
            )

        item_sets = {
            code: {
                self._snapshot_item_key(item)
                for item in (results[code].payload or {}).get("items", [])
            }
            for code in codes
        }
        first_items = item_sets[codes[0]]
        consistent = all(items == first_items for items in item_sets.values())
        generated_at = max(
            str((results[code].payload or {}).get("generated_at") or "")
            for code in codes
        )
        summaries = {
            code: {
                "status": "ok",
                "generated_at": (results[code].payload or {}).get("generated_at"),
                "count": len(item_sets[code]),
            }
            for code in codes
        }
        if not consistent:
            union_items = set().union(*item_sets.values())
            common_items = set.intersection(*item_sets.values())
            differences = {
                code: {
                    "missing": [
                        self._snapshot_item_from_key(item)
                        for item in sorted(union_items - item_sets[code])
                    ],
                    "not_on_all_firewalls": [
                        self._snapshot_item_from_key(item)
                        for item in sorted(item_sets[code] - common_items)
                    ],
                }
                for code in codes
            }
            return SnapshotRunnerResult(
                status="drifted",
                rc=2,
                artifact_dir="",
                payload={
                    "generated_at": generated_at,
                    "consistency_status": "drifted",
                    "firewall_codes": list(codes),
                    "firewalls": summaries,
                    "differences": differences,
                },
                error_message="Firewall snapshots are not logically consistent.",
            )

        payload = dict(results[codes[0]].payload or {})
        payload["generated_at"] = generated_at
        payload["consistency_status"] = "consistent"
        payload["firewall_codes"] = list(codes)
        payload["firewalls"] = summaries
        return SnapshotRunnerResult(
            status="successful",
            rc=0,
            artifact_dir="",
            payload=payload,
        )

    @staticmethod
    def _snapshot_item_key(item: dict[str, Any]) -> tuple[str, int]:
        return (str(item["ip"]), int(item.get("port") or 0))

    @staticmethod
    def _snapshot_item_from_key(item: tuple[str, int]) -> dict[str, Any]:
        ip_value, port = item
        if port == 0:
            return {"ip": ip_value}
        return {"ip": ip_value, "port": port}

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
