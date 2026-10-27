import json
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from api.config import settings
from api.execution import ExecutionTimeout, exclusive_file_lock
from api.ip_policy import (
    DIRECT_ACCESS_ALLOW_ACTIONS,
    validate_direct_access_target,
)
from api.time_utils import utc_now_iso


SUMMARY_EVENT_TASK_MARKERS = (
    "Query address-set member before",
    "Add target IP to address-set",
    "Remove target IP from address-set",
    "Validate target IP exists",
    "Validate target IP removed",
    "Query application inventory for target IP",
    "Query applications belonging to target IP",
    "Apply incremental application port changes",
    "Remove user-defined application and application group member",
    "Validate incremental application state",
    "Validate application removed",
    "Reject IP deny while ports still exist",
    "Commit and save firewall configuration",
    "Report unchanged firewall state",
)


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
    def _parent_orchestration_lock(self, timeout_seconds: float | None = None):
        # Shared with JobWorker so an all-firewall snapshot cannot observe a
        # transient state halfway through a multi-firewall parent mutation.
        lock_path = settings.database_path.parent / "firewall_parent.lock"
        timeout = min(settings.runner_lock_timeout_seconds, timeout_seconds if timeout_seconds is not None else settings.runner_lock_timeout_seconds)
        with exclusive_file_lock(lock_path, timeout):
            yield

    @contextmanager
    def _exclusive_runner_lock(self, private_data_dir: Path, timeout_seconds: float):
        private_data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = private_data_dir / "firewall_runner.lock"
        with exclusive_file_lock(lock_path, min(settings.runner_lock_timeout_seconds, timeout_seconds)):
            yield

    @staticmethod
    def _runner_options(deadline: float) -> dict[str, Any]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutionTimeout("Runner execution deadline exceeded.")
        return {
            # Use settings rather than timeout= so subsecond budgets are not
            # truncated to zero (which disables the runner timeout).
            "settings": {"job_timeout": remaining, "pexpect_timeout": min(0.2, remaining)},
            "cancel_callback": lambda: time.monotonic() >= deadline,
            "envvars": {
                "ANSIBLE_CONFIG": str(settings.project_root / "ansible.cfg"),
                "USG6000E_RUN_DEADLINE": str(time.time() + remaining),
            },
        }

    @staticmethod
    def _firewall_code(firewall_code: str | None) -> str:
        return firewall_code or settings.firewall_target_codes[0]

    def _private_data_dir(self, firewall_code: str) -> Path:
        # Each profile gets a separate ansible-runner env/artifact tree.  This is
        # required because child jobs execute concurrently.
        return settings.runner_private_data_dir / firewall_code

    @staticmethod
    def _failure_message_from_event(event: dict[str, Any]) -> str | None:
        if event.get("event") not in {
            "runner_on_failed",
            "runner_on_unreachable",
            "runner_on_async_failed",
        }:
            return None
        event_data = event.get("event_data")
        if not isinstance(event_data, dict):
            return None
        result = event_data.get("res")
        if not isinstance(result, dict):
            return None
        for key in ("stderr", "msg", "stdout"):
            value = result.get(key)
            if not isinstance(value, str):
                continue
            for line in value.splitlines():
                message = line.strip()
                if message:
                    return message[:2000]
        return None

    @contextmanager
    def _isolated_private_data_dir(
        self,
        firewall_runner_dir: Path,
        ident: str,
    ):
        """Keep runner env files isolated to one invocation.

        ansible-runner automatically reuses ``env/extravars`` when the same
        private data directory is used again.  Snapshot variables such as
        ``snapshot_mode`` must never leak into a later access mutation.
        """
        run_root = firewall_runner_dir / "runs"
        run_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="{0}-".format(ident),
            dir=str(run_root),
        ) as private_data_dir:
            yield Path(private_data_dir)

    def run_trade_access(
        self,
        job: dict[str, Any],
        firewall_code: str | None = None,
    ) -> RunnerResult:
        target_code = self._firewall_code(firewall_code)
        if str(job.get("action")) in DIRECT_ACCESS_ALLOW_ACTIONS:
            try:
                validate_direct_access_target(
                    str(job.get("target_ip", "")),
                    int(job.get("mask", 32)),
                )
            except (TypeError, ValueError) as exc:
                return RunnerResult(
                    status="failed",
                    rc=2,
                    artifact_dir=str(job.get("artifact_dir") or ""),
                    error_message=str(exc),
                )
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
        deadline = time.monotonic() + min(
            settings.runner_timeout_seconds,
            float(job.get("execution_timeout_seconds", settings.runner_timeout_seconds)),
        )
        playbook = str(project_root / settings.playbook_path)
        firewall_runner_dir = self._private_data_dir(target_code)
        firewall_runner_dir.mkdir(parents=True, exist_ok=True)
        artifact_root = firewall_runner_dir / "artifacts"

        job_id = str(job["job_id"])
        local_tmp_dir = Path(
            str(
                job.get("target_local_tmp_dir")
                or (Path(str(job["local_tmp_dir"])) / target_code)
            )
        )
        local_tmp_dir.mkdir(parents=True, exist_ok=True)
        ident = "{0}-{1}-{2}".format(job_id, target_code, uuid.uuid4().hex[:8])
        failure_messages: list[str] = []

        def capture_failure(event: dict[str, Any]) -> bool:
            message = self._failure_message_from_event(event)
            if message:
                failure_messages.append(message)
            return True

        # API 只组装业务请求，真正的华为设备操作仍交给原 playbook/role 链路。
        extravars = {
            "firewall_workflow_mode": "access",
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
        if job.get("desired_state") is not None:
            extravars["desired_access_state"] = job["desired_state"]
        extravars["force_finalize"] = bool(job.get("force_finalize", False))

        try:
            with self._exclusive_runner_lock(firewall_runner_dir, deadline - time.monotonic()):
                with self._isolated_private_data_dir(
                    firewall_runner_dir,
                    ident,
                ) as private_data_dir:
                    result = ansible_runner.run(
                        private_data_dir=str(private_data_dir),
                        artifact_dir=str(artifact_root),
                        project_dir=str(project_root),
                        playbook=playbook,
                        ident=ident,
                        extravars=extravars,
                        **self._runner_options(deadline),
                        suppress_env_files=True,
                        rotate_artifacts=20,
                        quiet=True,
                        event_handler=capture_failure,
                    )
        except ExecutionTimeout as exc:
            return RunnerResult("timeout", 254, str(artifact_root / ident), str(exc))
        except Exception as exc:
            return RunnerResult(
                status="failed",
                rc=1,
                artifact_dir=str(artifact_root / ident),
                error_message=str(exc),
            )

        status = getattr(result, "status", "unknown")
        rc = int(getattr(result, "rc", 1) or 0)
        if time.monotonic() >= deadline or status == "timeout":
            return RunnerResult("timeout", 254, str(artifact_root / ident), "Runner execution deadline exceeded; firewall changes may be partial.")
        return RunnerResult(
            status=status,
            rc=rc,
            artifact_dir=str(artifact_root / ident),
            error_message=failure_messages[-1] if rc != 0 and failure_messages else None,
        )

    def run_firewall_snapshot(
        self,
        snapshot_mode: str = "snapshot",
        firewall_code: str | None = None,
        timeout_seconds: float | None = None,
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
        deadline = time.monotonic() + min(
            settings.snapshot_timeout_seconds,
            timeout_seconds if timeout_seconds is not None else settings.snapshot_timeout_seconds,
        )
        playbook = str(project_root / settings.playbook_path)
        firewall_runner_dir = self._private_data_dir(target_code)
        firewall_runner_dir.mkdir(parents=True, exist_ok=True)
        artifact_root = firewall_runner_dir / "artifacts"

        snapshot_id = "{0}-{1}-snapshot-{2}".format(
            target_code,
            snapshot_mode,
            uuid.uuid4(),
        )
        artifact_dir = str(artifact_root / snapshot_id)
        settings.job_tmp_root.mkdir(parents=True, exist_ok=True)
        # Snapshot files are only an exchange boundary between Ansible and this
        # process.  The parsed payload is returned from memory, while runner
        # artifacts remain separately available under artifact_root.
        with tempfile.TemporaryDirectory(
            prefix="{0}-".format(snapshot_id),
            dir=str(settings.job_tmp_root),
        ) as temp_dir:
            local_tmp_dir = Path(temp_dir)
            snapshot_output_path = local_tmp_dir / "firewall_{0}_snapshot.json".format(
                snapshot_mode
            )

            extravars = {
                "firewall_workflow_mode": "snapshot",
                "local_tmp_dir": str(local_tmp_dir),
                "local_python_interpreter": sys.executable,
                "snapshot_mode": snapshot_mode,
                "snapshot_output_path": str(snapshot_output_path),
                "firewall_code": target_code,
            }

            try:
                with self._exclusive_runner_lock(firewall_runner_dir, deadline - time.monotonic()):
                    with self._isolated_private_data_dir(
                        firewall_runner_dir,
                        snapshot_id,
                    ) as private_data_dir:
                        result = ansible_runner.run(
                            private_data_dir=str(private_data_dir),
                            artifact_dir=str(artifact_root),
                            project_dir=str(project_root),
                            playbook=playbook,
                            ident=snapshot_id,
                            extravars=extravars,
                            **self._runner_options(deadline),
                            suppress_env_files=True,
                            rotate_artifacts=20,
                            quiet=True,
                        )
            except ExecutionTimeout as exc:
                return SnapshotRunnerResult("timeout", 254, artifact_dir, error_message=str(exc))
            except Exception as exc:
                return SnapshotRunnerResult(
                    status="failed",
                    rc=1,
                    artifact_dir=artifact_dir,
                    error_message=str(exc),
                )

            status = getattr(result, "status", "unknown")
            rc = int(getattr(result, "rc", 1) or 0)
            if time.monotonic() >= deadline or status == "timeout":
                return SnapshotRunnerResult("timeout", 254, artifact_dir, error_message="Firewall snapshot deadline exceeded.")
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

    def _query_snapshots_parallel(
        self, mode: str, codes: tuple[str, ...], timeout_seconds: float | None,
    ) -> dict[str, SnapshotRunnerResult]:
        deadline = time.monotonic() + (timeout_seconds if timeout_seconds is not None else settings.snapshot_timeout_seconds)
        results: dict[str, SnapshotRunnerResult] = {}

        def query(code):
            return self.run_firewall_snapshot(mode, code, timeout_seconds=max(0, deadline - time.monotonic()))

        with ThreadPoolExecutor(max_workers=min(len(codes), settings.firewall_parallel_workers)) as executor:
            futures = {executor.submit(query, code): code for code in codes}
            for future in as_completed(futures):
                code = futures[future]
                try:
                    results[code] = future.result()
                except Exception as exc:
                    results[code] = SnapshotRunnerResult("failed", 1, "", error_message=str(exc))
        return results

    def run_reconciled_snapshot(
        self,
        snapshot_mode: str,
        firewall_codes: tuple[str, ...] | list[str] | None = None,
    ) -> SnapshotRunnerResult:
        deadline = time.monotonic() + settings.snapshot_timeout_seconds
        try:
            with self._parent_orchestration_lock(deadline - time.monotonic()):
                return self._run_reconciled_snapshot_unlocked(
                    snapshot_mode, firewall_codes, deadline - time.monotonic(),
                )
        except ExecutionTimeout as exc:
            return SnapshotRunnerResult("timeout", 254, "", error_message=str(exc))

    def _run_reconciled_snapshot_unlocked(
        self,
        snapshot_mode: str,
        firewall_codes: tuple[str, ...] | list[str] | None = None,
        timeout_seconds: float | None = None,
    ) -> SnapshotRunnerResult:
        if snapshot_mode not in {"snapshot", "ips", "ports"}:
            return SnapshotRunnerResult(
                status="failed",
                rc=1,
                artifact_dir="",
                error_message="Invalid reconciled firewall snapshot mode.",
            )
        codes = tuple(firewall_codes or settings.firewall_target_codes)
        results = self._query_snapshots_parallel(snapshot_mode, codes, timeout_seconds)

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

    def run_firewall_consistency_check(
        self,
        firewall_codes: tuple[str, ...] | list[str] | None = None,
    ) -> SnapshotRunnerResult:
        """Query IP and port state once per firewall and build a repair report."""
        deadline = time.monotonic() + settings.snapshot_timeout_seconds
        try:
            with self._parent_orchestration_lock(deadline - time.monotonic()):
                return self._run_firewall_consistency_check_unlocked(
                    firewall_codes, deadline - time.monotonic(),
                )
        except ExecutionTimeout as exc:
            return SnapshotRunnerResult("timeout", 254, "", error_message=str(exc))

    def _run_firewall_consistency_check_unlocked(
        self,
        firewall_codes: tuple[str, ...] | list[str] | None = None,
        timeout_seconds: float | None = None,
    ) -> SnapshotRunnerResult:
        codes = tuple(firewall_codes or settings.firewall_target_codes)
        results = self._query_snapshots_parallel("state", codes, timeout_seconds)

        ip_sets: dict[str, set[tuple[str, int]]] = {}
        port_sets: dict[str, set[tuple[str, int]]] = {}
        failures: dict[str, str] = {}
        for code in codes:
            result = results[code]
            if result.rc != 0 or result.payload is None:
                failures[code] = result.error_message or "state query failed"
                continue
            try:
                ip_sets[code], port_sets[code] = self._state_snapshot_item_sets(
                    result.payload
                )
            except (KeyError, TypeError, ValueError) as exc:
                failures[code] = "Invalid state snapshot payload: {0}".format(exc)

        checked_at = utc_now_iso()
        if failures:
            firewalls = {
                code: {
                    "query_status": "failed" if code in failures else "successful",
                    "generated_at": self._snapshot_generated_at(
                        results[code].payload
                    ),
                    "artifact_dir": results[code].artifact_dir,
                    "ip_count": len(ip_sets.get(code, set())),
                    "port_count": len(port_sets.get(code, set())),
                    "error_message": failures.get(code),
                    "ip_missing": [],
                    "ip_extra": [],
                    "port_missing": [],
                    "port_extra": [],
                    "suggested_actions": [],
                }
                for code in codes
            }
            payload = {
                "checked_at": checked_at,
                "overall_status": "incomplete",
                "reference_strategy": "strict_majority_of_all_configured_firewalls",
                "firewall_codes": list(codes),
                "summary": {
                    "configured_firewall_count": len(codes),
                    "successful_firewall_count": len(codes) - len(failures),
                    "ip_consistent": None,
                    "port_consistent": None,
                    "ip_drift_item_count": 0,
                    "port_drift_item_count": 0,
                    "suggested_action_count": 0,
                    "ambiguous_item_count": 0,
                },
                "firewalls": firewalls,
                "differences": {"ips": [], "ports": []},
                "warning": (
                    "At least one firewall query failed. No correction actions were "
                    "generated because the comparison is incomplete."
                ),
            }
            return SnapshotRunnerResult(
                status="failed",
                rc=1,
                artifact_dir="",
                payload=payload,
                error_message="One or more firewall consistency-check queries failed.",
            )

        ip_differences = self._build_check_differences(ip_sets, codes)
        port_differences = self._build_check_differences(port_sets, codes)
        ip_by_key = {
            self._snapshot_item_key(item): item for item in ip_differences
        }
        port_by_key = {
            self._snapshot_item_key(item): item for item in port_differences
        }
        firewalls: dict[str, dict[str, Any]] = {}
        action_count = 0
        for code in codes:
            ip_missing = {
                key
                for key, item in ip_by_key.items()
                if item["reference_state"] == "present" and key not in ip_sets[code]
            }
            ip_extra = {
                key
                for key, item in ip_by_key.items()
                if item["reference_state"] == "absent" and key in ip_sets[code]
            }
            port_missing = {
                key
                for key, item in port_by_key.items()
                if item["reference_state"] == "present" and key not in port_sets[code]
            }
            port_extra = {
                key
                for key, item in port_by_key.items()
                if item["reference_state"] == "absent" and key in port_sets[code]
            }

            actions: list[dict[str, Any]] = []
            for action, keys, evidence in (
                ("add_ip", ip_missing, ip_by_key),
                ("add_port", port_missing, port_by_key),
                ("remove_port", port_extra, port_by_key),
                ("remove_ip", ip_extra, ip_by_key),
            ):
                for key in sorted(keys):
                    item = evidence[key]
                    action_item = {
                        "firewall_code": code,
                        "action": action,
                        **self._snapshot_item_from_key(key),
                        "present_on_firewalls": item["present_on_firewalls"],
                        "absent_on_firewalls": item["absent_on_firewalls"],
                        "reason": self._check_action_reason(item["reference_state"], item),
                    }
                    actions.append(action_item)

            action_count += len(actions)
            result = results[code]
            firewalls[code] = {
                "query_status": "successful",
                "generated_at": self._snapshot_generated_at(result.payload),
                "artifact_dir": result.artifact_dir,
                "ip_count": len(ip_sets[code]),
                "port_count": len(port_sets[code]),
                "error_message": None,
                "ip_missing": [
                    self._snapshot_item_from_key(item) for item in sorted(ip_missing)
                ],
                "ip_extra": [
                    self._snapshot_item_from_key(item) for item in sorted(ip_extra)
                ],
                "port_missing": [
                    self._snapshot_item_from_key(item) for item in sorted(port_missing)
                ],
                "port_extra": [
                    self._snapshot_item_from_key(item) for item in sorted(port_extra)
                ],
                "suggested_actions": actions,
            }

        ambiguous_count = sum(
            1
            for item in ip_differences + port_differences
            if item["reference_state"] == "ambiguous"
        )
        drifted = bool(ip_differences or port_differences)
        payload = {
            "checked_at": checked_at,
            "overall_status": "drifted" if drifted else "consistent",
            "reference_strategy": "strict_majority_of_all_configured_firewalls",
            "firewall_codes": list(codes),
            "summary": {
                "configured_firewall_count": len(codes),
                "successful_firewall_count": len(codes),
                "ip_consistent": not ip_differences,
                "port_consistent": not port_differences,
                "ip_drift_item_count": len(ip_differences),
                "port_drift_item_count": len(port_differences),
                "suggested_action_count": action_count,
                "ambiguous_item_count": ambiguous_count,
            },
            "firewalls": firewalls,
            "differences": {
                "ips": ip_differences,
                "ports": port_differences,
            },
            "warning": (
                "Correction actions are majority-based suggestions only. Verify the "
                "intended business state before changing a firewall manually."
            ),
        }
        return SnapshotRunnerResult(
            status="drifted" if drifted else "successful",
            rc=0,
            artifact_dir="",
            payload=payload,
        )

    @staticmethod
    def _state_snapshot_item_sets(
        payload: dict[str, Any],
    ) -> tuple[set[tuple[str, int]], set[tuple[str, int]]]:
        if not isinstance(payload, dict):
            raise TypeError("state snapshot payload must be an object")
        ip_items = payload["ip_items"]
        port_items = payload["port_items"]
        if not isinstance(ip_items, list) or not isinstance(port_items, list):
            raise TypeError("ip_items and port_items must be lists")
        ip_keys: set[tuple[str, int]] = set()
        for item in ip_items:
            if not isinstance(item, dict) or not isinstance(item.get("ip"), str):
                raise TypeError("each ip_items entry must contain a string ip")
            ip_keys.add((item["ip"], 0))

        port_keys: set[tuple[str, int]] = set()
        for item in port_items:
            if not isinstance(item, dict) or not isinstance(item.get("ip"), str):
                raise TypeError("each port_items entry must contain a string ip")
            if "port" not in item:
                raise KeyError("port")
            port = int(item["port"])
            if port < 1 or port > 65535:
                raise ValueError("port must be between 1 and 65535")
            port_keys.add((item["ip"], port))
        return ip_keys, port_keys

    @staticmethod
    def _snapshot_generated_at(payload: object) -> str | None:
        if not isinstance(payload, dict):
            return None
        value = payload.get("generated_at")
        return str(value) if value is not None else None

    @classmethod
    def _build_check_differences(
        cls,
        item_sets: dict[str, set[tuple[str, int]]],
        codes: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        union_items = set().union(*(item_sets[code] for code in codes))
        differences: list[dict[str, Any]] = []
        for key in sorted(union_items):
            present_on = [code for code in codes if key in item_sets[code]]
            if len(present_on) == len(codes):
                continue
            absent_on = [code for code in codes if code not in present_on]
            if len(present_on) * 2 > len(codes):
                reference_state = "present"
            elif len(present_on) * 2 < len(codes):
                reference_state = "absent"
            else:
                reference_state = "ambiguous"
            differences.append(
                {
                    **cls._snapshot_item_from_key(key),
                    "present_on_firewalls": present_on,
                    "absent_on_firewalls": absent_on,
                    "reference_state": reference_state,
                }
            )
        return differences

    @staticmethod
    def _check_action_reason(
        reference_state: str,
        item: dict[str, Any],
    ) -> str:
        present_count = len(item["present_on_firewalls"])
        total_count = present_count + len(item["absent_on_firewalls"])
        if reference_state == "present":
            return "Present on {0}/{1} firewalls; strict majority suggests adding it.".format(
                present_count,
                total_count,
            )
        return "Absent on {0}/{1} firewalls; strict majority suggests removing it.".format(
            total_count - present_count,
            total_count,
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

    def read_events(
        self,
        artifact_dir: object,
        detailed: bool = False,
    ) -> list[dict[str, object]]:
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
            event_name = str(payload.get("event") or "")
            task_name = event_data.get("task")
            event = {
                "counter": payload.get("counter", event_counter(event_file)),
                "event": event_name or None,
                "task": task_name,
                "created": payload.get("created"),
            }
            if detailed:
                events.append(event)
                continue

            if event_name in {
                "runner_on_failed",
                "runner_on_unreachable",
                "runner_on_async_failed",
            }:
                event["event"] = "failed"
                event["message"] = self._failure_message_from_event(payload)
                events.append(event)
                continue

            if event_name == "playbook_on_stats":
                event["event"] = "completed"
                event["task"] = "Ansible execution completed"
                events.append(event)
                continue

            if event_name != "runner_on_ok" or not isinstance(task_name, str):
                continue
            if not any(marker in task_name for marker in SUMMARY_EVENT_TASK_MARKERS):
                continue
            result = event_data.get("res") or {}
            event["event"] = "changed" if bool(result.get("changed")) else "ok"
            events.append(event)

        return events


runner_service = AnsibleRunnerService()
