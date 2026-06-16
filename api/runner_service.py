import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from api.config import settings


@dataclass(frozen=True)
class RunnerResult:
    status: str
    rc: int
    artifact_dir: str
    error_message: str | None = None


class AnsibleRunnerService:
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
            "local_python_interpreter": sys.executable,
        }
        if job["action"] == "allow":
            extravars["application_ports"] = job["ports"]

        try:
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

    def read_events(self, artifact_dir: object) -> list[dict[str, object]]:
        if not artifact_dir:
            return []

        event_dir = Path(str(artifact_dir)) / "job_events"
        if not event_dir.exists():
            return []

        def event_counter(event_file: Path) -> int:
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
