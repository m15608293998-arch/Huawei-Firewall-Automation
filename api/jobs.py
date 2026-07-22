import uuid
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from api.auth import Principal, authorize_job_read
from api.config import settings
from api.runner_service import runner_service
from api.schemas import JobStatus, TradeAccessJobCreate
from api.storage import JobStorage
from api.time_utils import utc_now_iso


storage = JobStorage(settings.database_path)


def _target_artifact_dirs(
    job_id: str,
    target: dict[str, Any],
) -> list[object]:
    """Return every retained mutation attempt, not only the latest artifact."""
    artifact_value = target.get("artifact_dir")
    if not artifact_value:
        return [None]
    artifact_path = Path(str(artifact_value))
    candidates = {artifact_path}
    parent = artifact_path.parent
    prefix = "{0}-{1}-".format(job_id, target["firewall_code"])
    try:
        candidates.update(
            candidate
            for candidate in parent.iterdir()
            if candidate.is_dir() and candidate.name.startswith(prefix)
        )
    except OSError:
        pass
    return sorted(candidates, key=lambda candidate: candidate.name)


def create_job(
    request: TradeAccessJobCreate,
    principal: Principal,
    permission_code: str | None = None,
) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    firewall_targets = list(settings.firewall_target_codes)
    # 每个任务使用独立临时目录和 artifact 目录，方便失败后按 job_id 排查。
    local_tmp_dir = str(settings.job_tmp_root / job_id)
    artifact_dir = str(settings.runner_private_data_dir / "artifacts" / job_id)

    job: dict[str, Any] = {
        "job_id": job_id,
        "status": JobStatus.pending.value,
        "action": request.action.value,
        "target_ip": request.target_ip,
        "mask": request.mask,
        "ports": request.ports or [],
        "description": request.description,
        "client_request_id": request.client_request_id,
        "principal_subject": principal.subject,
        "principal_id": principal.subject_id,
        "principal_client_id": principal.client_id,
        "principal_key_id": principal.key_id,
        "principal_type": principal.subject_type,
        "auth_type": principal.auth_type,
        "permission_code": permission_code,
        "runner_status": None,
        "runner_rc": None,
        "error_message": None,
        "created_at": utc_now_iso(),
        "started_at": None,
        "finished_at": None,
        "artifact_dir": artifact_dir,
        "local_tmp_dir": local_tmp_dir,
        "firewall_targets": firewall_targets,
        "desired_state": None,
        "state_version": None,
        "next_attempt_at": None,
    }
    storage.create_job(job, firewall_targets)
    return job


def get_job_or_404(job_id: str) -> dict[str, Any]:
    job = storage.get_job(job_id, include_targets=True)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found.",
        )
    return job


def get_job_events(
    job_id: str,
    principal: Principal,
    detailed: bool = False,
) -> list[dict[str, object]]:
    job = get_job_or_404(job_id)
    authorize_job_read(principal, job)
    events: list[dict[str, object]] = []
    for target in job.get("target_results") or []:
        for artifact_dir in _target_artifact_dirs(job_id, target):
            for event in runner_service.read_events(
                artifact_dir,
                detailed=detailed,
            ):
                event["firewall_code"] = target["firewall_code"]
                events.append(event)
    return sorted(
        events,
        key=lambda event: (str(event.get("created") or ""), int(event.get("counter") or 0)),
    )


def get_admin_job_events(
    job_id: str,
    detailed: bool = False,
) -> list[dict[str, object]]:
    job = get_job_or_404(job_id)
    events: list[dict[str, object]] = []
    for target in job.get("target_results") or []:
        for artifact_dir in _target_artifact_dirs(job_id, target):
            for event in runner_service.read_events(
                artifact_dir,
                detailed=detailed,
            ):
                event["firewall_code"] = target["firewall_code"]
                events.append(event)
    return sorted(
        events,
        key=lambda event: (str(event.get("created") or ""), int(event.get("counter") or 0)),
    )


def list_jobs(
    principal: Principal,
    limit: int,
    page: int,
    job_status: str | None,
    include_all: bool = False,
) -> list[dict[str, Any]]:
    # 管理端传 include_all；普通端始终按 principal_id 收敛。
    principal_id = None if include_all else principal.subject_id
    jobs = storage.list_jobs(
        limit=limit,
        offset=(page - 1) * limit,
        job_status=job_status,
        principal_id=principal_id,
        include_targets=True,
    )
    return jobs


def list_reconciling_jobs(limit: int = 100) -> list[dict[str, Any]]:
    return storage.list_jobs(
        limit=limit,
        offset=0,
        job_status=JobStatus.reconciling.value,
    )
