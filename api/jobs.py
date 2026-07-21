import uuid
from typing import Any

from fastapi import HTTPException, status

from api.auth import Principal, authorize_job_read
from api.config import settings
from api.runner_service import runner_service
from api.schemas import JobStatus, TradeAccessJobCreate
from api.storage import JobStorage
from api.time_utils import utc_now_iso


storage = JobStorage(settings.database_path)


def create_job(
    request: TradeAccessJobCreate,
    principal: Principal,
    permission_code: str | None = None,
) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
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
    }
    storage.create_job(job)
    return job


def get_job_or_404(job_id: str) -> dict[str, Any]:
    job = storage.get_job(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found.",
        )
    return job


def get_job_events(job_id: str, principal: Principal) -> list[dict[str, object]]:
    job = get_job_or_404(job_id)
    authorize_job_read(principal, job)
    return runner_service.read_events(job.get("artifact_dir"))


def get_admin_job_events(job_id: str) -> list[dict[str, object]]:
    job = get_job_or_404(job_id)
    return runner_service.read_events(job.get("artifact_dir"))


def list_jobs(
    principal: Principal,
    limit: int,
    page: int,
    job_status: str | None,
    include_all: bool = False,
) -> list[dict[str, Any]]:
    # 管理端传 include_all；普通端始终按 principal_id 收敛。
    principal_id = None if include_all else principal.subject_id
    return storage.list_jobs(
        limit=limit,
        offset=(page - 1) * limit,
        job_status=job_status,
        principal_id=principal_id,
    )
