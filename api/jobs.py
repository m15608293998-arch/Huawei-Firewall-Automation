import uuid
import re
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from api.auth import Principal, authorize_job_read
from api.config import settings
from api.runner_service import runner_service
from api.schemas import JobStatus, TradeAccessJobCreate
from api.storage import IdempotencyConflictError, JobStorage
from api.time_utils import utc_now_iso
from api.runtime_health import readiness_report


storage = JobStorage(settings.database_path)


def _target_artifact_dirs(
    job_id: str,
    target: dict[str, Any],
) -> list[Path]:
    """Read this job's evidence, including legacy and interrupted attempts."""
    artifact_value = target.get("artifact_dir")
    candidates = {Path(str(artifact_value))} if artifact_value else set()
    profile_dir = settings.runner_private_data_dir / str(target["firewall_code"])
    parents = {profile_dir / "job_artifacts" / job_id, profile_dir / "artifacts"}
    if artifact_value:
        parents.add(Path(str(artifact_value)).parent)
    prefix = "{0}-{1}-".format(job_id, target["firewall_code"])
    for parent in parents:
        try:
            candidates.update(candidate for candidate in parent.iterdir()
                              if candidate.is_dir() and candidate.name.startswith(prefix))
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
    try:
        return storage.create_job(job, firewall_targets)
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


def cancel_job(job_id: str, principal: Principal, include_all: bool = False) -> dict[str, Any]:
    job = get_job_or_404(job_id)
    if not include_all:
        authorize_job_read(principal, job)
    if job["status"] == JobStatus.canceled.value:
        return job
    if not storage.cancel_job(job_id, utc_now_iso()):
        latest = get_job_or_404(job_id)
        if latest["status"] == JobStatus.canceled.value:
            return latest
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only pending or prechecking jobs without configuration preparation can be canceled.",
        )
    return get_job_or_404(job_id)


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
) -> dict[str, Any]:
    job = get_job_or_404(job_id)
    authorize_job_read(principal, job)
    return _job_event_report(job, detailed)


def get_admin_job_events(
    job_id: str,
    detailed: bool = False,
) -> dict[str, Any]:
    job = get_job_or_404(job_id)
    return _job_event_report(job, detailed)


def _job_event_report(job: dict[str, Any], detailed: bool) -> dict[str, Any]:
    job_id = str(job["job_id"])
    events: list[dict[str, object]] = []
    warnings: list[str] = []
    retained_runs = 0
    expected_runs = 0
    for target in job.get("target_results") or []:
        prefix = "{0}-{1}-".format(job_id, target["firewall_code"])
        mutations = 0
        prechecks = 0
        expected_mutations = int(target.get("attempt_count") or 0)
        expected_prechecks = int(job.get("precheck_attempt_count") or 0)
        expected_runs += expected_mutations + expected_prechecks
        for artifact_dir in _target_artifact_dirs(job_id, target):
            try:
                if not any((artifact_dir / "job_events").glob("*.json")):
                    continue
                run_report = runner_service.read_event_report(artifact_dir, detailed=detailed)
            except Exception:
                warnings.append("{0}: an audit run could not be read.".format(target["firewall_code"]))
                continue
            if run_report["unreadable_event_count"]:
                warnings.append("{0}: some audit event files are unreadable or incomplete.".format(target["firewall_code"]))
            if not run_report["readable_event_count"]:
                continue
            run_events = run_report["events"]
            retained_runs += 1
            if re.fullmatch(re.escape(prefix) + r"[0-9a-f]{8}", artifact_dir.name):
                mutations += 1
            elif artifact_dir.name.startswith(prefix + "precheck-"):
                prechecks += 1
            elif expected_mutations == 0 and "-state-snapshot-" in artifact_dir.name:
                # The latest precheck path is known for legacy jobs; earlier
                # query runs had no job identity and cannot be reconstructed.
                prechecks += 1
            for event in run_events:
                event["firewall_code"] = target["firewall_code"]
                event["run_id"] = artifact_dir.name
                events.append(event)
        if mutations < expected_mutations or prechecks < expected_prechecks:
            warnings.append(
                "{0}: audit logs are incomplete ({1}/{2} mutation attempts, {3}/{4} prechecks retained); "
                "missing logs may still be recording, expired or deleted.".format(
                    target["firewall_code"], mutations, expected_mutations, prechecks, expected_prechecks,
                )
            )
    active = job["status"] in {"pending", "running", "prechecking", "applying", "verifying", "reconciling"}
    audit_status = "available" if retained_runs else "not_started"
    if warnings or (expected_runs and not retained_runs):
        audit_status = "recording" if active else ("partial" if retained_runs else "unavailable")
    return {
        "job_id": job_id,
        "events": sorted(events, key=lambda event: (
            str(event.get("created") or ""), str(event.get("run_id") or ""), int(event.get("counter") or 0),
        )),
        "audit_status": audit_status,
        "audit_warnings": warnings,
    }


def get_readiness_report() -> dict[str, Any]:
    return readiness_report(storage)


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
