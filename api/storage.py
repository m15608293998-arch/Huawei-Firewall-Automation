try:
    import sqlite3
except ModuleNotFoundError:
    import pysqlite3 as sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
import json
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


JOB_COLUMNS = [
    "job_id",
    "status",
    "action",
    "target_ip",
    "mask",
    "ports",
    "description",
    "client_request_id",
    "principal_subject",
    "principal_id",
    "principal_client_id",
    "principal_key_id",
    "principal_type",
    "auth_type",
    "permission_code",
    "runner_status",
    "runner_rc",
    "error_message",
    "created_at",
    "started_at",
    "finished_at",
    "artifact_dir",
    "local_tmp_dir",
    "firewall_targets",
    "desired_state",
    "state_version",
    "next_attempt_at",
    "deadline_at",
    "precheck_attempt_count",
    "request_fingerprint",
]

TARGET_COLUMNS = [
    "job_id",
    "firewall_code",
    "status",
    "attempt_count",
    "runner_status",
    "runner_rc",
    "error_message",
    "before_state",
    "desired_state",
    "observed_state",
    "artifact_dir",
    "local_tmp_dir",
    "started_at",
    "finished_at",
]


class IdempotencyConflictError(ValueError):
    pass


class JobStorage:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)
        self._lock = threading.Lock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.execute("pragma journal_mode = wal")
            conn.execute("begin immediate")
            # SQLite 没有独立迁移工具，这里用 create + ensure_column 做轻量升级。
            conn.execute(
                """
                create table if not exists jobs (
                    job_id text primary key,
                    status text not null,
                    action text not null,
                    target_ip text not null,
                    mask integer not null,
                    ports text not null default '[]',
                    description text,
                    client_request_id text,
                    principal_subject text,
                    principal_id text,
                    principal_client_id text,
                    principal_key_id text,
                    principal_type text,
                    auth_type text,
                    permission_code text,
                    runner_status text,
                    runner_rc integer,
                    error_message text,
                    created_at text not null,
                    started_at text,
                    finished_at text,
                    artifact_dir text,
                    local_tmp_dir text,
                    firewall_targets text not null default '[]',
                    desired_state text,
                    state_version integer,
                    next_attempt_at text
                )
                """
            )
            self._ensure_column(conn, "jobs", "ports", "text not null default '[]'")
            self._ensure_column(conn, "jobs", "principal_id", "text")
            self._ensure_column(conn, "jobs", "principal_client_id", "text")
            self._ensure_column(conn, "jobs", "principal_key_id", "text")
            self._ensure_column(conn, "jobs", "principal_type", "text")
            self._ensure_column(conn, "jobs", "permission_code", "text")
            self._ensure_column(conn, "jobs", "firewall_targets", "text not null default '[]'")
            self._ensure_column(conn, "jobs", "desired_state", "text")
            self._ensure_column(conn, "jobs", "state_version", "integer")
            self._ensure_column(conn, "jobs", "next_attempt_at", "text")
            self._ensure_column(conn, "jobs", "deadline_at", "text")
            self._ensure_column(conn, "jobs", "precheck_attempt_count", "integer not null default 0")
            self._ensure_column(conn, "jobs", "request_fingerprint", "text")
            conn.execute(
                "create unique index if not exists jobs_idempotency_idx "
                "on jobs (principal_id, client_request_id) where request_fingerprint is not null"
            )
            conn.execute(
                "create index if not exists jobs_request_lookup_idx "
                "on jobs (principal_id, client_request_id)"
            )
            conn.execute(
                "create index if not exists jobs_status_created_idx "
                "on jobs (status, created_at)"
            )
            conn.execute(
                "create index if not exists jobs_principal_created_idx "
                "on jobs (principal_id, created_at)"
            )
            conn.execute(
                "create index if not exists jobs_runnable_idx "
                "on jobs (status, next_attempt_at, created_at)"
            )
            conn.execute(
                """
                create table if not exists job_firewall_targets (
                    job_id text not null,
                    firewall_code text not null,
                    status text not null,
                    attempt_count integer not null default 0,
                    runner_status text,
                    runner_rc integer,
                    error_message text,
                    before_state text,
                    desired_state text,
                    observed_state text,
                    artifact_dir text,
                    local_tmp_dir text,
                    started_at text,
                    finished_at text,
                    primary key (job_id, firewall_code),
                    foreign key (job_id) references jobs(job_id) on delete cascade
                )
                """
            )
            conn.execute(
                "create index if not exists job_firewall_targets_status_idx "
                "on job_firewall_targets (status, job_id)"
            )
            conn.execute(
                "create table if not exists worker_heartbeats ("
                "worker_id text primary key, heartbeat_at text not null, progress_at text not null, "
                "progress_deadline_at text not null, phase text not null, job_id text, "
                "last_poll_at text, poll_error integer not null default 0)"
            )
            self._ensure_column(conn, "worker_heartbeats", "last_poll_at", "text")
            self._ensure_column(conn, "worker_heartbeats", "poll_error", "integer not null default 0")
            conn.execute("create table if not exists runtime_health_probe (id integer primary key, value integer not null)")
            conn.execute("insert or ignore into runtime_health_probe (id, value) values (1, 0)")
            conn.execute(
                """
                create table if not exists desired_access_states (
                    target_ip text primary key,
                    ip_present integer not null,
                    ports text not null,
                    version integer not null,
                    source_job_id text not null,
                    updated_at text not null
                )
                """
            )
            conn.execute(
                """
                create table if not exists subject_permissions (
                    subject_id text not null,
                    permission text not null,
                    created_at text not null,
                    primary key (subject_id, permission)
                )
                """
            )
            conn.execute(
                """
                create table if not exists subject_allowed_ips (
                    subject_id text not null,
                    ip_address text not null,
                    created_at text not null,
                    primary key (subject_id, ip_address)
                )
                """
            )
            conn.execute(
                """
                create table if not exists managed_users (
                    subject_id text primary key,
                    username text not null,
                    display_name text,
                    profile text not null,
                    enabled integer not null default 1,
                    created_at text not null,
                    updated_at text not null
                )
                """
            )
            conn.execute(
                """
                create table if not exists offline_api_keys (
                    key_id text primary key,
                    subject_id text not null,
                    label text not null,
                    token_hash text not null unique,
                    key_hint text not null,
                    encrypted_offline_token text,
                    offline_token_updated_at text,
                    created_at text not null,
                    last_used_at text,
                    revoked_at text
                )
                """
            )
            self._ensure_column(conn, "offline_api_keys", "encrypted_offline_token", "text")
            self._ensure_column(conn, "offline_api_keys", "offline_token_updated_at", "text")
            conn.execute(
                "create index if not exists offline_api_keys_subject_idx "
                "on offline_api_keys (subject_id, created_at)"
            )
            conn.execute(
                """
                create table if not exists offline_api_key_authorizations (
                    state_hash text primary key,
                    subject_id text not null,
                    label text not null,
                    code_verifier text not null,
                    redirect_uri text not null,
                    created_at text not null,
                    expires_at text not null
                )
                """
            )
            conn.execute(
                """
                insert or ignore into subject_permissions (
                    subject_id, permission, created_at
                )
                select subject_id, 'identity.user.manage', created_at
                from subject_permissions
                where permission = 'identity.client.manage'
                """
            )
            # 旧权限名迁移到新的用户管理权限，避免历史库升级后权限丢失。
            conn.execute(
                "delete from subject_permissions "
                "where permission = 'identity.client.manage'"
            )
            conn.commit()

    def _ensure_column(
        self,
        conn: sqlite3.Connection,
        table_name: str,
        column_name: str,
        column_type: str,
    ) -> None:
        columns = {
            row["name"]
            for row in conn.execute("pragma table_info({0})".format(table_name)).fetchall()
        }
        if column_name not in columns:
            conn.execute(
                "alter table {0} add column {1} {2}".format(
                    table_name,
                    column_name,
                    column_type,
                )
            )

    def record_worker_heartbeat(self, record: dict[str, Any]) -> None:
        with self._connect(timeout_seconds=0.5, existing_only=True) as conn:
            conn.execute(
                "insert into worker_heartbeats (worker_id, heartbeat_at, progress_at, progress_deadline_at, phase, job_id, last_poll_at, poll_error) "
                "values (:worker_id, :heartbeat_at, :progress_at, :progress_deadline_at, :phase, :job_id, :last_poll_at, :poll_error) "
                "on conflict(worker_id) do update set heartbeat_at=excluded.heartbeat_at, "
                "progress_at=excluded.progress_at, progress_deadline_at=excluded.progress_deadline_at, "
                "phase=excluded.phase, job_id=excluded.job_id, last_poll_at=excluded.last_poll_at, poll_error=excluded.poll_error",
                {"last_poll_at": None, "poll_error": False, **record},
            )

    def runtime_health_snapshot(self) -> dict[str, Any]:
        with self._connect(timeout_seconds=0.2, existing_only=True) as conn:
            # Commit a fixed-size health row so write/commit failures are also
            # detected. Business rows are unchanged; missing DBs are not created.
            conn.execute("begin immediate")
            conn.execute("update runtime_health_probe set value=1-value where id=1")
            workers = [dict(row) for row in conn.execute("select * from worker_heartbeats")]
            queue = dict(conn.execute(
                "select count(*) as pending_count, min(created_at) as oldest_created_at "
                "from jobs where status='pending'"
            ).fetchone())
            active_jobs = [dict(row) for row in conn.execute(
                "select job_id, deadline_at from jobs where status in "
                "('running', 'prechecking', 'applying', 'verifying', 'reconciling') "
                "and finished_at is null"
            )]
            conn.commit()
        return {"workers": workers, "queue": queue, "active_jobs": active_jobs}

    def create_job(
        self,
        job: dict[str, Any],
        firewall_targets: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        columns = JOB_COLUMNS
        placeholders = ", ".join(["?"] * len(columns))
        column_sql = ", ".join(columns)
        target_codes = list(firewall_targets or job.get("firewall_targets") or [])
        job = dict(job)
        job["firewall_targets"] = target_codes
        job["precheck_attempt_count"] = 0
        job["request_fingerprint"] = (
            self._request_fingerprint(job)
            if job.get("client_request_id") and job.get("principal_id") else None
        )
        values = [self._serialize_job_value(column, job.get(column)) for column in columns]

        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                if job["request_fingerprint"]:
                    previous = conn.execute(
                        "select * from jobs where principal_id = ? and client_request_id = ? limit 2",
                        (job["principal_id"], job["client_request_id"]),
                    ).fetchall()
                    if len(previous) > 1:
                        raise IdempotencyConflictError("This request ID belongs to multiple legacy jobs; use a new request ID.")
                    if previous:
                        existing = self._deserialize_job(previous[0])
                        if self._request_fingerprint(existing) != job["request_fingerprint"]:
                            raise IdempotencyConflictError("The request ID was already used with different request content.")
                        conn.commit()
                        return existing
                conn.execute(
                    "insert into jobs ({0}) values ({1})".format(column_sql, placeholders),
                    values,
                )
                conn.executemany(
                    """
                    insert into job_firewall_targets (
                        job_id, firewall_code, status, attempt_count, local_tmp_dir
                    ) values (?, ?, 'pending', 0, ?)
                    """,
                    [
                        (
                            job["job_id"],
                            code,
                            str(Path(str(job["local_tmp_dir"])) / code),
                        )
                        for code in target_codes
                    ],
                )
                conn.commit()
        return job

    @staticmethod
    def _request_fingerprint(job: dict[str, Any]) -> str:
        payload = {key: job.get(key) for key in ("action", "target_ip", "mask")}
        payload["ports"] = sorted({int(port) for port in job.get("ports") or []})
        payload["description"] = job.get("description") or None
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def get_job(
        self,
        job_id: str,
        include_targets: bool = False,
    ) -> dict[str, Any] | None:
        target_rows: list[sqlite3.Row] = []
        with self._connect() as conn:
            if include_targets:
                conn.execute("begin")
            row = conn.execute(
                "select {0} from jobs where job_id = ?".format(", ".join(JOB_COLUMNS)),
                (job_id,),
            ).fetchone()
            if row is not None and include_targets:
                target_rows = conn.execute(
                    "select {0} from job_firewall_targets where job_id = ? "
                    "order by firewall_code".format(", ".join(TARGET_COLUMNS)),
                    (job_id,),
                ).fetchall()
        if row is None:
            return None
        job = self._deserialize_job(row)
        if include_targets:
            job["target_results"] = [
                self._deserialize_target(target_row) for target_row in target_rows
            ]
        return job

    def ensure_job_targets(
        self,
        job_id: str,
        firewall_targets: list[str] | tuple[str, ...],
        local_tmp_dir: str,
    ) -> None:
        """Backfill child rows for jobs created before multi-target support."""
        target_codes = list(dict.fromkeys(str(code) for code in firewall_targets))
        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                conn.execute(
                    "update jobs set firewall_targets = ? where job_id = ?",
                    (json.dumps(target_codes), job_id),
                )
                conn.executemany(
                    """
                    insert or ignore into job_firewall_targets (
                        job_id, firewall_code, status, attempt_count, local_tmp_dir
                    ) values (?, ?, 'pending', 0, ?)
                    """,
                    [
                        (
                            job_id,
                            code,
                            str(Path(local_tmp_dir) / code),
                        )
                        for code in target_codes
                    ],
                )
                conn.commit()

    def list_jobs(
        self,
        limit: int = 100,
        offset: int = 0,
        job_status: str | None = None,
        principal_id: str | None = None,
        include_targets: bool = False,
    ) -> list[dict[str, Any]]:
        conditions = []
        values: list[Any] = []
        if job_status is not None:
            conditions.append("status = ?")
            values.append(job_status)
        if principal_id is not None:
            conditions.append("principal_id = ?")
            values.append(principal_id)

        where_sql = ""
        if conditions:
            where_sql = " where " + " and ".join(conditions)
        values.extend([limit, offset])

        # 条件只来自白名单参数，值仍全部走占位符绑定。
        target_rows_by_job: dict[str, list[sqlite3.Row]] = {}
        with self._connect() as conn:
            if include_targets:
                conn.execute("begin")
            rows = conn.execute(
                "select {0} from jobs{1} order by created_at desc, job_id desc limit ? offset ?".format(
                    ", ".join(JOB_COLUMNS),
                    where_sql,
                ),
                values,
            ).fetchall()
            if include_targets and rows:
                job_ids = [str(row["job_id"]) for row in rows]
                placeholders = ", ".join("?" for _ in job_ids)
                target_rows = conn.execute(
                    "select {0} from job_firewall_targets where job_id in ({1}) "
                    "order by job_id, firewall_code".format(
                        ", ".join(TARGET_COLUMNS),
                        placeholders,
                    ),
                    job_ids,
                ).fetchall()
                for target_row in target_rows:
                    target_rows_by_job.setdefault(
                        str(target_row["job_id"]),
                        [],
                    ).append(target_row)
        jobs = [self._deserialize_job(row) for row in rows]
        if include_targets:
            for job in jobs:
                job["target_results"] = [
                    self._deserialize_target(target_row)
                    for target_row in target_rows_by_job.get(str(job["job_id"]), [])
                ]
        return jobs

    def claim_next_pending_job(self, started_at: str) -> dict[str, Any] | None:
        """Atomically claim the oldest pending job."""
        return self._claim_next_job(started_at, (), include_reconciling=False)

    def claim_next_runnable_job(
        self, started_at: str, job_timeout_seconds: float | None = None,
    ) -> dict[str, Any] | None:
        """Claim a pending job or resume one interrupted by a worker crash.

        The caller must hold the cross-process parent orchestration lock.  That
        lock proves an unfinished in-progress row no longer has a live owner.
        """
        resumable_statuses = ("running", "prechecking", "applying", "verifying")
        return self._claim_next_job(
            started_at,
            resumable_statuses,
            include_reconciling=True,
            job_timeout_seconds=job_timeout_seconds,
        )

    def _claim_next_job(
        self,
        started_at: str,
        resumable_statuses: tuple[str, ...],
        include_reconciling: bool,
        job_timeout_seconds: float | None = None,
    ) -> dict[str, Any] | None:
        candidate_conditions = ["jobs.status = 'pending'"]
        query_values: list[str] = []
        if include_reconciling:
            candidate_conditions.append(
                "(jobs.status = 'reconciling' and "
                "(jobs.next_attempt_at is null or jobs.next_attempt_at <= ?))"
            )
            query_values.append(started_at)
        if resumable_statuses:
            placeholders = ", ".join("?" for _ in resumable_statuses)
            candidate_conditions.append(
                "(jobs.status in ({0}) and jobs.finished_at is null)".format(
                    placeholders
                )
            )
            query_values.extend(resumable_statuses)

        active_statuses = (
            "pending",
            "running",
            "prechecking",
            "applying",
            "verifying",
            "reconciling",
        )
        active_placeholders = ", ".join("'{0}'".format(value) for value in active_statuses)
        condition = """
            ({0})
            and not exists (
                select 1
                from jobs as earlier
                where earlier.target_ip = jobs.target_ip
                  and earlier.job_id != jobs.job_id
                  and earlier.status in ({1})
                  and (
                      earlier.created_at < jobs.created_at
                      or (
                          earlier.created_at = jobs.created_at
                          and earlier.job_id < jobs.job_id
                      )
                  )
            )
        """.format(" or ".join(candidate_conditions), active_placeholders)

        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                row = conn.execute(
                    """
                    select {0}
                    from jobs
                    where {1}
                    order by created_at, job_id
                    limit 1
                    """.format(", ".join(JOB_COLUMNS), condition),
                    tuple(query_values),
                ).fetchone()

                if row is None:
                    conn.commit()
                    return None

                job_id = row["job_id"]
                deadline_at = row["deadline_at"]
                if deadline_at is None and job_timeout_seconds is not None:
                    deadline_at = (datetime.fromisoformat(started_at) + timedelta(seconds=job_timeout_seconds)).isoformat()
                update_values: tuple[Any, ...] = (started_at, deadline_at, job_id, *query_values)
                cursor = conn.execute(
                    """
                    update jobs
                    set status = 'running',
                        started_at = coalesce(started_at, ?),
                        deadline_at = coalesce(deadline_at, ?),
                        next_attempt_at = null
                    where job_id = ?
                      and ({0})
                    """.format(condition),
                    update_values,
                )
                if cursor.rowcount != 1:
                    conn.rollback()
                    return None

                conn.commit()

        job = self._deserialize_job(row)
        job["status"] = "running"
        job["started_at"] = job.get("started_at") or started_at
        job["next_attempt_at"] = None
        job["deadline_at"] = deadline_at
        return job

    def start_job_precheck(self, job_id: str) -> int | None:
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "update jobs set status = 'prechecking', runner_status = 'initializing_baseline', "
                    "precheck_attempt_count = precheck_attempt_count + 1 "
                    "where job_id = ? and status = 'running'",
                    (job_id,),
                )
                if cursor.rowcount != 1:
                    return None
                row = conn.execute("select precheck_attempt_count from jobs where job_id = ?", (job_id,)).fetchone()
                conn.commit()
                return int(row["precheck_attempt_count"])

    def begin_job_application(self, job_id: str) -> bool:
        # This atomic boundary races safely with cancellation: once reserved,
        # the ledger and firewall may change and cancellation is no longer safe.
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "update jobs set status = 'applying', runner_status = 'applying' "
                    "where job_id = ? and status in ('running', 'prechecking')",
                    (job_id,),
                )
                conn.commit()
                return cursor.rowcount == 1

    def cancel_job(self, job_id: str, canceled_at: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                cursor = conn.execute(
                    """
                    update jobs set status = 'canceled', runner_status = 'canceled',
                        finished_at = ?, next_attempt_at = null,
                        error_message = 'Canceled before firewall configuration.'
                    where job_id = ?
                      and (status in ('pending', 'prechecking') or
                           (status = 'reconciling' and runner_status = 'precheck_retry_scheduled'))
                      and desired_state is null and state_version is null
                      and not exists (select 1 from desired_access_states where source_job_id = jobs.job_id)
                      and not exists (select 1 from job_firewall_targets
                                      where job_id = jobs.job_id and attempt_count > 0)
                    """,
                    (canceled_at, job_id),
                )
                if cursor.rowcount != 1:
                    return False
                conn.execute(
                    "update job_firewall_targets set status = 'canceled', runner_status = 'canceled', "
                    "finished_at = ? where job_id = ?",
                    (canceled_at, job_id),
                )
                conn.commit()
                return True

    def update_job(self, job_id: str, fields: dict[str, Any]) -> None:
        if not fields:
            return

        invalid = [key for key in fields if key not in JOB_COLUMNS]
        if invalid:
            raise ValueError("Invalid job columns: {0}".format(", ".join(invalid)))

        assignments = ", ".join(["{0} = ?".format(key) for key in fields])
        values = [
            self._serialize_job_value(key, value)
            for key, value in fields.items()
        ] + [job_id]

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "update jobs set {0} where job_id = ? and status != 'canceled'".format(assignments),
                    values,
                )
                conn.commit()

    def list_job_targets(self, job_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "select {0} from job_firewall_targets where job_id = ? "
                "order by firewall_code".format(", ".join(TARGET_COLUMNS)),
                (job_id,),
            ).fetchall()
        return [self._deserialize_target(row) for row in rows]

    def get_job_target(
        self,
        job_id: str,
        firewall_code: str,
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select {0} from job_firewall_targets "
                "where job_id = ? and firewall_code = ?".format(
                    ", ".join(TARGET_COLUMNS)
                ),
                (job_id, firewall_code),
            ).fetchone()
        return self._deserialize_target(row) if row is not None else None

    def update_job_target(
        self,
        job_id: str,
        firewall_code: str,
        fields: dict[str, Any],
    ) -> None:
        if not fields:
            return
        invalid = [key for key in fields if key not in TARGET_COLUMNS]
        if invalid:
            raise ValueError(
                "Invalid firewall target columns: {0}".format(", ".join(invalid))
            )
        assignments = ", ".join("{0} = ?".format(key) for key in fields)
        values = [
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            if key in {"before_state", "desired_state", "observed_state"}
            and value is not None
            else value
            for key, value in fields.items()
        ]
        values.extend([job_id, firewall_code])
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "update job_firewall_targets set {0} "
                    "where job_id = ? and firewall_code = ? "
                    "and exists (select 1 from jobs where jobs.job_id = job_firewall_targets.job_id "
                    "and jobs.status != 'canceled')".format(assignments),
                    values,
                )
                conn.commit()

    def start_job_target_attempt(
        self,
        job_id: str,
        firewall_code: str,
        status: str,
        attempt_count: int,
        started_at: str,
    ) -> None:
        """Move the parent and one child into mutation state atomically."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                conn.execute(
                    "update jobs set status = 'applying', runner_status = 'applying' "
                    "where job_id = ?",
                    (job_id,),
                )
                conn.execute(
                    "update job_firewall_targets "
                    "set status = ?, attempt_count = ?, started_at = ?, "
                    "finished_at = null, runner_status = null, runner_rc = null, "
                    "error_message = null "
                    "where job_id = ? and firewall_code = ?",
                    (status, attempt_count, started_at, job_id, firewall_code),
                )
                conn.commit()

    def mark_job_verifying_if_targets_ready(self, job_id: str) -> bool:
        """Advance the parent only when every child is verifying or verified."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                row = conn.execute(
                    "select count(*) as total, "
                    "sum(case when status in ('verifying', 'verified') then 1 else 0 end) "
                    "as ready from job_firewall_targets where job_id = ?",
                    (job_id,),
                ).fetchone()
                total = int(row["total"] or 0)
                ready = int(row["ready"] or 0)
                changed = False
                if total > 0 and ready == total:
                    cursor = conn.execute(
                        "update jobs set status = 'verifying', runner_status = 'verifying' "
                        "where job_id = ? and status in ('applying', 'verifying')",
                        (job_id,),
                    )
                    changed = cursor.rowcount == 1
                conn.commit()
        return changed

    def get_desired_access_state(self, target_ip: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select target_ip, ip_present, ports, version, source_job_id, updated_at "
                "from desired_access_states where target_ip = ?",
                (target_ip,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["ip_present"] = bool(result["ip_present"])
        result["ports"] = json.loads(result["ports"] or "[]")
        return result

    def save_desired_access_state(
        self,
        target_ip: str,
        ip_present: bool,
        ports: list[int],
        source_job_id: str,
        updated_at: str,
    ) -> dict[str, Any]:
        normalized_ports = sorted({int(port) for port in ports})
        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                row = conn.execute(
                    "select version from desired_access_states where target_ip = ?",
                    (target_ip,),
                ).fetchone()
                version = int(row["version"] if row is not None else 0) + 1
                conn.execute(
                    """
                    insert into desired_access_states (
                        target_ip, ip_present, ports, version, source_job_id, updated_at
                    ) values (?, ?, ?, ?, ?, ?)
                    on conflict(target_ip) do update set
                        ip_present = excluded.ip_present,
                        ports = excluded.ports,
                        version = excluded.version,
                        source_job_id = excluded.source_job_id,
                        updated_at = excluded.updated_at
                    """,
                    (
                        target_ip,
                        int(ip_present),
                        json.dumps(normalized_ports),
                        version,
                        source_job_id,
                        updated_at,
                    ),
                )
                conn.commit()
        return {
            "target_ip": target_ip,
            "ip_present": bool(ip_present),
            "ports": normalized_ports,
            "version": version,
            "source_job_id": source_job_id,
            "updated_at": updated_at,
        }

    def get_subject_permissions(self, subject_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                select permission
                from subject_permissions
                where subject_id = ?
                order by permission
                """,
                (subject_id,),
            ).fetchall()
        return [str(row["permission"]) for row in rows]

    def list_subject_permissions(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                select subject_id, permission, created_at
                from subject_permissions
                order by subject_id, permission
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_subject_allowed_ips(self, subject_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                select ip_address
                from subject_allowed_ips
                where subject_id = ?
                order by ip_address
                """,
                (subject_id,),
            ).fetchall()
        return [str(row["ip_address"]) for row in rows]

    def list_subject_allowed_ips(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                select subject_id, ip_address, created_at
                from subject_allowed_ips
                order by subject_id, ip_address
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def grant_subject_permission(
        self,
        subject_id: str,
        permission: str,
        created_at: str,
    ) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    insert or ignore into subject_permissions (
                        subject_id, permission, created_at
                    ) values (?, ?, ?)
                    """,
                    (subject_id, permission, created_at),
                )
                conn.commit()

    def revoke_subject_permission(self, subject_id: str, permission: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "delete from subject_permissions "
                    "where subject_id = ? and permission = ?",
                    (subject_id, permission),
                )
                conn.commit()
        return cursor.rowcount > 0

    def grant_subject_allowed_ip(
        self,
        subject_id: str,
        ip_address: str,
        created_at: str,
    ) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    insert or ignore into subject_allowed_ips (
                        subject_id, ip_address, created_at
                    ) values (?, ?, ?)
                    """,
                    (subject_id, ip_address, created_at),
                )
                conn.commit()

    def revoke_subject_allowed_ip(self, subject_id: str, ip_address: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "delete from subject_allowed_ips "
                    "where subject_id = ? and ip_address = ?",
                    (subject_id, ip_address),
                )
                conn.commit()
        return cursor.rowcount > 0

    def save_managed_user_access(
        self,
        subject_id: str,
        username: str,
        display_name: str | None,
        profile: str,
        enabled: bool,
        permissions: list[str],
        allowed_ips: list[str],
        updated_at: str,
    ) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                # 用户资料和权限/IP 列表在一个事务里更新，避免前端看到半更新状态。
                conn.execute(
                    """
                    insert into managed_users (
                        subject_id,
                        username,
                        display_name,
                        profile,
                        enabled,
                        created_at,
                        updated_at
                    ) values (?, ?, ?, ?, ?, ?, ?)
                    on conflict(subject_id) do update set
                        username = excluded.username,
                        display_name = excluded.display_name,
                        profile = excluded.profile,
                        enabled = excluded.enabled,
                        updated_at = excluded.updated_at
                    """,
                    (
                        subject_id,
                        username,
                        display_name,
                        profile,
                        int(enabled),
                        updated_at,
                        updated_at,
                    ),
                )
                self._replace_subject_access(
                    conn,
                    subject_id,
                    permissions,
                    allowed_ips,
                    updated_at,
                )
                conn.commit()

    def get_managed_user(self, subject_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                select
                    subject_id,
                    username,
                    display_name,
                    profile,
                    enabled,
                    created_at,
                    updated_at
                from managed_users
                where subject_id = ?
                """,
                (subject_id,),
            ).fetchone()
        if row is None:
            return None
        return self._managed_user_record(row)

    def list_managed_users(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                select
                    subject_id,
                    username,
                    display_name,
                    profile,
                    enabled,
                    created_at,
                    updated_at
                from managed_users
                order by username
                """
            ).fetchall()
        return [self._managed_user_record(row) for row in rows]

    def save_offline_api_key_authorization(self, record: dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "delete from offline_api_key_authorizations where expires_at <= ?",
                    (record["created_at"],),
                )
                conn.execute(
                    """
                    insert into offline_api_key_authorizations (
                        state_hash, subject_id, label, code_verifier,
                        redirect_uri, created_at, expires_at
                    ) values (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["state_hash"],
                        record["subject_id"],
                        record["label"],
                        record["code_verifier"],
                        record["redirect_uri"],
                        record["created_at"],
                        record["expires_at"],
                    ),
                )
                conn.commit()

    def consume_offline_api_key_authorization(
        self,
        state_hash: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            with self._connect() as conn:
                conn.execute("begin immediate")
                # OAuth state 读出后立即删除，回调重放会自然失败。
                row = conn.execute(
                    "select * from offline_api_key_authorizations where state_hash = ?",
                    (state_hash,),
                ).fetchone()
                conn.execute(
                    "delete from offline_api_key_authorizations where state_hash = ?",
                    (state_hash,),
                )
                conn.commit()
        return dict(row) if row is not None else None

    def create_offline_api_key(self, record: dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    insert into offline_api_keys (
                        key_id, subject_id, label, token_hash, key_hint,
                        encrypted_offline_token, offline_token_updated_at,
                        created_at, last_used_at, revoked_at
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["key_id"],
                        record["subject_id"],
                        record["label"],
                        record["token_hash"],
                        record["key_hint"],
                        record.get("encrypted_offline_token"),
                        record.get("offline_token_updated_at"),
                        record["created_at"],
                        record.get("last_used_at"),
                        record.get("revoked_at"),
                    ),
                )
                conn.commit()

    def count_active_offline_api_keys(self, subject_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                select count(*) as count
                from offline_api_keys
                where subject_id = ? and revoked_at is null
                """,
                (subject_id,),
            ).fetchone()
        return int(row["count"] if row is not None else 0)

    def get_offline_api_key_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select * from offline_api_keys where token_hash = ?",
                (token_hash,),
            ).fetchone()
        return dict(row) if row is not None else None

    def update_offline_api_key_token(
        self,
        key_id: str,
        encrypted_offline_token: str,
        updated_at: str,
    ) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    update offline_api_keys
                    set encrypted_offline_token = ?,
                        offline_token_updated_at = ?
                    where key_id = ? and revoked_at is null
                    """,
                    (encrypted_offline_token, updated_at, key_id),
                )
                conn.commit()

    def list_offline_api_keys(self, subject_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                select key_id, subject_id, label, key_hint,
                       created_at, last_used_at, revoked_at
                from offline_api_keys
                where subject_id = ? and revoked_at is null
                order by created_at desc
                """,
                (subject_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def touch_offline_api_key(self, key_id: str, used_at: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "update offline_api_keys set last_used_at = ? where key_id = ?",
                    (used_at, key_id),
                )
                conn.commit()

    def update_offline_api_key_label(
        self,
        subject_id: str,
        key_id: str,
        label: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    update offline_api_keys
                    set label = ?
                    where subject_id = ? and key_id = ? and revoked_at is null
                    """,
                    (label, subject_id, key_id),
                )
                if cursor.rowcount == 0:
                    return None
                row = conn.execute(
                    """
                    select key_id, subject_id, label, key_hint,
                           created_at, last_used_at, revoked_at
                    from offline_api_keys
                    where subject_id = ? and key_id = ?
                    """,
                    (subject_id, key_id),
                ).fetchone()
                conn.commit()
        return dict(row) if row is not None else None

    def revoke_offline_api_key(
        self,
        subject_id: str,
        key_id: str,
        revoked_at: str,
    ) -> bool:
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    update offline_api_keys
                    set revoked_at = ?
                    where subject_id = ? and key_id = ? and revoked_at is null
                    """,
                    (revoked_at, subject_id, key_id),
                )
                conn.commit()
        return cursor.rowcount > 0

    @staticmethod
    def _replace_subject_access(
        conn: sqlite3.Connection,
        subject_id: str,
        permissions: list[str],
        allowed_ips: list[str],
        updated_at: str,
    ) -> None:
        # 权限列表规模很小，整表替换比做差量更新更直接。
        conn.execute(
            "delete from subject_permissions where subject_id = ?",
            (subject_id,),
        )
        conn.executemany(
            """
            insert into subject_permissions (
                subject_id, permission, created_at
            ) values (?, ?, ?)
            """,
            [(subject_id, permission, updated_at) for permission in permissions],
        )
        conn.execute(
            "delete from subject_allowed_ips where subject_id = ?",
            (subject_id,),
        )
        conn.executemany(
            """
            insert into subject_allowed_ips (
                subject_id, ip_address, created_at
            ) values (?, ?, ?)
            """,
            [(subject_id, ip_address, updated_at) for ip_address in allowed_ips],
        )

    @contextmanager
    def _connect(self, timeout_seconds: float = 5, existing_only: bool = False) -> Iterator[sqlite3.Connection]:
        path = self.database_path.resolve().as_uri() + "?mode=rw" if existing_only else str(self.database_path)
        conn = sqlite3.connect(path, timeout=timeout_seconds, uri=existing_only)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("pragma busy_timeout = {0}".format(max(1, int(timeout_seconds * 1000))))
            # sqlite3.Connection's own context manager commits or rolls back,
            # but it does not close the connection.  Keep those transaction
            # semantics while making connection ownership explicit here.
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _deserialize_job(row: sqlite3.Row) -> dict[str, Any]:
        job = dict(row)
        job["ports"] = json.loads(job.get("ports") or "[]")
        job["firewall_targets"] = json.loads(job.get("firewall_targets") or "[]")
        if job.get("desired_state"):
            job["desired_state"] = json.loads(job["desired_state"])
        return job

    @staticmethod
    def _serialize_job_value(column: str, value: Any) -> Any:
        if column == "ports":
            return json.dumps(value or [])
        if column == "firewall_targets":
            return json.dumps(value or [])
        if column == "desired_state":
            return (
                json.dumps(value, ensure_ascii=False, sort_keys=True)
                if value is not None
                else None
            )
        return value

    @staticmethod
    def _deserialize_target(row: sqlite3.Row) -> dict[str, Any]:
        target = dict(row)
        for key in ("before_state", "desired_state", "observed_state"):
            if target.get(key):
                target[key] = json.loads(target[key])
        return target

    def _managed_user_record(self, row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        record["enabled"] = bool(record["enabled"])
        record["permissions"] = self.get_subject_permissions(record["subject_id"])
        record["allowed_ips"] = self.get_subject_allowed_ips(record["subject_id"])
        return record
