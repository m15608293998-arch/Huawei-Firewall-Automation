try:
    import sqlite3
except ModuleNotFoundError:
    import pysqlite3 as sqlite3
import json
import threading
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
]

class JobStorage:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)
        self._lock = threading.Lock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.execute("pragma journal_mode = wal")
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
                    local_tmp_dir text
                )
                """
            )
            self._ensure_column(conn, "jobs", "ports", "text not null default '[]'")
            self._ensure_column(conn, "jobs", "principal_id", "text")
            self._ensure_column(conn, "jobs", "principal_client_id", "text")
            self._ensure_column(conn, "jobs", "principal_key_id", "text")
            self._ensure_column(conn, "jobs", "principal_type", "text")
            self._ensure_column(conn, "jobs", "permission_code", "text")
            conn.execute(
                "create index if not exists jobs_status_created_idx "
                "on jobs (status, created_at)"
            )
            conn.execute(
                "create index if not exists jobs_principal_created_idx "
                "on jobs (principal_id, created_at)"
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

    def create_job(self, job: dict[str, Any]) -> None:
        columns = JOB_COLUMNS
        placeholders = ", ".join(["?"] * len(columns))
        column_sql = ", ".join(columns)
        # ports 是结构化字段，落 SQLite 时统一序列化为 JSON。
        values = [
            json.dumps(job.get(column) or []) if column == "ports" else job.get(column)
            for column in columns
        ]

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "insert into jobs ({0}) values ({1})".format(column_sql, placeholders),
                    values,
                )
                conn.commit()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select {0} from jobs where job_id = ?".format(", ".join(JOB_COLUMNS)),
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return self._deserialize_job(row)

    def list_jobs(
        self,
        limit: int = 100,
        offset: int = 0,
        job_status: str | None = None,
        principal_id: str | None = None,
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
        with self._connect() as conn:
            rows = conn.execute(
                "select {0} from jobs{1} order by created_at desc, job_id desc limit ? offset ?".format(
                    ", ".join(JOB_COLUMNS),
                    where_sql,
                ),
                values,
            ).fetchall()
        return [self._deserialize_job(row) for row in rows]

    def claim_next_pending_job(self, started_at: str) -> dict[str, Any] | None:
        """Atomically claim the oldest pending job for one worker."""
        with self._lock:
            with self._connect() as conn:
                # begin immediate 抢写锁，保证多个 worker 不会拿到同一个 pending job。
                conn.execute("begin immediate")
                row = conn.execute(
                    """
                    select {0}
                    from jobs
                    where status = 'pending'
                    order by created_at, job_id
                    limit 1
                    """.format(", ".join(JOB_COLUMNS))
                ).fetchone()

                if row is None:
                    conn.commit()
                    return None

                job_id = row["job_id"]
                cursor = conn.execute(
                    """
                    update jobs
                    set status = 'running', started_at = ?
                    where job_id = ? and status = 'pending'
                    """,
                    (started_at, job_id),
                )
                if cursor.rowcount != 1:
                    conn.rollback()
                    return None

                conn.commit()

        job = self._deserialize_job(row)
        job["status"] = "running"
        job["started_at"] = started_at
        return job

    def update_job(self, job_id: str, fields: dict[str, Any]) -> None:
        if not fields:
            return

        invalid = [key for key in fields if key not in JOB_COLUMNS]
        if invalid:
            raise ValueError("Invalid job columns: {0}".format(", ".join(invalid)))

        assignments = ", ".join(["{0} = ?".format(key) for key in fields])
        values = list(fields.values()) + [job_id]

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "update jobs set {0} where job_id = ?".format(assignments),
                    values,
                )
                conn.commit()

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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.database_path), timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("pragma busy_timeout = 5000")
        return conn

    @staticmethod
    def _deserialize_job(row: sqlite3.Row) -> dict[str, Any]:
        job = dict(row)
        job["ports"] = json.loads(job.get("ports") or "[]")
        return job

    def _managed_user_record(self, row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        record["enabled"] = bool(record["enabled"])
        record["permissions"] = self.get_subject_permissions(record["subject_id"])
        record["allowed_ips"] = self.get_subject_allowed_ips(record["subject_id"])
        return record
