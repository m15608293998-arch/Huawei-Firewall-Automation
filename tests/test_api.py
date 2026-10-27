import inspect
import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

import api.jobs as jobs_module
from api.auth import Principal
from api.config import settings
from api.permissions import VALID_PERMISSIONS
from api.main import (
    admin_ui,
    check_firewall_consistency,
    cancel_trade_access_job,
    cancel_any_trade_access_job,
    create_trade_access_allow_job,
    create_trade_access_deny_job,
    create_trade_access_ip_allow_job,
    create_trade_access_ip_deny_job,
    create_trade_access_ports_allow_job,
    create_trade_access_ports_deny_job,
    get_firewall_ip_snapshot,
    get_firewall_port_snapshot,
    get_firewall_snapshot,
    get_any_trade_access_job,
    get_any_trade_access_job_events,
    get_trade_access_job,
    get_trade_access_job_events,
    get_current_trade_access,
    get_oidc_browser_config,
    healthz,
    list_all_trade_access_jobs,
    list_trade_access_jobs,
    test_ui,
)
from api.schemas import (
    FirewallConsistencyCheckResponse,
    FirewallIpSnapshotResponse,
    FirewallPortSnapshotResponse,
    FirewallSnapshotResponse,
    JobDetailResponse,
    TradeAccessAllowRequest,
    TradeAccessDenyRequest,
    TradeAccessIpAllowRequest,
    TradeAccessIpRequest,
    TradeAccessPortAllowRequest,
    TradeAccessPortDenyRequest,
)
from api.storage import JobStorage
from api.runner_service import SnapshotRunnerResult


def principal(subject_id: str, admin: bool = False) -> Principal:
    role = settings.keycloak_admin_role if admin else settings.keycloak_user_role
    return Principal(
        subject_id=subject_id,
        subject=subject_id,
        auth_type="keycloak_admin_bearer" if admin else "keycloak",
        roles=[role],
        client_id=subject_id + "-client",
        permissions=sorted(VALID_PERMISSIONS),
        allowed_ips=["192.168.5.224", "192.168.66.22"],
    )


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp_dir.name) / "jobs.sqlite3")
        self.original_jobs_storage = jobs_module.storage
        jobs_module.storage = self.storage
        self.user = principal("user-subject")
        self.other_user = principal("other-subject")
        self.admin = principal("admin-subject", admin=True)

    def tearDown(self) -> None:
        jobs_module.storage = self.original_jobs_storage
        self.temp_dir.cleanup()

    def create_job(self, owner: Principal | None = None):
        return create_trade_access_allow_job(
            request=TradeAccessAllowRequest(
                target_ip="203.0.113.10",
                ports=[12001, 12005],
            ),
            principal=owner or self.user,
        )

    def test_request_id_returns_existing_job_and_rejects_changed_body(self):
        request = TradeAccessAllowRequest(target_ip="203.0.113.10", ports=[443], client_request_id="retry-safe")
        first = create_trade_access_allow_job(request, self.user)
        self.storage.update_job(first["job_id"], {"status": "successful"})
        replay = create_trade_access_allow_job(request, self.user)
        self.assertEqual(replay["job_id"], first["job_id"])
        self.assertEqual(replay["status"], "successful")
        with self.assertRaises(HTTPException) as conflict:
            create_trade_access_allow_job(request.model_copy(update={"ports": [80]}), self.user)
        self.assertEqual(conflict.exception.status_code, 409)
        self.assertEqual(len(self.storage.list_jobs()), 1)

    def test_cancellation_checks_ownership_and_keeps_duplicate_request_canceled(self):
        request = TradeAccessAllowRequest(target_ip="203.0.113.10", ports=[443], client_request_id="cancel-key")
        job = create_trade_access_allow_job(request, self.user)
        with self.assertRaises(HTTPException) as unauthorized:
            cancel_trade_access_job(job["job_id"], self.other_user)
        self.assertEqual(unauthorized.exception.status_code, 404)
        canceled = cancel_trade_access_job(job["job_id"], self.user)
        self.assertEqual(canceled["status"], "canceled")
        self.assertEqual(cancel_trade_access_job(job["job_id"], self.user)["status"], "canceled")
        self.assertEqual(create_trade_access_allow_job(request, self.user)["job_id"], job["job_id"])
        self.assertEqual({target["status"] for target in canceled["target_results"]}, {"canceled"})

    def test_admin_can_cancel_pending_job_but_cannot_cancel_application(self):
        job = self.create_job()
        self.assertEqual(cancel_any_trade_access_job(job["job_id"], self.admin)["status"], "canceled")
        next_job = self.create_job()
        self.storage.update_job(next_job["job_id"], {"status": "applying"})
        with self.assertRaises(HTTPException) as conflict:
            cancel_any_trade_access_job(next_job["job_id"], self.admin)
        self.assertEqual(conflict.exception.status_code, 409)

    def test_user_job_creation_and_subject_scoped_read(self) -> None:
        job = self.create_job()
        self.assertEqual(job["status"], "pending")
        self.assertEqual(job["principal_id"], "user-subject")
        self.assertEqual(job["principal_client_id"], "user-subject-client")
        self.assertEqual(job["permission_code"], "firewall.allow")
        self.assertEqual(job["firewall_targets"], list(settings.firewall_target_codes))

        owner_job = get_trade_access_job(job_id=job["job_id"], principal=self.user)
        self.assertEqual(owner_job["ports"], [12001, 12005])
        self.assertEqual(
            [target["firewall_code"] for target in owner_job["target_results"]],
            sorted(settings.firewall_target_codes),
        )

        with self.assertRaises(HTTPException) as caught:
            get_trade_access_job(job_id=job["job_id"], principal=self.other_user)
        self.assertEqual(caught.exception.status_code, 404)

    def test_user_can_submit_non_rfc1918_ip_and_ports_without_sk_attributes(self) -> None:
        job = create_trade_access_allow_job(
            request=TradeAccessAllowRequest(
                target_ip="203.0.113.11",
                ports=[22, 443, 12001],
            ),
            principal=self.user,
        )
        self.assertEqual(job["target_ip"], "203.0.113.11")
        self.assertEqual(job["ports"], [22, 443, 12001])

    def test_offline_api_key_id_is_recorded_in_job_audit(self) -> None:
        sk_user = self.user.model_copy(
            update={
                "auth_type": "offline_api_key",
                "key_id": "offline-api-key-id",
            }
        )
        job = self.create_job(sk_user)
        self.assertEqual(job["principal_key_id"], sk_user.key_id)
        self.assertEqual(job["principal_id"], sk_user.subject_id)

    def test_allow_and_deny_endpoints_set_action_server_side(self) -> None:
        allow_job = self.create_job()
        deny_job = create_trade_access_deny_job(
            request=TradeAccessDenyRequest(target_ip="192.168.66.22"),
            principal=self.user,
        )

        self.assertEqual(allow_job["action"], "allow")
        self.assertEqual(deny_job["action"], "deny")
        self.assertEqual(deny_job["ports"], [])

    def test_split_firewall_endpoints_set_action_and_permission_code(self) -> None:
        ip_allow_job = create_trade_access_ip_allow_job(
            request=TradeAccessIpAllowRequest(target_ip="203.0.113.11"),
            principal=self.user,
        )
        ports_allow_job = create_trade_access_ports_allow_job(
            request=TradeAccessPortAllowRequest(
                target_ip="203.0.113.11",
                ports=[12001, 12002],
            ),
            principal=self.user,
        )
        ports_deny_job = create_trade_access_ports_deny_job(
            request=TradeAccessPortDenyRequest(
                target_ip="192.168.66.22",
                ports=[12002],
            ),
            principal=self.user,
        )
        ip_deny_job = create_trade_access_ip_deny_job(
            request=TradeAccessIpRequest(target_ip="192.168.66.22"),
            principal=self.user,
        )

        self.assertEqual(ip_allow_job["action"], "allow_ip")
        self.assertEqual(ip_allow_job["ports"], [])
        self.assertEqual(ip_allow_job["permission_code"], "firewall.ip.allow")
        self.assertEqual(ports_allow_job["action"], "allow_ports")
        self.assertEqual(ports_allow_job["ports"], [12001, 12002])
        self.assertEqual(ports_allow_job["permission_code"], "firewall.ports.allow")
        self.assertEqual(ports_deny_job["action"], "deny_ports")
        self.assertEqual(ports_deny_job["ports"], [12002])
        self.assertEqual(ports_deny_job["permission_code"], "firewall.ports.deny")
        self.assertEqual(ip_deny_job["action"], "deny_ip")
        self.assertEqual(ip_deny_job["ports"], [])
        self.assertEqual(ip_deny_job["permission_code"], "firewall.ip.deny")

    def test_user_list_is_scoped_and_admin_list_contains_all_jobs(self) -> None:
        own_job = self.create_job(self.user)
        other_job = self.create_job(self.other_user)

        user_jobs = list_trade_access_jobs(
            limit=100,
            page=1,
            job_status=None,
            principal=self.user,
        )
        admin_jobs = list_all_trade_access_jobs(
            limit=100,
            page=1,
            job_status=None,
            principal=self.admin,
        )

        self.assertEqual([job["job_id"] for job in user_jobs], [own_job["job_id"]])
        self.assertEqual(
            {job["job_id"] for job in admin_jobs},
            {own_job["job_id"], other_job["job_id"]},
        )

    def test_admin_endpoint_can_read_another_subject_job(self) -> None:
        job = self.create_job(self.user)
        response = get_any_trade_access_job(job_id=job["job_id"], principal=self.admin)
        self.assertEqual(response["job_id"], job["job_id"])

    def test_firewall_snapshot_endpoint_returns_runner_payload(self) -> None:
        import api.main as main_module

        original_runner = main_module.runner_service.run_reconciled_snapshot
        payload = {
            "generated_at": "2026-07-03T10:30:00+08:00",
            "items": [
                {
                    "ip": "192.168.66.22",
                    "port": 12001,
                }
            ],
        }
        main_module.runner_service.run_reconciled_snapshot = lambda snapshot_mode="snapshot": SnapshotRunnerResult(
            status="successful",
            rc=0,
            artifact_dir="/tmp/artifacts/snapshot",
            payload=payload,
        )
        try:
            response = asyncio.run(get_firewall_snapshot(principal=self.user))
        finally:
            main_module.runner_service.run_reconciled_snapshot = original_runner

        validated = FirewallSnapshotResponse.model_validate(response)
        self.assertEqual(validated.items[0].ip, "192.168.66.22")
        self.assertEqual(validated.items[0].port, 12001)

    def test_split_firewall_snapshot_endpoints_use_separate_modes(self) -> None:
        import api.main as main_module

        original_runner = main_module.runner_service.run_reconciled_snapshot
        requested_modes = []

        def fake_snapshot(snapshot_mode="snapshot"):
            requested_modes.append(snapshot_mode)
            if snapshot_mode == "ips":
                payload = {
                    "generated_at": "2026-07-03T10:30:00+08:00",
                    "items": [
                        {
                            "ip": "192.168.66.22",
                        }
                    ],
                }
            else:
                payload = {
                    "generated_at": "2026-07-03T10:30:00+08:00",
                    "items": [
                        {
                            "ip": "192.168.66.22",
                            "port": 12001,
                        }
                    ],
                }
            return SnapshotRunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/artifacts/snapshot",
                payload=payload,
            )

        main_module.runner_service.run_reconciled_snapshot = fake_snapshot
        try:
            ip_response = asyncio.run(get_firewall_ip_snapshot(principal=self.user))
            port_response = asyncio.run(get_firewall_port_snapshot(principal=self.user))
        finally:
            main_module.runner_service.run_reconciled_snapshot = original_runner

        self.assertEqual(requested_modes, ["ips", "ports"])
        self.assertEqual(
            FirewallIpSnapshotResponse.model_validate(ip_response).items[0].ip,
            "192.168.66.22",
        )
        self.assertEqual(
            FirewallPortSnapshotResponse.model_validate(port_response).items[0].port,
            12001,
        )

    def test_firewall_snapshot_endpoint_reports_runner_failure(self) -> None:
        import api.main as main_module

        original_runner = main_module.runner_service.run_reconciled_snapshot
        main_module.runner_service.run_reconciled_snapshot = lambda snapshot_mode="snapshot": SnapshotRunnerResult(
            status="failed",
            rc=1,
            artifact_dir="/tmp/artifacts/snapshot",
            error_message="snapshot failed",
        )
        try:
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(get_firewall_snapshot(principal=self.user))
        finally:
            main_module.runner_service.run_reconciled_snapshot = original_runner

        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(caught.exception.detail["message"], "snapshot failed")

    def test_firewall_snapshot_endpoint_reports_cross_firewall_drift(self) -> None:
        import api.main as main_module

        original_runner = main_module.runner_service.run_reconciled_snapshot
        drift_payload = {
            "consistency_status": "drifted",
            "firewalls": {
                "PG-FW": {"status": "ok", "count": 1},
                "IDC-FW": {"status": "ok", "count": 0},
            },
            "differences": {
                "IDC-FW": {"missing": [{"ip": "192.168.66.22"}]},
            },
        }
        main_module.runner_service.run_reconciled_snapshot = lambda snapshot_mode="snapshot": SnapshotRunnerResult(
            status="drifted",
            rc=2,
            artifact_dir="",
            payload=drift_payload,
            error_message="Firewall snapshots are not logically consistent.",
        )
        try:
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(get_firewall_snapshot(principal=self.user))
        finally:
            main_module.runner_service.run_reconciled_snapshot = original_runner

        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(
            caught.exception.detail["reconciliation"]["consistency_status"],
            "drifted",
        )

    def test_clean_snapshot_queries_are_blocked_while_parent_reconciles(self) -> None:
        import api.main as main_module

        job = self.create_job()
        self.storage.update_job(
            job["job_id"],
            {
                "status": "reconciling",
                "next_attempt_at": "2026-07-21T10:00:30+00:00",
                "error_message": "IDC-FW did not reach desired state.",
            },
        )
        original_runner = main_module.runner_service.run_reconciled_snapshot
        runner_called = False

        def unexpected_snapshot(snapshot_mode="snapshot"):
            nonlocal runner_called
            runner_called = True
            raise AssertionError("clean snapshot runner must not be called")

        main_module.runner_service.run_reconciled_snapshot = unexpected_snapshot
        try:
            for endpoint in (
                get_firewall_snapshot,
                get_firewall_ip_snapshot,
                get_firewall_port_snapshot,
            ):
                with self.assertRaises(HTTPException) as caught:
                    asyncio.run(endpoint(principal=self.user))
                self.assertEqual(caught.exception.status_code, 409)
                self.assertEqual(
                    caught.exception.detail["blocking_jobs"][0]["job_id"],
                    job["job_id"],
                )
                self.assertEqual(
                    caught.exception.detail["check_endpoint"],
                    "/api/v1/trade-access/firewall/check",
                )
        finally:
            main_module.runner_service.run_reconciled_snapshot = original_runner

        self.assertFalse(runner_called)

    def test_consistency_check_remains_available_while_parent_reconciles(self) -> None:
        import api.main as main_module

        job = self.create_job()
        self.storage.update_job(
            job["job_id"],
            {
                "status": "reconciling",
                "next_attempt_at": "2026-07-21T10:00:30+00:00",
            },
        )
        original_runner = main_module.runner_service.run_firewall_consistency_check
        main_module.runner_service.run_firewall_consistency_check = lambda: SnapshotRunnerResult(
            status="drifted",
            rc=0,
            artifact_dir="",
            payload={"overall_status": "drifted"},
        )
        try:
            response = asyncio.run(check_firewall_consistency(principal=self.user))
        finally:
            main_module.runner_service.run_firewall_consistency_check = original_runner

        self.assertEqual(response["overall_status"], "drifted")

    def test_firewall_check_returns_drift_report_as_successful_http_payload(self) -> None:
        import api.main as main_module

        original_runner = main_module.runner_service.run_firewall_consistency_check
        payload = {
            "checked_at": "2026-07-21T10:00:00+08:00",
            "overall_status": "drifted",
            "reference_strategy": "strict_majority_of_all_configured_firewalls",
            "firewall_codes": ["PG-FW", "PG-FW-1", "IDC-FW"],
            "summary": {
                "configured_firewall_count": 3,
                "successful_firewall_count": 3,
                "ip_consistent": False,
                "port_consistent": True,
                "ip_drift_item_count": 1,
                "port_drift_item_count": 0,
                "suggested_action_count": 1,
                "ambiguous_item_count": 0,
            },
            "firewalls": {
                code: {
                    "query_status": "successful",
                    "generated_at": "2026-07-21T10:00:00+08:00",
                    "artifact_dir": "/tmp/{0}".format(code),
                    "ip_count": 1 if code != "IDC-FW" else 0,
                    "port_count": 0,
                    "error_message": None,
                    "ip_missing": (
                        [{"ip": "192.168.66.22"}] if code == "IDC-FW" else []
                    ),
                    "ip_extra": [],
                    "port_missing": [],
                    "port_extra": [],
                    "suggested_actions": (
                        [
                            {
                                "firewall_code": "IDC-FW",
                                "action": "add_ip",
                                "ip": "192.168.66.22",
                                "present_on_firewalls": ["PG-FW", "PG-FW-1"],
                                "absent_on_firewalls": ["IDC-FW"],
                                "reason": "Present on 2/3 firewalls; strict majority suggests adding it.",
                            }
                        ]
                        if code == "IDC-FW"
                        else []
                    ),
                }
                for code in ("PG-FW", "PG-FW-1", "IDC-FW")
            },
            "differences": {
                "ips": [
                    {
                        "ip": "192.168.66.22",
                        "present_on_firewalls": ["PG-FW", "PG-FW-1"],
                        "absent_on_firewalls": ["IDC-FW"],
                        "reference_state": "present",
                    }
                ],
                "ports": [],
            },
            "warning": "Verify intended business state before manual changes.",
        }
        main_module.runner_service.run_firewall_consistency_check = lambda: SnapshotRunnerResult(
            status="drifted",
            rc=0,
            artifact_dir="",
            payload=payload,
        )
        try:
            response = asyncio.run(check_firewall_consistency(principal=self.user))
        finally:
            main_module.runner_service.run_firewall_consistency_check = original_runner

        validated = FirewallConsistencyCheckResponse.model_validate(response)
        self.assertEqual(validated.overall_status, "drifted")
        self.assertEqual(
            validated.firewalls["IDC-FW"].suggested_actions[0].action,
            "add_ip",
        )

    def test_firewall_check_reports_incomplete_query_as_service_unavailable(self) -> None:
        import api.main as main_module

        original_runner = main_module.runner_service.run_firewall_consistency_check
        main_module.runner_service.run_firewall_consistency_check = lambda: SnapshotRunnerResult(
            status="failed",
            rc=1,
            artifact_dir="",
            payload={"overall_status": "incomplete"},
            error_message="One or more firewall consistency-check queries failed.",
        )
        try:
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(check_firewall_consistency(principal=self.user))
        finally:
            main_module.runner_service.run_firewall_consistency_check = original_runner

        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(caught.exception.detail["check"]["overall_status"], "incomplete")

    def test_api_job_creation_has_no_background_task_parameter(self) -> None:
        allow_parameters = inspect.signature(create_trade_access_allow_job).parameters
        deny_parameters = inspect.signature(create_trade_access_deny_job).parameters
        self.assertNotIn("background_tasks", allow_parameters)
        self.assertNotIn("background_tasks", deny_parameters)

    def test_health_endpoint(self) -> None:
        self.assertEqual(healthz(), {"status": "ok"})

    def test_oidc_browser_config_uses_public_portal_client(self) -> None:
        response = get_oidc_browser_config("test")
        self.assertEqual(response["client_id"], settings.keycloak_browser_client_id)
        self.assertIn("/protocol/openid-connect/auth", response["authorization_endpoint"])
        self.assertIn("openid", response["scope"])
        self.assertNotIn("offline_access", response["scope"])

    def test_admin_oidc_browser_config_uses_trade_access_admin_portal(self) -> None:
        response = get_oidc_browser_config("admin")
        self.assertEqual(
            response["client_id"],
            settings.keycloak_admin_browser_client_id,
        )
        self.assertIn("/realms/trade-access/", response["authorization_endpoint"])

    def test_admin_oidc_refresh_tokens_remain_in_browser_session(self) -> None:
        oidc_source = (
            Path(__file__).resolve().parents[1] / "api" / "static" / "oidc.js"
        ).read_text(encoding="utf-8")
        self.assertIn("sessionStorage.setItem(TOKEN_KEY", oidc_source)
        self.assertIn('PORTAL = window.location.pathname.startsWith("/admin-ui")', oidc_source)
        self.assertIn("portal=${encodeURIComponent(PORTAL)}", oidc_source)
        self.assertIn('grant_type: "refresh_token"', oidc_source)
        self.assertIn("now + 30", oidc_source)

    def test_current_access_reports_assigned_ips(self) -> None:
        response = get_current_trade_access(self.user)
        self.assertEqual(response["client_id"], "user-subject-client")
        self.assertEqual(
            response["allowed_ips"],
            ["192.168.5.224", "192.168.66.22"],
        )
        self.assertFalse(response["is_admin"])

    def test_test_ui_endpoint_serves_html(self) -> None:
        response = test_ui()
        self.assertEqual(response.media_type, "text/html")
        self.assertIn(b"Trade Access API", response.body)
        self.assertIn(b"/static/oidc.js", response.body)
        self.assertIn(b"tradeAccessOidc.login", response.body)
        self.assertIn(b"authenticatedFetch", response.body)
        self.assertIn("创建 API Key".encode("utf-8"), response.body)
        self.assertIn(b"/api/v1/api-keys/authorize", response.body)
        self.assertIn(b"generatedApiKey", response.body)
        self.assertIn("完整 API Key 仅显示一次".encode("utf-8"), response.body)
        self.assertIn("删除 API Key".encode("utf-8"), response.body)
        self.assertIn("修改 API Key".encode("utf-8"), response.body)
        self.assertIn("最新使用日期".encode("utf-8"), response.body)
        self.assertIn(b"editApiKeyDialog", response.body)
        self.assertIn(b"deleteApiKeyDialog", response.body)
        self.assertIn(b'method: "PATCH"', response.body)
        self.assertNotIn(b"window.confirm", response.body)
        self.assertIn("登录成功，初始化失败".encode("utf-8"), response.body)
        self.assertIn(b"isLoginFailure", response.body)
        self.assertIn("当前账号没有任务查询权限".encode("utf-8"), response.body)
        self.assertIn(b"hasJobReadPermission", response.body)
        self.assertIn(b"/api/v1/trade-access/allow/ip", response.body)
        self.assertIn(b"/api/v1/trade-access/allow/ports", response.body)
        self.assertIn(b"/api/v1/trade-access/deny/ports", response.body)
        self.assertIn(b"/api/v1/trade-access/deny/ip", response.body)
        self.assertIn(b"/api/v1/trade-access/jobs/events/", response.body)
        self.assertIn(b"/api/v1/trade-access/firewall/check", response.body)
        self.assertIn(b"queryFirewallCheck", response.body)
        self.assertIn(b"renderConsistencyCheck", response.body)
        self.assertIn(b"renderJobTargetResults", response.body)
        self.assertIn(b"selectedJobId", response.body)
        self.assertIn(b"listJobs(false, job)", response.body)
        self.assertIn(b"getJob().then(followJob)", response.body)
        self.assertIn("需人工处理".encode("utf-8"), response.body)
        self.assertIn("多防火墙执行结果".encode("utf-8"), response.body)
        self.assertIn("人工纠错建议".encode("utf-8"), response.body)
        self.assertNotIn(b"/api/v1/trade-access/ip/allow", response.body)
        self.assertNotIn(b"/api/v1/trade-access/ports/allow", response.body)
        self.assertNotIn(b"/api/v1/trade-access/ports/deny", response.body)
        self.assertNotIn(b"/api/v1/trade-access/ip/deny", response.body)
        self.assertIn("只放行目标 IP，不配置端口".encode("utf-8"), response.body)
        self.assertIn("取消 IP 前必须先删除此 IP 的所有端口".encode("utf-8"), response.body)
        self.assertIn("完全撤销".encode("utf-8"), response.body)
        self.assertNotIn(b"profile.allowed_ips.join", response.body)
        self.assertNotIn(b"allowedTargetIp", response.body)
        self.assertNotIn("管理员分配的 IP".encode("utf-8"), response.body)
        self.assertIn("上一页".encode("utf-8"), response.body)
        self.assertIn("下一页".encode("utf-8"), response.body)
        self.assertIn(b"jobsPaginationMeta", response.body)
        self.assertNotIn(b"Keycloak Access Token", response.body)
        self.assertNotIn(b"copyAccessToken", response.body)
        self.assertNotIn(b"trade_access_user_sk", response.body)
        self.assertNotIn("验证 SK".encode("utf-8"), response.body)
        self.assertNotIn(b"X-API-Key", response.body)

    def test_admin_ui_endpoint_serves_html(self) -> None:
        response = admin_ui()
        self.assertEqual(response.media_type, "text/html")
        self.assertIn("MicroTrade Access 用户管理平台".encode("utf-8"), response.body)
        self.assertIn(b"/static/oidc.js", response.body)
        self.assertIn("更新时间".encode("utf-8"), response.body)
        self.assertIn(b' timeZone:"Asia/Shanghai"', response.body)
        self.assertIn("刷新列表".encode("utf-8"), response.body)
        self.assertNotIn("机器 Client".encode("utf-8"), response.body)
        self.assertNotIn(b"generateUserSk", response.body)
        self.assertNotIn(b"userSkDialog", response.body)
        self.assertNotIn(b"showModal", response.body)
        self.assertNotIn(b"secret-keys", response.body)
        self.assertIn(b'font-family:"IBM Plex Sans","Noto Sans SC"', response.body)
        self.assertIn(b"saveFeedback", response.body)
        self.assertIn("正在保存用户授权".encode("utf-8"), response.body)
        self.assertIn("保存成功，授权已立即生效".encode("utf-8"), response.body)
        self.assertIn(b"/api/v1/trade-access/firewall/check", response.body)
        self.assertIn(b"queryFirewallCheck", response.body)
        self.assertIn(b"renderConsistencyCheck", response.body)
        self.assertIn("人工纠错建议".encode("utf-8"), response.body)
        self.assertNotIn(b"userAllowedIps", response.body)
        self.assertNotIn("允许操作的精确 IP".encode("utf-8"), response.body)
        self.assertNotIn("IP 数量".encode("utf-8"), response.body)

    def test_job_detail_times_are_serialized_as_china_standard_time(self) -> None:
        response = JobDetailResponse.model_validate(
            {
                "job_id": "job-timezone",
                "status": "successful",
                "action": "allow",
                "target_ip": "192.168.5.224",
                "mask": 32,
                "created_at": "2026-06-08T01:41:58.242945+00:00",
                "started_at": "2026-06-08T01:41:58.488974Z",
                "finished_at": None,
                "next_attempt_at": "2026-06-08T01:42:28.488974+00:00",
            }
        )
        self.assertEqual(response.created_at, "2026-06-08T09:41:58.242945+08:00")
        self.assertEqual(response.started_at, "2026-06-08T09:41:58.488974+08:00")
        self.assertIsNone(response.finished_at)
        self.assertEqual(
            response.next_attempt_at,
            "2026-06-08T09:42:28.488974+08:00",
        )

    def test_user_and_admin_event_endpoints(self) -> None:
        job = self.create_job()
        run = Path(self.temp_dir.name) / (job["job_id"] + "-" + settings.firewall_target_codes[0] + "-123456ab")
        (run / "job_events").mkdir(parents=True)
        (run / "job_events/1-event.json").write_text("{}")
        self.storage.update_job_target(job["job_id"], settings.firewall_target_codes[0], {"artifact_dir": str(run), "attempt_count": 1})
        original_read_events = jobs_module.runner_service.read_event_report
        jobs_module.runner_service.read_event_report = lambda artifact_dir, detailed=False: {"readable_event_count": 1, "unreadable_event_count": 0, "events": [
            {
                "counter": 1,
                "event": "runner_on_ok",
                "task": "Test task",
                "created": "2026-06-05T00:00:00+00:00",
            }
        ]}
        try:
            user_response = get_trade_access_job_events(
                job_id=job["job_id"],
                principal=self.user,
            )
            admin_response = get_any_trade_access_job_events(
                job_id=job["job_id"],
                principal=self.admin,
            )
        finally:
            jobs_module.runner_service.read_event_report = original_read_events

        self.assertEqual(user_response["events"][0]["task"], "Test task")
        self.assertEqual(admin_response["events"][0]["task"], "Test task")


if __name__ == "__main__":
    unittest.main()
