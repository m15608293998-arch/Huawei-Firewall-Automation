import inspect
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
    create_trade_access_allow_job,
    create_trade_access_deny_job,
    create_trade_access_ip_allow_job,
    create_trade_access_ip_deny_job,
    create_trade_access_ports_allow_job,
    create_trade_access_ports_deny_job,
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
    JobDetailResponse,
    TradeAccessAllowRequest,
    TradeAccessDenyRequest,
    TradeAccessIpRequest,
    TradeAccessPortAllowRequest,
    TradeAccessPortDenyRequest,
)
from api.storage import JobStorage


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
                target_ip="192.168.5.224",
                ports=[12001, 12005],
            ),
            principal=owner or self.user,
        )

    def test_user_job_creation_and_subject_scoped_read(self) -> None:
        job = self.create_job()
        self.assertEqual(job["status"], "pending")
        self.assertEqual(job["principal_id"], "user-subject")
        self.assertEqual(job["principal_client_id"], "user-subject-client")
        self.assertEqual(job["permission_code"], "firewall.allow")

        owner_job = get_trade_access_job(job_id=job["job_id"], principal=self.user)
        self.assertEqual(owner_job["ports"], [12001, 12005])

        with self.assertRaises(HTTPException) as caught:
            get_trade_access_job(job_id=job["job_id"], principal=self.other_user)
        self.assertEqual(caught.exception.status_code, 404)

    def test_user_can_submit_valid_ip_and_ports_without_sk_attributes(self) -> None:
        job = create_trade_access_allow_job(
            request=TradeAccessAllowRequest(
                target_ip="192.168.66.22",
                ports=[22, 443, 12001],
            ),
            principal=self.user,
        )
        self.assertEqual(job["target_ip"], "192.168.66.22")
        self.assertEqual(job["ports"], [22, 443, 12001])

    def test_user_secret_key_id_is_recorded_in_job_audit(self) -> None:
        sk_user = self.user.model_copy(
            update={
                "auth_type": "user_secret_key",
                "key_id": "0123456789abcdef0123456789abcdef",
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
            request=TradeAccessIpRequest(target_ip="192.168.66.22"),
            principal=self.user,
        )
        ports_allow_job = create_trade_access_ports_allow_job(
            request=TradeAccessPortAllowRequest(
                target_ip="192.168.66.22",
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
        self.assertIn(b"/api/v1/trade-access/ip/allow", response.body)
        self.assertIn(b"/api/v1/trade-access/ports/allow", response.body)
        self.assertIn(b"/api/v1/trade-access/ports/deny", response.body)
        self.assertIn(b"/api/v1/trade-access/ip/deny", response.body)
        self.assertIn("完全撤销".encode("utf-8"), response.body)
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
        self.assertIn(b"generateUserSk", response.body)
        self.assertIn(b"userSkDialog", response.body)
        self.assertIn(b'<section class="subsection hidden"', response.body)
        self.assertIn(b"showModal", response.body)
        self.assertIn("完整密钥仅显示一次".encode("utf-8"), response.body)
        self.assertIn(b"secret-keys", response.body)
        self.assertIn(b'font-family:"IBM Plex Sans","Noto Sans SC"', response.body)
        self.assertIn(b"saveFeedback", response.body)
        self.assertIn("正在保存用户授权".encode("utf-8"), response.body)
        self.assertIn("保存成功，授权已立即生效".encode("utf-8"), response.body)

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
            }
        )
        self.assertEqual(response.created_at, "2026-06-08T09:41:58.242945+08:00")
        self.assertEqual(response.started_at, "2026-06-08T09:41:58.488974+08:00")
        self.assertIsNone(response.finished_at)

    def test_user_and_admin_event_endpoints(self) -> None:
        job = self.create_job()
        original_read_events = jobs_module.runner_service.read_events
        jobs_module.runner_service.read_events = lambda artifact_dir: [
            {
                "counter": 1,
                "event": "runner_on_ok",
                "task": "Test task",
                "created": "2026-06-05T00:00:00+00:00",
            }
        ]
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
            jobs_module.runner_service.read_events = original_read_events

        self.assertEqual(user_response["events"][0]["task"], "Test task")
        self.assertEqual(admin_response["events"][0]["task"], "Test task")


if __name__ == "__main__":
    unittest.main()
