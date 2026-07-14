from pathlib import Path

import json

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

import api.jobs as jobs_module
from api.config import settings
from api.auth import (
    Principal,
    authorize_job_read,
    authorize_trade_access_request,
    require_firewall_allow,
    require_firewall_deny,
    require_firewall_ip_allow,
    require_firewall_ip_deny,
    require_firewall_job_audit,
    require_firewall_job_read,
    require_firewall_ports_allow,
    require_firewall_ports_deny,
    require_firewall_snapshot_read,
    require_identity_user_manage,
    require_trade_access_user,
    offline_api_key_service,
)
from api.jobs import (
    create_job,
    get_admin_job_events,
    get_job_events,
    get_job_or_404,
    list_jobs,
)
from api.schemas import (
    CurrentAccessResponse,
    FirewallIpSnapshotResponse,
    FirewallPortSnapshotResponse,
    FirewallSnapshotResponse,
    JobCreateResponse,
    JobDetailResponse,
    JobEventsResponse,
    JobStatus,
    ManagedUserResponse,
    ManagedUserUpdate,
    KeycloakUserSummary,
    OfflineApiKeyAuthorizeRequest,
    OfflineApiKeyAuthorizeResponse,
    OfflineApiKeyResponse,
    OfflineApiKeyUpdateRequest,
    OidcBrowserConfigResponse,
    TradeAccessAllowRequest,
    TradeAccessDenyRequest,
    TradeAccessIpRequest,
    TradeAccessJobCreate,
    TradeAccessPortAllowRequest,
    TradeAccessPortDenyRequest,
)
from api.permissions import (
    FIREWALL_ALLOW,
    FIREWALL_DENY,
    FIREWALL_IP_ALLOW,
    FIREWALL_IP_DENY,
    FIREWALL_PORTS_ALLOW,
    FIREWALL_PORTS_DENY,
)
from api.admin_users import (
    ManagedUserValidationError,
    admin_user_service,
    keycloak_admin_client,
)
from api.keycloak_admin import (
    KeycloakAdminConfigurationError,
    KeycloakAdminError,
)
from api.offline_api_keys import (
    OfflineApiKeyConfigurationError,
    OfflineApiKeyError,
    OfflineApiKeyNotFoundError,
    OfflineApiKeyUnavailableError,
)
from api.runner_service import runner_service


app = FastAPI(
    title="Trade Access API",
    description="HTTP API wrapper for the Huawei USG6000E Ansible trade access workflow.",
    version="0.9.0",
)

TEST_UI_PATH = Path(__file__).resolve().parent / "static" / "test_ui.html"
# 页面内容启动时读入内存，生产环境改 HTML 后需要重启服务才会生效。
TEST_UI_HTML = TEST_UI_PATH.read_text(encoding="utf-8")
ADMIN_UI_PATH = Path(__file__).resolve().parent / "static" / "admin_ui.html"
ADMIN_UI_HTML = ADMIN_UI_PATH.read_text(encoding="utf-8")
app.mount(
    "/static",
    StaticFiles(directory=str(TEST_UI_PATH.parent)),
    name="static",
)


@app.get("/test-ui", include_in_schema=False)
def test_ui():
    return HTMLResponse(TEST_UI_HTML)


@app.get("/admin-ui", include_in_schema=False)
def admin_ui():
    return HTMLResponse(ADMIN_UI_HTML)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    try:
        jobs_module.storage.check_health()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Job database is unavailable.",
        ) from exc
    return {"status": "ready"}


@app.get(
    "/api/v1/auth/config",
    response_model=OidcBrowserConfigResponse,
)
def get_oidc_browser_config(portal: str = Query(default="test", pattern="^(test|admin)$")):
    # 普通测试页和管理员页使用不同的浏览器端 client，避免前端拿错登录入口。
    if portal == "admin":
        return {
            "issuer": settings.keycloak_issuer,
            "authorization_endpoint": settings.keycloak_authorization_url,
            "token_endpoint": settings.keycloak_token_url,
            "logout_endpoint": settings.keycloak_logout_url,
            "client_id": settings.keycloak_admin_browser_client_id,
            "scope": settings.keycloak_admin_browser_scope,
        }
    return {
        "issuer": settings.keycloak_issuer,
        "authorization_endpoint": settings.keycloak_authorization_url,
        "token_endpoint": settings.keycloak_token_url,
        "logout_endpoint": settings.keycloak_logout_url,
        "client_id": settings.keycloak_browser_client_id,
        "scope": settings.keycloak_browser_scope,
    }


@app.get(
    "/api/v1/trade-access/me",
    response_model=CurrentAccessResponse,
)
def get_current_trade_access(
    principal: Principal = Depends(require_trade_access_user),
):
    return {
        "subject_id": principal.subject_id,
        "subject": principal.subject,
        "subject_type": principal.subject_type,
        "client_id": principal.client_id,
        "roles": principal.roles,
        "permissions": principal.permissions,
        "allowed_ips": principal.allowed_ips,
        "is_admin": principal.is_admin,
    }


def raise_offline_api_key_error(exc: Exception) -> None:
    # service 层只抛业务异常，HTTP 状态码统一在 API 边界转换。
    if isinstance(exc, OfflineApiKeyNotFoundError):
        code = status.HTTP_404_NOT_FOUND
    elif isinstance(
        exc,
        (OfflineApiKeyConfigurationError, OfflineApiKeyUnavailableError),
    ):
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        code = status.HTTP_400_BAD_REQUEST
    raise HTTPException(status_code=code, detail=str(exc)) from exc


@app.post(
    "/api/v1/api-keys/authorize",
    response_model=OfflineApiKeyAuthorizeResponse,
)
def authorize_offline_api_key(
    request: Request,
    payload: OfflineApiKeyAuthorizeRequest,
    principal: Principal = Depends(require_trade_access_user),
):
    redirect_uri = str(request.url_for("complete_offline_api_key_authorization"))
    try:
        return offline_api_key_service.begin_authorization(
            subject_id=principal.subject_id,
            label=payload.label,
            redirect_uri=redirect_uri,
        )
    except (
        OfflineApiKeyConfigurationError,
        OfflineApiKeyError,
        OfflineApiKeyUnavailableError,
    ) as exc:
        raise_offline_api_key_error(exc)


def _api_key_callback_html(payload: dict[str, object]) -> HTMLResponse:
    # OAuth 回调页只负责把结果交给前端，避免把 api_key 留在 URL 或 referrer 里。
    serialized = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    return HTMLResponse(
        (
            '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            "<title>API Key</title></head><body><script>"
            "sessionStorage.setItem('trade-access.api-key.result',JSON.stringify({0}));"
            "window.location.replace('/test-ui');"
            "</script></body></html>"
        ).format(serialized),
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/auth/offline/callback", include_in_schema=False)
def complete_offline_api_key_authorization(
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    if error:
        return _api_key_callback_html(
            {"error": error_description or error}
        )
    if not state or not code:
        return _api_key_callback_html(
            {"error": "Keycloak callback is missing code or state."}
        )
    try:
        created = offline_api_key_service.complete_authorization(state, code)
        return _api_key_callback_html({"created": created})
    except (
        OfflineApiKeyConfigurationError,
        OfflineApiKeyError,
        OfflineApiKeyUnavailableError,
    ) as exc:
        return _api_key_callback_html({"error": str(exc)})


@app.get(
    "/api/v1/api-keys",
    response_model=list[OfflineApiKeyResponse],
)
def list_offline_api_keys(
    principal: Principal = Depends(require_trade_access_user),
):
    return offline_api_key_service.list(principal.subject_id)


@app.patch(
    "/api/v1/api-keys/{key_id}",
    response_model=OfflineApiKeyResponse,
)
def update_offline_api_key(
    key_id: str,
    payload: OfflineApiKeyUpdateRequest,
    principal: Principal = Depends(require_trade_access_user),
):
    try:
        return offline_api_key_service.update_label(
            principal.subject_id,
            key_id,
            payload.label,
        )
    except (OfflineApiKeyError, OfflineApiKeyNotFoundError) as exc:
        raise_offline_api_key_error(exc)


@app.delete("/api/v1/api-keys/{key_id}", status_code=204)
def revoke_offline_api_key(
    key_id: str,
    principal: Principal = Depends(require_trade_access_user),
):
    try:
        offline_api_key_service.revoke(principal.subject_id, key_id)
    except (OfflineApiKeyError, OfflineApiKeyNotFoundError) as exc:
        raise_offline_api_key_error(exc)
    return Response(status_code=204)


def raise_admin_user_error(exc: Exception) -> None:
    if isinstance(exc, ManagedUserValidationError):
        code = status.HTTP_400_BAD_REQUEST
    elif isinstance(exc, KeycloakAdminConfigurationError):
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        code = status.HTTP_502_BAD_GATEWAY
    raise HTTPException(status_code=code, detail=str(exc)) from exc


@app.get("/api/v1/admin/users/status")
def get_managed_user_status(
    principal: Principal = Depends(require_identity_user_manage),
):
    del principal
    return {"keycloak_provisioning_configured": keycloak_admin_client.configured}


@app.get(
    "/api/v1/admin/users",
    response_model=list[ManagedUserResponse],
)
def list_managed_users(
    principal: Principal = Depends(require_identity_user_manage),
):
    del principal
    return admin_user_service.list_users()


@app.get(
    "/api/v1/admin/users/search",
    response_model=list[KeycloakUserSummary],
)
def search_keycloak_users(
    q: str = Query(min_length=1, max_length=120),
    limit: int = Query(default=20, ge=1, le=100),
    principal: Principal = Depends(require_identity_user_manage),
):
    del principal
    try:
        return admin_user_service.search(q, limit)
    except (KeycloakAdminConfigurationError, KeycloakAdminError) as exc:
        raise_admin_user_error(exc)


@app.put(
    "/api/v1/admin/users/{subject_id}",
    response_model=ManagedUserResponse,
)
def update_managed_user(
    subject_id: str,
    request: ManagedUserUpdate,
    principal: Principal = Depends(require_identity_user_manage),
):
    del principal
    try:
        return admin_user_service.update(subject_id, request)
    except (
        ManagedUserValidationError,
        KeycloakAdminConfigurationError,
        KeycloakAdminError,
    ) as exc:
        raise_admin_user_error(exc)


@app.post(
    "/api/v1/trade-access/allow",
    response_model=JobCreateResponse,
    status_code=202,
)
def create_trade_access_allow_job(
    request: TradeAccessAllowRequest,
    principal: Principal = Depends(require_firewall_allow),
):
    # 兼容老的一键放行接口，实际落库后仍由 worker 串行执行。
    job_request = TradeAccessJobCreate(action="allow", **request.model_dump())
    authorize_trade_access_request(principal, job_request)
    return create_job(job_request, principal, FIREWALL_ALLOW)


@app.post(
    "/api/v1/trade-access/allow/ip",
    response_model=JobCreateResponse,
    status_code=202,
)
def create_trade_access_ip_allow_job(
    request: TradeAccessIpRequest,
    principal: Principal = Depends(require_firewall_ip_allow),
):
    job_request = TradeAccessJobCreate(action="allow_ip", **request.model_dump())
    authorize_trade_access_request(principal, job_request)
    return create_job(job_request, principal, FIREWALL_IP_ALLOW)


@app.post(
    "/api/v1/trade-access/allow/ports",
    response_model=JobCreateResponse,
    status_code=202,
)
def create_trade_access_ports_allow_job(
    request: TradeAccessPortAllowRequest,
    principal: Principal = Depends(require_firewall_ports_allow),
):
    job_request = TradeAccessJobCreate(action="allow_ports", **request.model_dump())
    authorize_trade_access_request(principal, job_request)
    return create_job(job_request, principal, FIREWALL_PORTS_ALLOW)


@app.post(
    "/api/v1/trade-access/deny/ports",
    response_model=JobCreateResponse,
    status_code=202,
)
def create_trade_access_ports_deny_job(
    request: TradeAccessPortDenyRequest,
    principal: Principal = Depends(require_firewall_ports_deny),
):
    job_request = TradeAccessJobCreate(action="deny_ports", **request.model_dump())
    authorize_trade_access_request(principal, job_request)
    return create_job(job_request, principal, FIREWALL_PORTS_DENY)


@app.post(
    "/api/v1/trade-access/deny/ip",
    response_model=JobCreateResponse,
    status_code=202,
)
def create_trade_access_ip_deny_job(
    request: TradeAccessIpRequest,
    principal: Principal = Depends(require_firewall_ip_deny),
):
    job_request = TradeAccessJobCreate(action="deny_ip", **request.model_dump())
    authorize_trade_access_request(principal, job_request)
    return create_job(job_request, principal, FIREWALL_IP_DENY)


@app.post(
    "/api/v1/trade-access/deny",
    response_model=JobCreateResponse,
    status_code=202,
)
def create_trade_access_deny_job(
    request: TradeAccessDenyRequest,
    principal: Principal = Depends(require_firewall_deny),
):
    job_request = TradeAccessJobCreate(action="deny", **request.model_dump())
    authorize_trade_access_request(principal, job_request)
    return create_job(job_request, principal, FIREWALL_DENY)


@app.get(
    "/api/v1/trade-access/firewall/snapshot",
    response_model=FirewallSnapshotResponse,
)
def get_firewall_snapshot(
    principal: Principal = Depends(require_firewall_snapshot_read),
):
    del principal
    result = runner_service.run_firewall_snapshot("snapshot")
    if result.rc != 0 or result.payload is None:
        detail = result.error_message or "Firewall snapshot query failed."
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
        )
    return result.payload


@app.get(
    "/api/v1/trade-access/firewall/snapshot/ips",
    response_model=FirewallIpSnapshotResponse,
)
def get_firewall_ip_snapshot(
    principal: Principal = Depends(require_firewall_snapshot_read),
):
    del principal
    result = runner_service.run_firewall_snapshot("ips")
    if result.rc != 0 or result.payload is None:
        detail = result.error_message or "Firewall IP snapshot query failed."
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
        )
    return result.payload


@app.get(
    "/api/v1/trade-access/firewall/snapshot/ports",
    response_model=FirewallPortSnapshotResponse,
)
def get_firewall_port_snapshot(
    principal: Principal = Depends(require_firewall_snapshot_read),
):
    del principal
    result = runner_service.run_firewall_snapshot("ports")
    if result.rc != 0 or result.payload is None:
        detail = result.error_message or "Firewall port snapshot query failed."
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
        )
    return result.payload


@app.get(
    "/api/v1/trade-access/jobs",
    response_model=list[JobDetailResponse],
)
def list_trade_access_jobs(
    limit: int = Query(default=100, ge=1, le=500),
    page: int = Query(default=1, ge=1, le=1_000_000),
    job_status: JobStatus | None = Query(default=None, alias="status"),
    principal: Principal = Depends(require_firewall_job_read),
):
    # 普通用户只能看到自己的任务，管理员审计接口走 include_all。
    return list_jobs(
        principal=principal,
        limit=limit,
        page=page,
        job_status=job_status.value if job_status else None,
    )


@app.get(
    "/api/v1/trade-access/jobs/{job_id}",
    response_model=JobDetailResponse,
)
def get_trade_access_job(
    job_id: str,
    principal: Principal = Depends(require_firewall_job_read),
):
    job = get_job_or_404(job_id)
    authorize_job_read(principal, job)
    return job


@app.get(
    "/api/v1/trade-access/jobs/events/{job_id}",
    response_model=JobEventsResponse,
)
def get_trade_access_job_events(
    job_id: str,
    principal: Principal = Depends(require_firewall_job_read),
):
    return {
        "job_id": job_id,
        "events": get_job_events(job_id, principal),
    }


@app.get(
    "/api/v1/admin/trade-access/jobs",
    response_model=list[JobDetailResponse],
)
def list_all_trade_access_jobs(
    limit: int = Query(default=100, ge=1, le=500),
    page: int = Query(default=1, ge=1, le=1_000_000),
    job_status: JobStatus | None = Query(default=None, alias="status"),
    principal: Principal = Depends(require_firewall_job_audit),
):
    return list_jobs(
        principal=principal,
        limit=limit,
        page=page,
        job_status=job_status.value if job_status else None,
        include_all=True,
    )


@app.get(
    "/api/v1/admin/trade-access/jobs/{job_id}",
    response_model=JobDetailResponse,
)
def get_any_trade_access_job(
    job_id: str,
    principal: Principal = Depends(require_firewall_job_audit),
):
    del principal
    return get_job_or_404(job_id)


@app.get(
    "/api/v1/admin/trade-access/jobs/events/{job_id}",
    response_model=JobEventsResponse,
)
def get_any_trade_access_job_events(
    job_id: str,
    principal: Principal = Depends(require_firewall_job_audit),
):
    del principal
    return {
        "job_id": job_id,
        "events": get_admin_job_events(job_id),
    }
