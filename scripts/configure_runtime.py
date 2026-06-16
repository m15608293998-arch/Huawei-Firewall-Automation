#!/usr/bin/env python3.12
import argparse
import getpass
import os
import shlex
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / ".runtime" / "trade-access.env"


def shell_value(value: str) -> str:
    return shlex.quote(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create the persistent local runtime environment file."
    )
    parser.add_argument(
        "--keycloak-server-url",
        default="http://192.168.6.30:8080",
    )
    parser.add_argument("--realm", default="trade-access")
    parser.add_argument("--resource-client-id", default="trade-access-api")
    parser.add_argument("--browser-client-id", default="trade-access-portal")
    parser.add_argument(
        "--browser-scope",
        default="openid profile email",
    )
    parser.add_argument(
        "--admin-browser-client-id",
        default="trade-access-admin-portal",
    )
    parser.add_argument(
        "--admin-browser-scope",
        default="openid profile email",
    )
    parser.add_argument("--offline-client-id", default="trade-access-offline")
    parser.add_argument(
        "--offline-client-scope",
        default="openid profile offline_access",
    )
    parser.add_argument("--user-role", default="trade-access-user")
    parser.add_argument("--admin-role", default="trade-access-admin")
    parser.add_argument("--admin-client-id", default="trade-access-provisioner")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    provisioning_secret = getpass.getpass("Provisioning Client Secret: ").strip()
    if not provisioning_secret:
        parser.error("Provisioning Client Secret must not be empty")
    offline_client_secret = getpass.getpass("Offline API Key Client Secret: ").strip()
    if not offline_client_secret:
        parser.error("Offline API Key Client Secret must not be empty")

    values = {
        "TRADE_ACCESS_API_AUTH_ENABLED": "true",
        "TRADE_ACCESS_API_LEGACY_USER_SECRET_KEY_AUTH_ENABLED": "false",
        "TRADE_ACCESS_API_KEYCLOAK_SERVER_URL": args.keycloak_server_url.rstrip("/"),
        "TRADE_ACCESS_API_KEYCLOAK_REALM": args.realm,
        "TRADE_ACCESS_API_KEYCLOAK_CLIENT_ID": args.resource_client_id,
        "TRADE_ACCESS_API_KEYCLOAK_BROWSER_CLIENT_ID": args.browser_client_id,
        "TRADE_ACCESS_API_KEYCLOAK_BROWSER_SCOPE": args.browser_scope,
        "TRADE_ACCESS_API_KEYCLOAK_ADMIN_BROWSER_CLIENT_ID": args.admin_browser_client_id,
        "TRADE_ACCESS_API_KEYCLOAK_ADMIN_BROWSER_SCOPE": args.admin_browser_scope,
        "TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_ID": args.offline_client_id,
        "TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_SECRET": offline_client_secret,
        "TRADE_ACCESS_API_KEYCLOAK_OFFLINE_SCOPE": args.offline_client_scope,
        "TRADE_ACCESS_API_KEYCLOAK_USER_ROLE": args.user_role,
        "TRADE_ACCESS_API_KEYCLOAK_ADMIN_ROLE": args.admin_role,
        "TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_ID": args.admin_client_id,
        "TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_SECRET": provisioning_secret,
    }
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        "{0}={1}".format(name, shell_value(value))
        for name, value in values.items()
    ) + "\n"
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(output)
    os.chmod(output, 0o600)

    print("Runtime environment saved to {0}".format(output))
    print("File mode: 600")
    print("Start services with: python3.12 scripts/run_services.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
