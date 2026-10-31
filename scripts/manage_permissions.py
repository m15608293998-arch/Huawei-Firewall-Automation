#!/usr/bin/env python3.12
import argparse
import ipaddress
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from api.config import settings
from api.permissions import VALID_PERMISSIONS, validate_permission
from api.storage import JobStorage
from api.time_utils import utc_now_iso


USER_PROFILE = {
    "firewall.ip.allow",
    "firewall.ip.deny",
    "firewall.ports.allow",
    "firewall.ports.deny",
    "firewall.snapshot.read",
    "firewall.job.read",
}
ADMIN_PROFILE = set(VALID_PERMISSIONS)


def _expand_permissions(raw_permissions: set[str]) -> set[str]:
    expanded: set[str] = set()
    for permission in raw_permissions:
        normalized = validate_permission(permission)
        if normalized == "firewall.allow":
            expanded.update({"firewall.ip.allow", "firewall.ports.allow"})
        elif normalized == "firewall.deny":
            expanded.update({"firewall.ip.deny", "firewall.ports.deny"})
        else:
            expanded.add(normalized)
    return expanded


def selected_permissions(args: argparse.Namespace) -> list[str]:
    permissions = _expand_permissions(set(args.permission or []))
    # profile 是快捷模板，仍然会经过 validate_permission 做统一校验。
    if args.profile == "user":
        permissions.update(USER_PROFILE)
    elif args.profile == "admin":
        permissions.update(_expand_permissions(ADMIN_PROFILE))
    return sorted(validate_permission(permission) for permission in permissions)


def selected_ips(args: argparse.Namespace) -> list[str]:
    result = set()
    for value in args.ip or []:
        try:
            result.add(str(ipaddress.IPv4Address(value)))
        except ValueError as exc:
            raise ValueError("Invalid IPv4 address: {0}".format(value)) from exc
    return sorted(result)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Manage API operation permissions for Keycloak users by subject ID."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("grant", "revoke"):
        operation = subparsers.add_parser(command)
        operation.add_argument("--subject-id", required=True)
        operation.add_argument("--profile", choices=("user", "admin"))
        operation.add_argument(
            "--permission",
            action="append",
            choices=sorted(VALID_PERMISSIONS),
        )
        operation.add_argument(
            "--ip",
            action="append",
            help="Exact IPv4 address this subject may allow or deny; repeat as needed.",
        )
        if command == "grant":
            operation.add_argument("--username", help="Keycloak username for managed user record.")
            operation.add_argument("--display-name", help="Display name for managed user record.")
            status_group = operation.add_mutually_exclusive_group()
            status_group.add_argument("--enabled", action="store_true", help="Enable the managed user.")
            status_group.add_argument("--disabled", action="store_true", help="Disable the managed user.")

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--subject-id")
    args = parser.parse_args()

    storage = JobStorage(settings.database_path)
    subject_id = getattr(args, "subject_id", None)
    if args.command == "grant":
        permissions = selected_permissions(args)
        allowed_ips = selected_ips(args)
        if not permissions and not allowed_ips and not args.profile:
            parser.error("grant requires --profile, --permission, or --ip")
        now_iso = utc_now_iso()
        existing_user = storage.get_managed_user(subject_id)
        existing_permissions = set(storage.get_subject_permissions(subject_id))
        existing_ips = set(storage.get_subject_allowed_ips(subject_id))
        merged_permissions = sorted(existing_permissions | set(permissions))
        merged_ips = sorted(existing_ips | set(allowed_ips))
        profile = args.profile or (existing_user["profile"] if existing_user else ("admin" if "identity.user.manage" in merged_permissions or "firewall.job.audit" in merged_permissions else "user"))
        username = (args.username or (existing_user["username"] if existing_user else subject_id)).strip()
        display_name = (
            args.display_name
            if args.display_name is not None
            else (existing_user["display_name"] if existing_user else None)
        )
        if getattr(args, "disabled", False):
            enabled = False
        elif getattr(args, "enabled", False):
            enabled = True
        elif existing_user is not None:
            enabled = bool(existing_user["enabled"])
        else:
            enabled = True

        storage.save_managed_user_access(
            subject_id=subject_id,
            username=username,
            display_name=display_name,
            profile=profile,
            enabled=enabled,
            permissions=merged_permissions,
            allowed_ips=merged_ips,
            updated_at=now_iso,
        )
        print(
            json.dumps(
                {
                    "subject_id": subject_id,
                    "username": username,
                    "profile": profile,
                    "enabled": enabled,
                    "granted_permissions": permissions,
                    "granted_ips": allowed_ips,
                },
                indent=2,
            )
        )
        return 0

    if args.command == "revoke":
        raw_requested = {validate_permission(p) for p in (args.permission or [])}
        permissions = selected_permissions(args)
        permissions_to_revoke = sorted(set(permissions) | raw_requested)
        allowed_ips = selected_ips(args)
        if not permissions_to_revoke and not allowed_ips:
            parser.error("revoke requires --profile, --permission, or --ip")
        revoked = []
        for permission in permissions_to_revoke:
            removed = storage.revoke_subject_permission(subject_id, permission)
            if removed:
                revoked.append(permission)
        revoked_ips = []
        for ip_address in allowed_ips:
            removed = storage.revoke_subject_allowed_ip(subject_id, ip_address)
            if removed:
                revoked_ips.append(ip_address)
        print(
            json.dumps(
                {
                    "subject_id": subject_id,
                    "revoked_permissions": revoked,
                    "revoked_ips": revoked_ips,
                },
                indent=2,
            )
        )
        return 0

    records = storage.list_subject_permissions()
    ip_records = storage.list_subject_allowed_ips()
    managed_users = storage.list_managed_users()
    if args.subject_id:
        records = [record for record in records if record["subject_id"] == args.subject_id]
        ip_records = [record for record in ip_records if record["subject_id"] == args.subject_id]
        managed_users = [user for user in managed_users if user["subject_id"] == args.subject_id]
    print(
        json.dumps(
            {
                "database_path": str(settings.database_path),
                "managed_users": managed_users,
                "permissions": records,
                "allowed_ips": ip_records,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
