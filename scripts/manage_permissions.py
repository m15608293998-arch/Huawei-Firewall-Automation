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
    "firewall.allow",
    "firewall.deny",
    "firewall.job.read",
}
ADMIN_PROFILE = USER_PROFILE | {
    "firewall.job.audit",
    "identity.user.manage",
}


def selected_permissions(args: argparse.Namespace) -> list[str]:
    permissions = set(args.permission or [])
    if args.profile == "user":
        permissions.update(USER_PROFILE)
    elif args.profile == "admin":
        permissions.update(ADMIN_PROFILE)
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

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--subject-id")
    args = parser.parse_args()

    storage = JobStorage(settings.database_path)
    subject_id = getattr(args, "subject_id", None)
    if args.command == "grant":
        permissions = selected_permissions(args)
        allowed_ips = selected_ips(args)
        if not permissions and not allowed_ips:
            parser.error("grant requires --profile, --permission, or --ip")
        if args.profile == "user" and not allowed_ips:
            parser.error("grant --profile user requires at least one --ip")
        for permission in permissions:
            storage.grant_subject_permission(subject_id, permission, utc_now_iso())
        for ip_address in allowed_ips:
            storage.grant_subject_allowed_ip(subject_id, ip_address, utc_now_iso())
        print(
            json.dumps(
                {
                    "subject_id": subject_id,
                    "granted_permissions": permissions,
                    "granted_ips": allowed_ips,
                },
                indent=2,
            )
        )
        return 0

    if args.command == "revoke":
        permissions = selected_permissions(args)
        allowed_ips = selected_ips(args)
        if not permissions and not allowed_ips:
            parser.error("revoke requires --profile, --permission, or --ip")
        revoked = []
        for permission in permissions:
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
    if args.subject_id:
        records = [record for record in records if record["subject_id"] == args.subject_id]
        ip_records = [record for record in ip_records if record["subject_id"] == args.subject_id]
    print(
        json.dumps(
            {
                "database_path": str(settings.database_path),
                "permissions": records,
                "allowed_ips": ip_records,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
