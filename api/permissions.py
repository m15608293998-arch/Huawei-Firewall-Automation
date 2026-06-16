VALID_PERMISSIONS = {
    "firewall.allow",
    "firewall.deny",
    "firewall.job.read",
    "firewall.job.audit",
    "identity.user.manage",
}

FIREWALL_ALLOW = "firewall.allow"
FIREWALL_DENY = "firewall.deny"
FIREWALL_JOB_READ = "firewall.job.read"
FIREWALL_JOB_AUDIT = "firewall.job.audit"
IDENTITY_USER_MANAGE = "identity.user.manage"


def validate_permission(permission: str) -> str:
    normalized = permission.strip().lower()
    if normalized not in VALID_PERMISSIONS:
        raise ValueError("Unknown permission: {0}".format(permission))
    return normalized
