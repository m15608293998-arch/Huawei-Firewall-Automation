VALID_PERMISSIONS = {
    "firewall.allow",
    "firewall.deny",
    "firewall.ip.allow",
    "firewall.ip.deny",
    "firewall.ports.allow",
    "firewall.ports.deny",
    "firewall.job.read",
    "firewall.job.audit",
    "identity.user.manage",
}

FIREWALL_ALLOW = "firewall.allow"
FIREWALL_DENY = "firewall.deny"
FIREWALL_IP_ALLOW = "firewall.ip.allow"
FIREWALL_IP_DENY = "firewall.ip.deny"
FIREWALL_PORTS_ALLOW = "firewall.ports.allow"
FIREWALL_PORTS_DENY = "firewall.ports.deny"
FIREWALL_JOB_READ = "firewall.job.read"
FIREWALL_JOB_AUDIT = "firewall.job.audit"
IDENTITY_USER_MANAGE = "identity.user.manage"


def validate_permission(permission: str) -> str:
    normalized = permission.strip().lower()
    if normalized not in VALID_PERMISSIONS:
        raise ValueError("Unknown permission: {0}".format(permission))
    return normalized
