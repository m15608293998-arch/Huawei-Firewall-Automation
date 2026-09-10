import ipaddress


# This policy intentionally mirrors the three firewall-recognized RFC1918
# ranges.  IPv4Address.is_private is broader and would reject other special-use
# ranges that are outside this requirement.
RFC1918_PRIVATE_IPV4_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

DIRECT_ACCESS_ALLOW_ACTIONS = frozenset({"allow", "allow_ip", "allow_ports"})

RFC1918_PRIVATE_IPV4_ERROR = (
    "DirectAccess allow operations reject RFC1918 private IPv4 targets "
    "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
)


def validate_direct_access_target(target_ip: str, mask: int = 32) -> None:
    """Reject a DirectAccess target that overlaps an RFC1918 private network."""
    target_network = ipaddress.IPv4Network(
        "{0}/{1}".format(target_ip, mask),
        strict=True,
    )
    if any(
        target_network.overlaps(private_network)
        for private_network in RFC1918_PRIVATE_IPV4_NETWORKS
    ):
        raise ValueError(RFC1918_PRIVATE_IPV4_ERROR)
