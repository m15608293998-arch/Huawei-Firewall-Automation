import unittest

from pydantic import ValidationError

from api.ip_policy import validate_direct_access_target
from api.schemas import (
    TradeAccessAllowRequest,
    TradeAccessDenyRequest,
    TradeAccessIpAllowRequest,
    TradeAccessIpRequest,
    TradeAccessJobCreate,
    TradeAccessPortAllowRequest,
    TradeAccessPortDenyRequest,
)


class DirectAccessIpPolicyTests(unittest.TestCase):
    def test_rfc1918_range_boundaries_are_rejected(self) -> None:
        private_addresses = (
            "10.0.0.0",
            "10.255.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.0.0",
            "192.168.255.255",
        )

        for target_ip in private_addresses:
            with self.subTest(target_ip=target_ip):
                with self.assertRaisesRegex(ValueError, "RFC1918 private IPv4"):
                    validate_direct_access_target(target_ip)

    def test_addresses_adjacent_to_rfc1918_ranges_are_not_rejected(self) -> None:
        non_rfc1918_addresses = (
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
        )

        for target_ip in non_rfc1918_addresses:
            with self.subTest(target_ip=target_ip):
                validate_direct_access_target(target_ip)

    def test_network_overlapping_rfc1918_range_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "RFC1918 private IPv4"):
            validate_direct_access_target("172.0.0.0", 11)

    def test_every_allow_request_shape_rejects_private_target(self) -> None:
        factories = {
            "combined allow": lambda target_ip: TradeAccessAllowRequest(
                target_ip=target_ip,
                ports=[12001],
            ),
            "IP allow": lambda target_ip: TradeAccessIpAllowRequest(
                target_ip=target_ip,
            ),
            "port allow": lambda target_ip: TradeAccessPortAllowRequest(
                target_ip=target_ip,
                ports=[12001],
            ),
        }

        for label, factory in factories.items():
            for target_ip in ("10.20.30.40", "172.20.30.40", "192.168.30.40"):
                with self.subTest(request=label, target_ip=target_ip):
                    with self.assertRaisesRegex(
                        ValidationError,
                        "RFC1918 private IPv4",
                    ):
                        factory(target_ip)

    def test_internal_job_model_rejects_every_private_allow_action(self) -> None:
        requests = (
            {"action": "allow", "ports": [12001]},
            {"action": "allow_ip"},
            {"action": "allow_ports", "ports": [12001]},
        )

        for request in requests:
            with self.subTest(action=request["action"]):
                with self.assertRaisesRegex(
                    ValidationError,
                    "RFC1918 private IPv4",
                ):
                    TradeAccessJobCreate(target_ip="192.168.30.40", **request)

    def test_deny_requests_still_accept_private_target_for_cleanup(self) -> None:
        target_ip = "192.168.30.40"

        self.assertEqual(
            TradeAccessDenyRequest(target_ip=target_ip).target_ip,
            target_ip,
        )
        self.assertEqual(
            TradeAccessIpRequest(target_ip=target_ip).target_ip,
            target_ip,
        )
        self.assertEqual(
            TradeAccessPortDenyRequest(
                target_ip=target_ip,
                ports=[12001],
            ).target_ip,
            target_ip,
        )
        for request in (
            {"action": "deny"},
            {"action": "deny_ip"},
            {"action": "deny_ports", "ports": [12001]},
        ):
            with self.subTest(action=request["action"]):
                self.assertEqual(
                    TradeAccessJobCreate(target_ip=target_ip, **request).target_ip,
                    target_ip,
                )


if __name__ == "__main__":
    unittest.main()
