import unittest

import httpx

from api.keycloak_admin import KeycloakAdminClient


class KeycloakAdminClientTests(unittest.TestCase):
    def test_user_search_and_role_assignment_use_keycloak_user_subject(self) -> None:
        requests = []

        def response(method, url, status, payload=None):
            return httpx.Response(
                status,
                json=payload,
                request=httpx.Request(method, url),
            )

        def requester(method, url, **kwargs):
            requests.append((method, url, kwargs))
            if url.endswith("/protocol/openid-connect/token"):
                return response(method, url, 200, {"access_token": "admin-token", "expires_in": 300})
            if method == "GET" and url.endswith("/clients"):
                return response(method, url, 200, [{"id": "api-uuid", "clientId": "trade-access-api"}])
            if method == "GET" and url.endswith("/clients/api-uuid/roles/trade-access-admin"):
                return response(method, url, 200, {"id": "role-admin", "name": "trade-access-admin"})
            if method == "GET" and url.endswith("/users/user-subject/role-mappings/clients/api-uuid"):
                return response(method, url, 200, [])
            if method == "POST" and url.endswith("/users/user-subject/role-mappings/clients/api-uuid"):
                return response(method, url, 204, None)
            if method == "GET" and url.endswith("/users"):
                return response(method, url, 200, [{
                    "id": "user-subject",
                    "username": "employee-a",
                    "firstName": "Employee",
                    "lastName": "A",
                    "enabled": True,
                }])
            raise AssertionError("Unexpected request: {0} {1}".format(method, url))

        client = KeycloakAdminClient(
            token_url="https://keycloak.example/realms/trade-access/protocol/openid-connect/token",
            admin_api_url="https://keycloak.example/admin/realms/trade-access",
            admin_client_id="provisioner",
            admin_client_secret="provisioner-secret",
            resource_client_id="trade-access-api",
            user_role="trade-access-user",
            admin_role="trade-access-admin",
            requester=requester,
        )

        client.set_user_profile("user-subject", "admin")
        users = client.search_users("employee", 10)

        self.assertEqual(users[0]["subject_id"], "user-subject")
        self.assertEqual(users[0]["display_name"], "Employee A")
        role_post = next(
            item for item in requests
            if item[0] == "POST" and "/users/user-subject/role-mappings/" in item[1]
        )
        self.assertEqual(role_post[2]["json"][0]["name"], "trade-access-admin")


if __name__ == "__main__":
    unittest.main()
