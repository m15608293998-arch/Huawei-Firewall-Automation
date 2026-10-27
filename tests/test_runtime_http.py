import asyncio
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import httpx

from api import jobs
from api import main
from api.auth import Principal
from api.config import settings
from api.permissions import VALID_PERMISSIONS
from api.query_capacity import DeviceQueryCoordinator
from api.runner_service import SnapshotRunnerResult
from api.storage import JobStorage


class RuntimeHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp.name) / "jobs.sqlite3")
        self.pool = DeviceQueryCoordinator()
        self.release, self.entered = threading.Event(), threading.Event()
        self.calls = 0
        self.principal = Principal(
            subject_id="load-user", subject="load-user", auth_type="keycloak_bearer",
            roles=[settings.keycloak_user_role], permissions=sorted(VALID_PERMISSIONS),
        )

        async def authorized():
            return self.principal

        self.original_overrides = dict(main.app.dependency_overrides)
        for dependency in (main.require_firewall_snapshot_read, main.require_firewall_allow, main.require_firewall_job_read):
            main.app.dependency_overrides[dependency] = authorized
        self.contexts = [
            patch.object(jobs, "storage", self.storage),
            patch.object(main, "query_coordinator", self.pool),
            patch.object(main.runner_service, "run_reconciled_snapshot", self.slow_snapshot),
        ]
        for context in self.contexts:
            context.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://local-test")
        now = datetime.now(timezone.utc)
        self.storage.record_worker_heartbeat({
            "worker_id": "load-worker", "heartbeat_at": now.isoformat(), "progress_at": now.isoformat(),
            "progress_deadline_at": (now + timedelta(seconds=60)).isoformat(),
            "last_poll_at": now.isoformat(), "phase": "idle", "job_id": None,
        })

    async def asyncTearDown(self):
        self.release.set()
        await self.client.aclose()
        self.pool.close()
        for context in reversed(self.contexts):
            context.stop()
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(self.original_overrides)
        self.temp.cleanup()

    def slow_snapshot(self, mode="snapshot"):
        self.calls += 1
        self.entered.set()
        if not self.release.wait(5):
            raise AssertionError("Local HTTP query fixture was not released")
        return SnapshotRunnerResult("successful", 0, "", payload={
            "generated_at": "2026-10-27T00:00:00+00:00",
            "items": [{"ip": "203.0.113.10", **({} if mode == "ips" else {"port": 443})}],
        })

    async def test_snapshot_burst_keeps_health_submission_and_job_reads_responsive(self):
        leader = asyncio.create_task(self.client.get("/api/v1/trade-access/firewall/snapshot/ips"))
        self.assertTrue(await asyncio.to_thread(self.entered.wait, 1))
        try:
            burst = await asyncio.wait_for(asyncio.gather(*[
                self.client.get("/api/v1/trade-access/firewall/snapshot/ports") for _ in range(100)
            ]), timeout=2)
            self.assertTrue(all(response.status_code == 503 and response.headers["retry-after"] == "1" for response in burst))
            health, ready, accepted = await asyncio.wait_for(asyncio.gather(
                self.client.get("/healthz"), self.client.get("/readyz"),
                self.client.post("/api/v1/trade-access/allow", json={"target_ip": "203.0.113.10", "ports": [443]}),
            ), timeout=2)
            self.assertEqual([health.status_code, ready.status_code, accepted.status_code], [200, 200, 202])
            detail = await asyncio.wait_for(self.client.get("/api/v1/trade-access/jobs/" + accepted.json()["job_id"]), 2)
            self.assertEqual(detail.status_code, 200)
            self.assertEqual(detail.json()["status"], "pending")
            self.assertEqual(self.calls, 1)
        finally:
            self.release.set()
            self.assertEqual((await leader).status_code, 200)

    async def test_http_followers_are_bounded_and_share_one_query(self):
        with patch.object(settings, "query_max_waiters", 3):
            leader = asyncio.create_task(self.client.get("/api/v1/trade-access/firewall/snapshot/ips"))
            self.assertTrue(await asyncio.to_thread(self.entered.wait, 1))
            followers = [asyncio.create_task(self.client.get("/api/v1/trade-access/firewall/snapshot/ips")) for _ in range(5)]
            try:
                await asyncio.sleep(0.1)
                self.assertEqual(self.calls, 1)
            finally:
                self.release.set()
            responses = await asyncio.gather(leader, *followers)
        self.assertEqual(sum(response.status_code == 200 for response in responses), 4)
        self.assertEqual(sum(response.status_code == 503 for response in responses), 2)

    async def test_compatibility_snapshot_and_ports_share_execution(self):
        leader = asyncio.create_task(self.client.get("/api/v1/trade-access/firewall/snapshot/ports"))
        self.assertTrue(await asyncio.to_thread(self.entered.wait, 1))
        follower = asyncio.create_task(self.client.get("/api/v1/trade-access/firewall/snapshot"))
        await asyncio.sleep(0.05)
        self.release.set()
        first, second = await asyncio.gather(leader, follower)
        self.assertEqual([first.status_code, second.status_code], [200, 200])
        self.assertEqual(first.json()["items"], second.json()["items"])
        self.assertEqual(self.calls, 1)

    async def test_readiness_reports_database_loss_and_liveness_still_responds(self):
        self.storage.database_path.unlink()
        response = await self.client.get("/readyz")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["checks"]["database"], "unavailable")
        self.assertEqual((await self.client.get("/healthz")).status_code, 200)
        self.assertFalse(self.storage.database_path.exists())

    async def test_query_authentication_is_required_before_admission(self):
        main.app.dependency_overrides.pop(main.require_firewall_snapshot_read)
        self.assertEqual((await self.client.get("/api/v1/trade-access/firewall/snapshot/ips")).status_code, 401)
        self.assertEqual(self.calls, 0)

    async def test_http_lifespan_restart_reopens_query_executor(self):
        async with main.lifespan(main.app):
            self.assertEqual(await main.query_coordinator.run(("ips",), lambda: "first"), "first")
        self.assertTrue(main.query_coordinator.closed)
        async with main.lifespan(main.app):
            self.assertEqual(await main.query_coordinator.run(("ips",), lambda: "second"), "second")
        self.assertTrue(main.query_coordinator.closed)


if __name__ == "__main__":
    unittest.main()
