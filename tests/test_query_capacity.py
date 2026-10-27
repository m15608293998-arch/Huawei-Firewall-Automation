import asyncio
import threading
import unittest
from unittest.mock import patch

from api.config import settings
from api.query_capacity import DeviceQueryCoordinator, QueryBusyError


class QueryCapacityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.pool = DeviceQueryCoordinator()
        self.addCleanup(self.pool.close)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        self.calls = 0

    def slow_query(self):
        self.calls += 1
        self.entered.set()
        if not self.release.wait(3):
            raise AssertionError("Local query fixture was not released")
        return {"items": ["first"]}

    async def start_query(self):
        leader = asyncio.create_task(self.pool.run(("ips",), self.slow_query))
        self.assertTrue(await asyncio.to_thread(self.entered.wait, 1))
        return leader

    async def test_identical_requests_share_one_run_and_results_are_not_cached(self):
        leader = await self.start_query()
        followers = [asyncio.create_task(self.pool.run(("ips",), self.slow_query)) for _ in range(5)]
        await asyncio.sleep(0.02)
        self.assertEqual(self.calls, 1)
        self.release.set()
        results = await asyncio.gather(leader, *followers)
        self.assertTrue(all(result == results[0] for result in results))
        await self.pool.run(("ips",), self.slow_query)
        self.assertEqual(self.calls, 2)

    async def test_other_query_kinds_and_excess_waiters_are_rejected(self):
        with patch.object(settings, "query_max_waiters", 1):
            leader = await self.start_query()
            follower = asyncio.create_task(self.pool.run(("ips",), self.slow_query))
            await asyncio.sleep(0.02)
            for key in (("ports",), ("ips",)):
                with self.assertRaises(QueryBusyError):
                    await self.pool.run(key, self.slow_query)
            self.release.set()
            await asyncio.gather(leader, follower)
        self.assertEqual(self.calls, 1)

    async def test_canceling_leader_does_not_release_running_query_capacity(self):
        leader = await self.start_query()
        leader.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await leader
        with self.assertRaises(QueryBusyError):
            await self.pool.run(("ports",), self.slow_query)
        follower = asyncio.create_task(self.pool.run(("ips",), self.slow_query))
        self.release.set()
        await follower
        self.assertEqual(self.calls, 1)

    async def test_waiter_timeout_does_not_cancel_shared_execution(self):
        with patch.object(settings, "query_wait_timeout_seconds", 0.03):
            leader = await self.start_query()
            with self.assertRaises(QueryBusyError):
                await self.pool.run(("ips",), self.slow_query)
            self.release.set()
            self.assertEqual(await leader, {"items": ["first"]})

    async def test_failed_query_releases_capacity(self):
        def failure():
            raise ValueError("test failure")

        with self.assertRaises(ValueError):
            await self.pool.run(("ips",), failure)
        self.assertEqual(await self.pool.run(("ports",), lambda: "recovered"), "recovered")


if __name__ == "__main__":
    unittest.main()
