import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api.auth import Principal
from api.config import settings
from api import jobs
from api.schemas import TradeAccessJobCreate
from api.storage import JobStorage
from api.worker import JobWorker
from scripts import reconcile_firewall_to_ip_ports as legacy
from scripts import sync_firewall_inventory_api as sync
from test_worker import FakeRunner


class ReconcileApiTests(unittest.TestCase):
    def test_compatibility_entrypoint_passes_options_to_api_synchronizer(self):
        arguments = ["--input", "fixture.json", "--audit-output", "fixture-audit.json", "--execute", "--token-file", "credential"]
        with patch.object(legacy, "sync_inventory_main") as run:
            legacy.main(arguments)
        forwarded = run.call_args.args[0]
        self.assertEqual(forwarded[-len(arguments):], arguments)
        self.assertIn("--api-base-url", forwarded)

    def test_sync_creates_worker_jobs_for_all_three_firewalls(self):
        codes = ("A", "B", "C")
        ip = "203.0.113.10"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            storage = JobStorage(root / "jobs.sqlite3")
            runner = FakeRunner(states={code: {"ip_present": False, "ports": []} for code in codes})
            worker = JobWorker(storage, runner, retry_waiter=lambda _: None)

            class ApiFixture:
                def __init__(self, url, *args):
                    self.url = url

                def request(self, method, path, data=None):
                    if method == "GET" and path == "/me":
                        return {"permissions": ["firewall.allow", "firewall.deny", "firewall.snapshot.read", "firewall.job.read"]}
                    if method == "POST":
                        action = {"/allow/ip": "allow_ip", "/allow/ports": "allow_ports"}[path]
                        result = jobs.create_job(
                            TradeAccessJobCreate(action=action, **data),
                            Principal(subject_id="fixture", subject="fixture", auth_type="development"),
                        )
                        worker.run_once()
                        return result
                    if method == "GET" and path.startswith("/jobs/"):
                        return storage.get_job(path.rsplit("/", 1)[-1], include_targets=True)
                    raise AssertionError((method, path))

                def snapshot(self, mode):
                    states = [runner.states[code] for code in codes]
                    if any(state != states[0] for state in states[1:]):
                        raise AssertionError("Partial device state must not be returned as a clean snapshot")
                    state = states[0]
                    items = ([{"ip": ip}] if state["ip_present"] else []) if mode == "ips" else [
                        {"ip": ip, "port": port} for port in state["ports"]
                    ]
                    return {"consistency_status": "consistent", "items": items, "firewall_codes": list(codes)}

            source = root / "source.json"
            source.write_text(json.dumps([{"ip": ip, "port": [443]}]))
            audit = root / "audit.json"
            with patch.object(sync, "Client", ApiFixture), patch.object(jobs, "storage", storage), \
                    patch.object(settings, "firewall_targets", ",".join(codes)), \
                    patch.object(settings, "job_tmp_root", root / "jobs"):
                legacy.main(["--input", str(source), "--audit-output", str(audit), "--execute"])
            self.assertEqual([runner.states[code]["ports"] for code in codes], [[443], [443], [443]])
            completed = storage.list_jobs(include_targets=True)
            self.assertEqual(len(completed), 2)
            for job in completed:
                self.assertEqual(job["status"], "successful")
                self.assertEqual(job["firewall_targets"], list(codes))
                self.assertEqual({target["status"] for target in job["target_results"]}, {"verified"})
            self.assertTrue(json.loads(audit.read_text())["exact_match"])


if __name__ == "__main__":
    unittest.main()
