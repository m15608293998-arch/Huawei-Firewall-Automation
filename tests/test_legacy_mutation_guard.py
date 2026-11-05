import copy
from pathlib import Path
import tempfile
import unittest

from api.runner_service import RunnerResult, SnapshotRunnerResult
from api.storage import JobStorage
from api.worker import JobWorker
from test_consistency_checks import application, state_payload, IP, BASE, SECOND_IP


class StaticRunner:
    def __init__(self, payload):
        self.payload = payload
        self.mutations = []

    def run_firewall_snapshot(self, *args, **kwargs):
        return SnapshotRunnerResult('successful', 0, '', copy.deepcopy(self.payload))

    def run_trade_access(self, job, firewall_code=None):
        self.mutations.append(job['action'])
        return RunnerResult('successful', 0, '')


class LegacyMutationGuardTests(unittest.TestCase):
    def execute(self, config, ledger=False, action='deny_ports'):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = JobStorage(Path(directory.name) / 'jobs.sqlite3')
        if ledger:
            store.save_desired_access_state(IP, True, [], 'previous', '2026-01-01T00:00:00+00:00')
        store.create_job({'job_id': 'test-job', 'status': 'pending', 'action': action,
                          'target_ip': IP, 'mask': 32, 'ports': [443] if action=='deny_ports' else [],
                          'created_at': '2026-11-05T00:00:00+00:00',
                          'local_tmp_dir': str(Path(directory.name)/'job'),
                          'firewall_targets': ['TEST-FW']}, ['TEST-FW'])
        runner = StaticRunner(state_payload(config))
        worker = JobWorker(store, runner, retry_waiter=lambda _: None)
        worker.run_once()
        return store.get_job('test-job'), runner

    def test_legacy_and_shared_apps_never_report_successful_port_revocation(self):
        for name, bindings in (
            ('Legacy_Trade', ((IP, 32, 443),)),
            ('UD_TServe_legacy', ((IP, 32, 443),)),
            ('Shared_Trade', ((IP, 32, 443), (SECOND_IP, 32, 8443))),
        ):
            for ledger in (False, True):
                with self.subTest(name=name, ledger=ledger):
                    job, runner = self.execute(application(name, bindings), ledger=ledger)
                    self.assertEqual(job['status'], 'manual_intervention_required')
                    self.assertIn(name, job['error_message'])
                    self.assertIn('migration', job['error_message'])
                    if not ledger:
                        self.assertEqual(runner.mutations, [])
                    self.assertIn({'ip': IP, 'port': 443}, runner.payload['port_items'])

    def test_other_ips_legacy_app_does_not_block_target(self):
        job, _ = self.execute(application('Legacy_Other', ((SECOND_IP, 32, 443),)))
        self.assertEqual(job['status'], 'successful')

    def test_ungrouped_unrelated_app_does_not_block_target(self):
        job, _ = self.execute(application('Corporate_Other', ((IP, 32, 443),), grouped=False))
        self.assertEqual(job['status'], 'successful')

    def test_full_deny_cannot_hide_residual_legacy_binding(self):
        job, _ = self.execute(application('Legacy_Trade', ((IP,32,443),)), action='deny')
        self.assertEqual(job['status'], 'manual_intervention_required')
        self.assertIn('Legacy_Trade', job['error_message'])


    def test_non_host_legacy_binding_cannot_be_ignored(self):
        job, _ = self.execute(application('Legacy_Network', (('203.0.113.0', 24, 443),)))
        self.assertEqual(job['status'], 'manual_intervention_required')
        self.assertIn('Legacy_Network', job['error_message'])

    def test_resumed_applied_target_cannot_skip_legacy_validation(self):
        runner = StaticRunner(state_payload(application('Legacy_Trade', ((IP, 32, 443),))))
        with tempfile.TemporaryDirectory() as directory:
            storage = JobStorage(Path(directory)/'jobs.sqlite3')
            job = {'job_id': 'resume', 'status': 'verifying', 'action': 'deny_ports',
                   'target_ip': IP, 'mask': 32, 'ports': [443],
                   'created_at': '2026-11-05T00:00:00+00:00',
                   'local_tmp_dir': str(Path(directory)/'job'),
                   'firewall_targets': ['TEST-FW'],
                   'desired_state': {'ip_present': True, 'ports': [], 'version': 1}, 'state_version': 1}
            storage.create_job(job, ['TEST-FW'])
            storage.save_desired_access_state(IP, True, [], 'resume', '2026-11-05T00:00:00+00:00')
            storage.update_job_target('resume', 'TEST-FW', {'status': 'applied', 'runner_status': 'successful', 'runner_rc': 0})
            JobWorker(storage, runner, retry_waiter=lambda _: None).run_once()
            self.assertEqual(storage.get_job('resume')['status'], 'manual_intervention_required')
            self.assertEqual(runner.mutations, [])


if __name__ == '__main__':
    unittest.main()
