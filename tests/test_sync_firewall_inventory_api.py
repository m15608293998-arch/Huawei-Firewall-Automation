import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'inventory_sync', Path(__file__).resolve().parents[1] / 'scripts/sync_firewall_inventory_api.py'
)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


class InventorySyncTests(unittest.TestCase):
    def inventory(self, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text(json.dumps(value))
            return sync.load_inventory(path)

    def test_repeated_ips_merge_without_losing_ports(self):
        desired, meta = self.inventory([
            {'IP': '59.36.20.54', 'port': [12002, 12009]},
            {'ip': '59.36.20.54', 'port': [12009, 14002]},
        ])
        self.assertEqual(desired, {'59.36.20.54': {12002, 12009, 14002}})
        self.assertEqual(meta['unique_pairs'], 3)
        self.assertEqual(meta['duplicate_pairs'], 1)

    def test_invalid_input_fails_before_any_http_call(self):
        for ip, ports in [('10.1.2.3', [443]), ('172.16.0.1', [443]),
                          ('192.168.1.1', [443]), ('8.8.8.8', [True]),
                          ('8.8.8.8', [0]), ('8.8.8.8', [65536]),
                          ('8.8.8.8', []), ('127.0.0.1', [443])]:
            with self.subTest(ip=ip, ports=ports), self.assertRaises((ValueError, sync.SyncError)):
                self.inventory([{'IP': ip, 'port': ports}])

    def test_phase_plans_reach_exact_inventory_and_preserve_common_ports(self):
        desired = {'8.8.8.8': {443, 53}, '1.1.1.1': {443}}
        ips = {'8.8.8.8', '9.9.9.9'}
        current = {'8.8.8.8': {443, 80}, '9.9.9.9': {53}}
        ip_plan = sync.operations(desired, ips, current, 'ip')
        self.assertEqual([op['endpoint'] for op in ip_plan], ['/allow/ip', '/deny'])
        for op in ip_plan:
            if op['endpoint'] == '/allow/ip':
                ips.add(op['target_ip'])
            else:
                ips.remove(op['target_ip'])
                current.pop(op['target_ip'])
        self.assertEqual(ips, set(desired))
        for op in sync.operations(desired, ips, current, 'ports'):
            ports = current.setdefault(op['target_ip'], set())
            if op['endpoint'] == '/allow/ports':
                ports.update(op['ports'])
            else:
                self.assertNotIn(443, op['ports'])
                ports.difference_update(op['ports'])
        self.assertEqual(current, desired)
        self.assertEqual(sync.operations(desired, ips, current, 'ports'), [])

    def test_chunks_and_permission_preflight(self):
        plan = sync.operations({'8.8.8.8': set(range(1, 601))}, {'8.8.8.8'}, {}, 'ports')
        self.assertEqual([len(op['ports']) for op in plan], [256, 256, 88])
        with self.assertRaises(sync.SyncError):
            sync.preflight_permissions({'permissions': ['firewall.snapshot.read']}, True)
        sync.preflight_permissions({'permissions': ['firewall.snapshot.read', 'firewall.job.read',
                                                   'firewall.allow', 'firewall.deny']}, True)

    def test_credential_file_permissions_and_no_missing_credential_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key'
            path.write_text('test-key')
            path.chmod(0o644)
            client = sync.Client('http://127.0.0.1', path, 1)
            with self.assertRaises(sync.SyncError):
                client.credential()
            path.chmod(0o600)
            self.assertEqual(client.credential(), 'test-key')
        with patch.dict(sync.os.environ, {}, clear=True), patch.object(sync.urllib.request, 'urlopen') as http:
            with self.assertRaises(sync.SyncError):
                sync.Client('http://127.0.0.1', None, 1).request('GET', '/me')
            http.assert_not_called()

    def test_execute_and_resume_exact_match_through_api_client(self):
        state = {'ips': {'8.8.8.8', '9.9.9.9'},
                 'ports': {'8.8.8.8': {443, 80}, '9.9.9.9': {53}}, 'jobs': {}, 'posts': []}

        class FakeClient:
            def __init__(self, url, *args):
                self.url = url

            def snapshot(self, mode):
                items = ([{'ip': ip} for ip in state['ips']] if mode == 'ips' else
                         [{'ip': ip, 'port': port} for ip, ports in state['ports'].items() for port in ports])
                return {'items': items, 'consistency_status': 'consistent'}

            def request(self, method, path, data=None):
                if path == '/me':
                    return {'permissions': ['firewall.allow', 'firewall.deny',
                                            'firewall.snapshot.read', 'firewall.job.read']}
                if method == 'GET' and path.startswith('/jobs/'):
                    return state['jobs'][path.rsplit('/', 1)[1]]
                if method == 'POST':
                    state['posts'].append(path)
                    ip = data['target_ip']
                    if path == '/allow/ip':
                        state['ips'].add(ip)
                    elif path == '/deny':
                        state['ips'].remove(ip)
                        state['ports'].pop(ip, None)
                    elif path == '/allow/ports':
                        self.assert_ip_phase_done()
                        state['ports'].setdefault(ip, set()).update(data['ports'])
                    elif path == '/deny/ports':
                        self.assert_ip_phase_done()
                        state['ports'].setdefault(ip, set()).difference_update(data['ports'])
                    job_id = str(len(state['jobs']) + 1)
                    state['jobs'][job_id] = {'job_id': job_id, 'status': 'successful'}
                    return {'job_id': job_id}
                raise AssertionError((method, path))

            def assert_ip_phase_done(self):
                if state['ips'] != {'1.1.1.1', '8.8.8.8'}:
                    raise AssertionError('Ports started before IP alignment')

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.json'
            source.write_text(json.dumps([{'IP': '8.8.8.8', 'port': [443, 53]},
                                          {'IP': '1.1.1.1', 'port': [443]}]))
            audit_path = Path(directory) / 'audit.json'
            argv = ['sync', '--input', str(source), '--audit-output', str(audit_path), '--execute']
            with patch.object(sync, 'Client', FakeClient), patch.object(sync.sys, 'argv', argv):
                sync.main()
                before = len(state['posts'])
                sync.main()
            self.assertEqual(len(state['posts']), before)
            self.assertEqual(state['ports'], {'8.8.8.8': {443, 53}, '1.1.1.1': {443}})
            audit = json.loads(audit_path.read_text())
            self.assertTrue(audit['exact_match'])
            self.assertEqual(audit['status'], 'successful')
            self.assertEqual(len(audit['events']), 5)

    def test_get_retries_connection_reset_but_post_is_not_repeated(self):
        for method, expected_calls in [('GET', 3), ('POST', 1)]:
            with self.subTest(method=method), patch.dict(sync.os.environ, {'TRADE_ACCESS_API_TOKEN': 'test-key'}):
                client = sync.Client('http://192.168.6.30:8000', None, 1)
                with patch.object(client.opener, 'open', side_effect=ConnectionResetError), patch.object(sync.time, 'sleep') as sleep:
                    with self.assertRaises(sync.SyncError):
                        client.request(method, '/jobs')
                    self.assertEqual(client.opener.open.call_count, expected_calls)
                    self.assertEqual(sleep.call_count, expected_calls-1)

    def test_legacy_audit_is_rejected_without_overwriting_or_posting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.json'
            source.write_text(json.dumps([{'ip': '203.0.113.10', 'port': [443]}]))
            audit = root / 'audit.json'
            original = json.dumps({'run_id': 'old-direct-runner', 'input_sha256': 'legacy'})
            audit.write_text(original)
            with patch.object(sync.Client, 'request', return_value={
                'permissions': ['firewall.allow', 'firewall.deny', 'firewall.snapshot.read', 'firewall.job.read']
            }) as request, self.assertRaisesRegex(sync.SyncError, 'new --audit-output'):
                sync.main(['--input', str(source), '--audit-output', str(audit), '--execute'])
            self.assertEqual(audit.read_text(), original)
            self.assertEqual(request.call_args_list[0].args, ('GET', '/me'))
            self.assertEqual(request.call_count, 1)


if __name__ == '__main__':
    unittest.main()
