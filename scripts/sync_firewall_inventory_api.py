#!/usr/bin/env python3
"""Synchronize an IP/port JSON inventory using authenticated HTTP APIs only.

Dry-run is the default. Use --execute to apply the complete desired inventory,
including removing IPs and ports absent from the input. Credentials are read
from a protected file or TRADE_ACCESS_API_TOKEN, never written to the audit.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.ip_policy import validate_direct_access_target

ACTIVE = {'pending', 'running', 'prechecking', 'applying', 'verifying', 'reconciling'}
REQUIRED = {'firewall.snapshot.read', 'firewall.job.read'}
ROOT = '/api/v1/trade-access'


class SyncError(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def load_inventory(path):
    raw = path.read_bytes()
    rows = json.loads(raw)
    if not isinstance(rows, list) or not rows:
        raise SyncError('Input must be a nonempty JSON array.')
    desired = {}
    raw_count = 0
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise SyncError(f'Row {i} must be an object.')
        if set(row) not in ({'IP', 'port'}, {'ip', 'port'}):
            raise SyncError(f'Row {i}: expected IP/ip and port only.')
        value = row.get('IP', row.get('ip'))
        if not isinstance(value, str):
            raise SyncError(f'Row {i}: IP must be a string.')
        ip = str(ipaddress.IPv4Address(value))
        if ip != value:
            raise SyncError(f'Row {i}: noncanonical IP.')
        validate_direct_access_target(ip)
        address = ipaddress.IPv4Address(ip)
        if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local or ip == '255.255.255.255':
            raise SyncError(f'Row {i}: unsupported target {ip}.')
        ports = row['port']
        if not isinstance(ports, list) or not ports:
            raise SyncError(f'Row {i}: port must be a nonempty array.')
        for port in ports:
            if type(port) is not int or not 1 <= port <= 65535:
                raise SyncError(f'Row {i}: invalid port.')
            desired.setdefault(ip, set()).add(port)
            raw_count += 1
    return desired, {'sha256': hashlib.sha256(raw).hexdigest(), 'rows': len(rows),
                     'ips': len(desired), 'unique_pairs': sum(map(len, desired.values())),
                     'duplicate_pairs': raw_count - sum(map(len, desired.values()))}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.sync-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Client:
    def __init__(self, url, token_file, timeout):
        self.url, self.token_file, self.timeout = url.rstrip('/'), token_file, timeout
        host = urllib.parse.urlparse(self.url).hostname
        try:
            local = ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host == 'localhost'
        # Company LAN traffic should not consume an environment HTTP proxy's
        # connection pool. Other API hosts retain the system proxy behavior.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if local else urllib.request.build_opener()

    def credential(self):
        if self.token_file:
            mode = self.token_file.stat().st_mode
            if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o077:
                raise SyncError('Credential file must be a regular file with mode 600 or 400.')
            token = self.token_file.read_text().strip()
        else:
            token = os.environ.get('TRADE_ACCESS_API_TOKEN', '').strip()
        if not token or any(c.isspace() for c in token):
            raise SyncError('Provide one Bearer token/API key via --token-file or TRADE_ACCESS_API_TOKEN.')
        return token

    def request(self, method, path, data=None):
        token = self.credential()
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + token}
        body = None
        if data is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(data).encode()
        req = urllib.request.Request(self.url + ROOT + path, data=body, headers=headers, method=method)
        attempts = 3 if method == 'GET' else 1
        for attempt in range(attempts):
            try:
                with self.opener.open(req, timeout=self.timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors='replace').replace(token, '[REDACTED]')
                if method == 'GET' and exc.code in {408, 429, 502, 503, 504} and attempt+1 < attempts:
                    time.sleep(2 ** attempt)
                    continue
                raise SyncError(f'{method} {path}: HTTP {exc.code}: {detail[:2000]}') from None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if method == 'GET' and attempt+1 < attempts:
                    time.sleep(2 ** attempt)
                    continue
                raise SyncError(f'{method} {path}: {type(exc).__name__}; if POST was attempted, resume the same audit to resolve acceptance.') from None

    def snapshot(self, mode):
        result = self.request('GET', '/firewall/snapshot/' + mode)
        if result.get('consistency_status') != 'consistent' or not isinstance(result.get('items'), list):
            raise SyncError('Snapshot is incomplete or firewalls disagree.')
        return result


def pairs(inventory):
    return {(ip, port) for ip, ports in inventory.items() for port in ports}


def difference(desired, ips, current):
    return {'missing_ips': len(set(desired)-ips), 'extra_ips': len(ips-set(desired)),
            'missing_pairs': len(pairs(desired)-pairs(current)),
            'extra_pairs': len(pairs(current)-pairs(desired))}


def operations(desired, ips, current, phase):
    result = []
    if phase == 'ip':
        for ip in sorted(set(desired)-ips, key=ipaddress.IPv4Address):
            result.append({'endpoint': '/allow/ip', 'target_ip': ip})
        for ip in sorted(ips-set(desired), key=ipaddress.IPv4Address):
            result.append({'endpoint': '/deny', 'target_ip': ip})
    elif phase == 'ports':
        for endpoint in ('/allow/ports', '/deny/ports'):
            for ip in sorted(desired, key=ipaddress.IPv4Address):
                wanted, actual = desired[ip], current.get(ip, set())
                ports = sorted(wanted-actual if endpoint == '/allow/ports' else actual-wanted)
                for start in range(0, len(ports), 256):
                    result.append({'endpoint': endpoint, 'target_ip': ip, 'ports': ports[start:start+256]})
    return result


def preflight_permissions(identity, execute):
    if not identity.get('access_enabled', True):
        raise SyncError('API identity is disabled.')
    permissions = set(identity.get('permissions', []))
    needed = set(REQUIRED)
    if execute:
        if 'firewall.allow' not in permissions:
            needed |= {'firewall.ip.allow', 'firewall.ports.allow'}
        if 'firewall.deny' not in permissions:
            needed |= {'firewall.ip.deny', 'firewall.ports.deny'}
    if needed-permissions:
        raise SyncError('API credential lacks permissions: ' + ', '.join(sorted(needed-permissions)))
    if execute and identity.get('allowed_ips') and not identity.get('is_admin', False):
        # /me does not expose is_admin on all deployed versions; inspect roles too.
        if 'admin' not in identity.get('roles', []):
            raise SyncError('Use an authorized administrator credential for full-inventory synchronization.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--api-base-url', default='http://192.168.6.30:8000')
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--audit-output', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--request-timeout', type=float, default=600)
    parser.add_argument('--job-timeout', type=float, default=1800)
    parser.add_argument('--poll-interval', type=float, default=5)
    args = parser.parse_args(argv)
    if min(args.request_timeout, args.job_timeout, args.poll_interval) <= 0:
        parser.error('Timeouts and poll interval must be positive.')
    desired, source = load_inventory(args.input)
    print('Source:', json.dumps(source), flush=True)
    client = Client(args.api_base_url, args.token_file, args.request_timeout)
    identity = client.request('GET', '/me')
    preflight_permissions(identity, args.execute)
    if args.audit_output.exists():
        audit = json.loads(args.audit_output.read_text())
        if not isinstance(audit, dict) or not isinstance(audit.get('source'), dict) or not isinstance(audit.get('events'), list):
            raise SyncError('Existing file is not an API synchronization audit. Choose a new --audit-output path; the old file was preserved.')
        if audit['source'].get('sha256') != source['sha256'] or audit.get('api_base_url') != client.url:
            raise SyncError('Existing audit belongs to a different input or API.')
    else:
        audit = {'run_id': 'inventory-' + uuid.uuid4().hex, 'source': source,
                 'source_path': str(args.input.resolve()), 'api_base_url': client.url,
                 'started_at': now(), 'events': []}
    if audit.get('error'):
        audit.setdefault('interruptions', []).append({
            'at': audit.pop('stopped_at', None), 'error': audit.pop('error')})
    audit['identity'] = {k: identity.get(k) for k in ('subject_id', 'subject', 'roles')}
    audit['exact_match'] = False
    audit['status'] = 'running' if args.execute else 'planning'
    save = lambda: write_json(args.audit_output, audit)

    def wait(event):
        deadline = time.monotonic() + args.job_timeout
        last_status = None
        while time.monotonic() < deadline:
            job = client.request('GET', '/jobs/' + event['job_id'])
            event['status'] = job['status']
            if last_status != job['status']:
                print(event['operation']['target_ip'], event['operation']['endpoint'], job['status'], flush=True)
                last_status = job['status']
                save()
            if job['status'] not in ACTIVE:
                event['result'] = job
                save()
                if job['status'] != 'successful':
                    raise SyncError(f"Job {event['job_id']} ended as {job['status']}; audit has details.")
                return
            time.sleep(args.poll_interval)
        raise SyncError('Job deadline reached; job may still be running. Resume with the same audit.')

    def recover():
        for event in audit['events']:
            if event.get('status') == 'successful':
                continue
            if 'job_id' not in event:
                matches = []
                page = 1
                while True:
                    jobs = client.request('GET', '/jobs?' + urllib.parse.urlencode({'page': page, 'limit': 500}))
                    matches += [job for job in jobs if job.get('client_request_id') == event['client_request_id']]
                    if len(jobs) < 500:
                        break
                    page += 1
                if len(matches) != 1:
                    raise SyncError('Ambiguous POST acceptance; inspect audit/client_request_id before retrying. No POST was repeated.')
                event['job_id'] = matches[0]['job_id']
                save()
            wait(event)

    def get_state(label):
        ip_snapshot = client.snapshot('ips')
        port_snapshot = client.snapshot('ports')
        ips = {str(ipaddress.IPv4Address(item['ip'])) for item in ip_snapshot['items']}
        current = {}
        for item in port_snapshot['items']:
            ip = str(ipaddress.IPv4Address(item['ip']))
            if type(item['port']) is not int or not 1 <= item['port'] <= 65535:
                raise SyncError('Invalid snapshot port.')
            current.setdefault(ip, set()).add(item['port'])
        if not set(current).issubset(ips):
            raise SyncError('Port snapshot has IPs absent from the IP snapshot.')
        state = {'ip_snapshot': ip_snapshot, 'port_snapshot': port_snapshot,
                 'difference': difference(desired, ips, current)}
        audit.setdefault('snapshots', []).append({'label': label, **state})
        save()
        print(label, json.dumps(state['difference']), flush=True)
        return ips, current

    def apply(plan, phase):
        audit.setdefault('plans', []).append({'phase': phase, 'operations': plan, 'at': now()})
        save()
        for operation in plan:
            event = {'operation': operation, 'phase': phase, 'status': 'submitting',
                     'client_request_id': audit['run_id'] + '-' + uuid.uuid4().hex}
            audit['events'].append(event)
            save()
            payload = {k: v for k, v in operation.items() if k != 'endpoint'}
            payload.update(mask=32, client_request_id=event['client_request_id'])
            response = client.request('POST', operation['endpoint'], payload)
            event['job_id'] = response['job_id']
            event['status'] = 'pending'
            save()
            wait(event)

    try:
        if args.execute:
            recover()
        ips, current = get_state('before')
        ip_plan = operations(desired, ips, current, 'ip')
        if not args.execute:
            port_plan = operations(desired, set(desired), current, 'ports')
            audit['dry_run_plan'] = {'ip': ip_plan, 'ports': port_plan}
            audit['status'] = 'dry_run'
            save()
            print(f'Dry run: {len(ip_plan)} IP operations, {len(port_plan)} port operations.', flush=True)
            return
        apply(ip_plan, 'ip')
        if ip_plan:
            ips, current = get_state('after_ip')
        if ips != set(desired):
            raise SyncError('IP phase did not produce an exact match; port phase halted.')
        apply(operations(desired, ips, current, 'ports'), 'ports')
        ips, current = get_state('final')
        if any(difference(desired, ips, current).values()):
            raise SyncError('Final snapshot differs from input; audit has details.')
        audit.update(status='successful', completed_at=now(), exact_match=True)
        save()
        print(f'COMPLETE: exact_match=true ips={len(ips)} pairs={len(pairs(current))}', flush=True)
    except Exception as exc:
        audit.update(status='stopped', error=str(exc), stopped_at=now())
        save()
        raise


if __name__ == '__main__':
    try:
        main()
    except (SyncError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
