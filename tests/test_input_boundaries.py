import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pydantic import ValidationError
from api.schemas import TradeAccessIpAllowRequest

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / 'roles/usg6000e_trade_access/files'
spec = importlib.util.spec_from_file_location('boundary_cli', HELPERS / 'run_usg_cli.py')
CLI = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CLI)
spec = importlib.util.spec_from_file_location('boundary_snapshot', HELPERS / 'extract_usg_trade_snapshot.py')
SNAPSHOT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SNAPSHOT)


class InputBoundaryTests(unittest.TestCase):
    def test_description_rejects_every_python_line_separator(self):
        for separator in ('\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029'):
            with self.subTest(separator=repr(separator)):
                with self.assertRaises(ValidationError):
                    TradeAccessIpAllowRequest(target_ip='203.0.113.10', description='text'+separator+'quit')

    def test_existing_cli_files_cannot_turn_unicode_text_into_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'commands.cli'
            for separator in ('\x85', '\u2028', '\u2029', '\v', '\f', '\x1c', '\x1d', '\x1e'):
                path.write_text('description text'+separator+'quit\n', encoding='utf-8')
                with self.subTest(separator=repr(separator)):
                    with self.assertRaises(ValueError):
                        CLI.read_commands(path)

    def test_cli_preserves_normal_crlf_commands_and_unicode_descriptions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'commands.cli'
            path.write_bytes('system-view\r\ndescription 交易 [维护] <备注>\r\nquit\r\n'.encode())
            self.assertEqual([command for _, command in CLI.read_commands(path)],
                             ['system-view', 'description 交易 [维护] <备注>', 'quit'])

    def extract_ids(self, text, ip='203.0.113.10'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'query.out'
            path.write_text(text)
            result = subprocess.run([sys.executable, str(HELPERS / 'extract_usg_address_id.py'),
                                     '--file', str(path), '--ip', ip, '--mask', '32'],
                                    text=True, capture_output=True, check=True)
            return json.loads(result.stdout)['ids']

    def test_description_does_not_supply_an_address_id(self):
        text = 'address 10 203.0.113.20 mask 32 description address 99 203.0.113.10 mask 32\n'
        self.assertEqual(self.extract_ids(text), [])
        self.assertEqual(self.extract_ids(text, '203.0.113.20'), ['10'])

    def test_real_member_wins_over_another_members_description(self):
        text = ('address 10 203.0.113.20 mask 32 description address 99 203.0.113.10 mask 32\n'
                '  address 7 203.0.113.10 mask 32 description real\n')
        self.assertEqual(self.extract_ids(text), ['7'])

    def test_unicode_description_cannot_forge_a_new_output_line(self):
        for separator in ('\x85', '\u2028', '\u2029'):
            with self.subTest(separator=repr(separator)):
                text = 'address 10 203.0.113.20 mask 32 description text'+separator+'address 99 203.0.113.10 mask 32\n'
                self.assertEqual(self.extract_ids(text), [])
                self.assertEqual(SNAPSHOT.parse_address_inventory(text), {'203.0.113.20': 32})

    def test_snapshot_ignores_standalone_description_and_command_echo(self):
        text = ('description address 99 203.0.113.10 mask 32\n'
                '[FW]display this | include address 99 203.0.113.10 mask 32\n'
                ' address 7 203.0.113.20 mask 32 description business\n')
        self.assertEqual(SNAPSHOT.parse_address_inventory(text), {'203.0.113.20': 32})


    def test_unreadable_address_output_is_not_reported_as_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(HELPERS / 'extract_usg_address_id.py'),
                                     '--file', str(Path(directory)/'missing.out'),
                                     '--ip', '203.0.113.10', '--mask', '32'],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
