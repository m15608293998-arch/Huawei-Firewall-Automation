import importlib.util
import sys
import time
import unittest
from pathlib import Path

import pexpect


PATH = Path(__file__).resolve().parents[1] / "roles/usg6000e_trade_access/files/run_usg_cli.py"
SPEC = importlib.util.spec_from_file_location("prompt_cli", PATH)
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


class PromptTerminalTests(unittest.TestCase):
    def terminal(self, script, hostname="REAL-FW", login_prompt=None, probe_output="", paging_error=""):
        fixture = (
            "import os,time,tty\ntty.setraw(0)\n"
            "prompt=" + repr(login_prompt or "<" + hostname + ">") + "\n"
            "probe_output=" + repr(probe_output) + "\n"
            "paging_error=" + repr(paging_error) + "\n"
            "paging_disabled=False\n"
            "def send(text): os.write(1,text.encode())\n"
            "def command(echo=True):\n"
            "    global paging_disabled\n"
            "    while True:\n"
            "        data=b''\n"
            "        while not data.endswith(b'\\r'): data+=os.read(0,1)\n"
            "        value=data.decode().strip()\n"
            "        if value=='screen-length 0 temporary':\n"
            "            paging_disabled=not bool(paging_error)\n"
            "            send(value+'\\r\\n'+paging_error+prompt)\n"
            "            continue\n"
            "        if value.startswith('display current-configuration | include TRADE_ACCESS_BOUNDARY_'):\n"
            "            if probe_output is not None: send(value+'\\r\\n'+probe_output+prompt)\n"
            "            continue\n"
            "        if echo: send(value+'\\r\\n')\n"
            "        return value\n"
            "send(prompt)\n"
            + script + "\nwhile True: command()\n"
        )
        child = pexpect.spawn(sys.executable, ["-u", "-c", fixture], encoding="utf-8", echo=False, timeout=2)
        child.delaybeforesend = None
        child.execution_deadline = time.monotonic() + 5
        self.addCleanup(child.close, force=True)
        CLI.establish_ssh_session(child, 2)
        CLI.prepare_cli_session(child, 2)
        return child

    def test_bracket_description_and_delayed_error_are_read_before_command_finishes(self):
        child = self.terminal(
            "command()\n"
            "send('description [maintenance] <note>\\r\\n')\n"
            "time.sleep(0.02)\n"
            "send('Error: rejected description.\\r\\n[REAL-FW]')\n"
        )
        output = CLI.run_command_with_busy_retry(child, "description [maintenance] <note>", 2)
        self.assertIn("Error: rejected description.", output)
        with self.assertRaisesRegex(RuntimeError, "rejected description"):
            CLI.ensure_cli_command_accepted("fixture.cli", "description [maintenance] <note>", output)

    def test_standalone_labels_and_another_device_prompt_do_not_finish_command(self):
        child = self.terminal(
            "command()\n"
            "send('[maintenance]\\r\\n<OTHER-FW>\\r\\n<note>\\r\\n')\n"
            "time.sleep(0.02)\n"
            "send('last record\\r\\n[REAL-FW]')\n"
        )
        output = CLI.run_command_with_busy_retry(child, "display current-configuration", 2)
        self.assertIn("last record", output)
        self.assertTrue(output.endswith("[REAL-FW]"))

    def test_prompt_prefix_in_fragmented_command_echo_does_not_hide_late_error(self):
        child = self.terminal(
            "value=command(False)\n"
            "send('[REAL-FW]')\n"
            "time.sleep(0.12)\n"
            "send(value+'\\r\\nError: delayed rejection.\\r\\n[REAL-FW]')\n"
        )
        output = CLI.run_command_with_busy_retry(child, "description [maintenance]", 2)
        self.assertIn("Error: delayed rejection.", output)

    def test_wrapped_echo_containing_device_prompt_cannot_hide_delayed_error(self):
        command = "description " + "x" * 120 + "<REAL-FW>"
        child = self.terminal(
            "value=command(False)\n"
            "position=value.index('<')\n"
            "send(value[:position]+'\\r\\n'+value[position:])\n"
            "time.sleep(0.12)\n"
            "send('\\r\\nError: rejected wrapped command.\\r\\n<REAL-FW>')\n"
        )
        output = CLI.run_command_with_busy_retry(child, command, 2)
        self.assertIn("Error: rejected wrapped command.", output)
        with self.assertRaisesRegex(RuntimeError, "rejected wrapped command"):
            CLI.ensure_cli_command_accepted("fixture.cli", command, output)

    def test_terminal_wrapping_inside_command_verb_is_accepted(self):
        child = self.terminal(
            "value=command(False)\n"
            "send(value[:3]+'\\r\\n'+value[3:]+'\\r\\nlast record\\r\\n<REAL-FW>')\n"
        )
        output = CLI.run_command_with_busy_retry(child, "display current-configuration", 2)
        self.assertIn("last record", output)

    def test_wrapped_query_description_cannot_hide_error_in_either_prompt_shape(self):
        prefix = " address 1 203.0.113.10 mask 255.255.255.255 description "
        for label in ("<REAL-FW>", "[REAL-FW]"):
            with self.subTest(label=label):
                description = "x" * (200 - len(prefix)) + label
                self.assertLessEqual(len(description), 160)
                line = prefix + description
                child = self.terminal(
                    "command()\nprompt='[REAL-FW]'\nsend('\\r\\n'+prompt)\n"
                    "command()\n"
                    "send(" + repr(line[:200] + "\r\n" + line[200:]) + ")\n"
                    "time.sleep(0.12)\n"
                    "send('\\r\\nError: delayed query failure.\\r\\n'+prompt)\n"
                )
                CLI.run_command_with_busy_retry(child, "system-view", 2)
                output = CLI.run_command_with_busy_retry(child, "display this", 2)
                self.assertIn("Error: delayed query failure.", output)
                self.assertTrue(output.endswith("[REAL-FW]"), output)
                with self.assertRaisesRegex(RuntimeError, "delayed query failure"):
                    CLI.ensure_cli_command_accepted("fixture.cli", "display this", output)

    def test_failed_or_missing_query_probe_cannot_report_success(self):
        for probe_output, exception in (
            ("Error: unsupported query probe.\r\n", RuntimeError),
            (None, pexpect.TIMEOUT),
        ):
            with self.subTest(probe_output=probe_output):
                child = self.terminal(
                    "command()\nsend('last record\\r\\n'+prompt)\n",
                    probe_output=probe_output,
                )
                with self.assertRaises(exception):
                    CLI.run_command_with_busy_retry(child, "display this", 0.2)

    def test_wrapped_query_label_does_not_send_probe_into_a_pager(self):
        prefix = " address 1 203.0.113.10 mask 255.255.255.255 description "
        for label in ("<REAL-FW>", "[REAL-FW]"):
            with self.subTest(label=label):
                line = prefix + "x" * (200 - len(prefix)) + label
                child = self.terminal(
                    "command()\nprompt='[REAL-FW]'\nsend('\\r\\n'+prompt)\n"
                    "command()\nsend(" + repr(line[:200] + "\r\n" + line[200:]) + ")\n"
                    "time.sleep(0.12)\n"
                    "if not paging_disabled:\n"
                    "    send('\\r\\n---- More ----')\n"
                    "    received=os.read(0,1)\n"
                    "    send('\\r\\npager_key='+received.decode()+'\\r\\n')\n"
                    "send('\\r\\nlast record\\r\\n'+prompt)\n"
                )
                CLI.run_command_with_busy_retry(child, "system-view", 2)
                output = CLI.run_command_with_busy_retry(child, "display this", 0.3)
                self.assertIn("last record", output)
                self.assertNotIn("pager_key=d", output)

    def test_rejected_session_paging_setup_stops_before_business_commands(self):
        with self.assertRaisesRegex(RuntimeError, "unsupported session setting"):
            self.terminal("", paging_error="Error: unsupported session setting.\r\n")

    def test_fragmented_prompt_and_vsystem_view_changes_keep_same_device_identity(self):
        hostname = "REAL.FW+1"
        child = self.terminal(
            "for prompt in ['[REAL.FW+1]', '<REAL.FW+1-private>', '[~REAL.FW+1-private-addrset]']:\n"
            "    command()\n"
            "    send('description [maintenance]\\r\\n'+prompt[:6])\n"
            "    time.sleep(0.02)\n"
            "    send(prompt[6:])\n",
            hostname,
        )
        for command, prompt in (
            ("system-view", "[REAL.FW+1]"),
            ("switch vsys private", "<REAL.FW+1-private>"),
            ("system-view", "[~REAL.FW+1-private-addrset]"),
        ):
            output = CLI.run_command_with_busy_retry(child, command, 2)
            self.assertTrue(output.endswith(prompt), output)

    def test_save_confirmation_is_answered_before_returning_actual_prompt(self):
        child = self.terminal(
            "command()\n"
            "send('Are you sure to continue? [Y/N]')\n"
            "answer=command()\n"
            "send('answer='+answer+'\\r\\nInfo: Save the configuration successfully.\\r\\n<REAL-FW>')\n"
        )
        output = CLI.run_command_with_busy_retry(child, "save", 2)
        self.assertIn("answer=y", output)
        CLI.ensure_save_completed(output)

    def test_pagination_reaches_last_page_before_returning_prompt(self):
        child = self.terminal(
            "command()\n"
            "send('first record\\r\\n---- More ----')\n"
            "answer=os.read(0,1)\n"
            "send('\\r\\nlast record '+str(answer==b' ')+'\\r\\n<REAL-FW>')\n"
        )
        output = CLI.run_command_with_busy_retry(child, "display current-configuration", 2)
        self.assertIn("last record True", output)

    def test_huawei_ha_role_prefix_and_uncommitted_view_marker_are_preserved(self):
        child = self.terminal(
            "command()\n"
            "send('description [maintenance]\\r\\nHRP_S[*REAL-FW-private]')\n",
            login_prompt="HRP_M<REAL-FW>",
        )
        output = CLI.run_command_with_busy_retry(child, "system-view", 2)
        self.assertTrue(output.endswith("HRP_S[*REAL-FW-private]"), output)

    def test_missing_command_echo_fails_closed(self):
        child = self.terminal("command(False)\nsend('\\r\\n<REAL-FW>')\n")
        with self.assertRaises(pexpect.TIMEOUT):
            CLI.run_command_with_busy_retry(child, "display current-configuration", 0.15)


if __name__ == "__main__":
    unittest.main()
