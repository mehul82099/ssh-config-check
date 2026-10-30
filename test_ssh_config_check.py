#!/usr/bin/env python3
"""Tests for ssh-config-check (stdlib unittest)."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ssh_config_check as scc


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = scc.main(argv)
    return code, out.getvalue(), err.getvalue()


def rules(findings):
    return {f.rule for f in findings}


class ParserTests(unittest.TestCase):
    def test_keyword_value(self):
        rows = scc.parse_config("StrictHostKeyChecking no")
        self.assertEqual(rows[0][1:3], ("stricthostkeychecking", "no"))

    def test_keyword_equals_value(self):
        rows = scc.parse_config("StrictHostKeyChecking=no")
        self.assertEqual(rows[0][1:3], ("stricthostkeychecking", "no"))

    def test_keyword_case_insensitive(self):
        rows = scc.parse_config("PERMITROOTLOGIN yes")
        self.assertEqual(rows[0][1], "permitrootlogin")

    def test_comment_full_line_ignored(self):
        self.assertEqual(scc.parse_config("# PermitRootLogin yes"), [])

    def test_trailing_comment_stripped(self):
        rows = scc.parse_config("PermitRootLogin yes  # temporary")
        self.assertEqual(rows[0][2], "yes")

    def test_blank_lines_skipped(self):
        self.assertEqual(scc.parse_config("\n\n   \n"), [])

    def test_host_block_recorded(self):
        rows = scc.parse_config("Host bastion\n  ForwardAgent yes\n")
        self.assertEqual(rows[1][3], "Host bastion")

    def test_host_block_ends_at_next_host(self):
        rows = scc.parse_config(
            "Host a\n  ForwardAgent yes\nHost b\n  ForwardX11 yes\n")
        self.assertEqual(rows[1][3], "Host a")
        self.assertEqual(rows[3][3], "Host b")

    def test_match_block_recorded(self):
        rows = scc.parse_config("Match user admin\n  X11Forwarding yes\n")
        self.assertEqual(rows[1][3], "Match user admin")

    def test_leading_whitespace_ok(self):
        rows = scc.parse_config("   ForwardAgent    yes")
        self.assertEqual(rows[0][1:3], ("forwardagent", "yes"))

    def test_value_case_preserved(self):
        rows = scc.parse_config("UserKnownHostsFile /Dev/Null")
        self.assertEqual(rows[0][2], "/Dev/Null")

    def test_line_numbers_tracked(self):
        rows = scc.parse_config("\n\nForwardAgent yes\n")
        self.assertEqual(rows[0][0], 3)


class ClientRuleTests(unittest.TestCase):
    def check(self, text):
        return scc.check_config(text, "ssh_config", "client")

    def test_strict_host_key_checking_no_is_error(self):
        fs = self.check("StrictHostKeyChecking no")
        self.assertEqual(fs[0].rule, "strict-host-key-checking-off")
        self.assertEqual(fs[0].severity, "error")

    def test_strict_host_key_checking_off_is_error(self):
        fs = self.check("StrictHostKeyChecking off")
        self.assertEqual(rules(fs), {"strict-host-key-checking-off"})

    def test_strict_host_key_checking_ask_ok(self):
        self.assertEqual(self.check("StrictHostKeyChecking ask"), [])

    def test_strict_host_key_checking_yes_ok(self):
        self.assertEqual(self.check("StrictHostKeyChecking yes"), [])

    def test_shk_value_case_insensitive(self):
        fs = self.check("StrictHostKeyChecking No")
        self.assertEqual(rules(fs), {"strict-host-key-checking-off"})

    def test_known_hosts_dev_null_is_error(self):
        fs = self.check("UserKnownHostsFile /dev/null")
        self.assertEqual(fs[0].rule, "known-hosts-dev-null")
        self.assertEqual(fs[0].severity, "error")

    def test_known_hosts_normal_path_ok(self):
        self.assertEqual(
            self.check("UserKnownHostsFile ~/.ssh/known_hosts"), [])

    def test_forward_agent_yes_warning(self):
        fs = self.check("ForwardAgent yes")
        self.assertEqual(fs[0].rule, "agent-forward")
        self.assertEqual(fs[0].severity, "warning")

    def test_forward_agent_no_ok(self):
        self.assertEqual(self.check("ForwardAgent no"), [])

    def test_forward_x11_yes_warning(self):
        fs = self.check("ForwardX11 yes")
        self.assertEqual(rules(fs), {"x11-forward"})

    def test_forward_x11_trusted_yes_warning(self):
        fs = self.check("ForwardX11Trusted yes")
        self.assertEqual(rules(fs), {"x11-forward-trusted"})

    def test_forward_x11_no_ok(self):
        self.assertEqual(self.check("ForwardX11 no"), [])

    def test_permit_local_command_yes_warning(self):
        fs = self.check("PermitLocalCommand yes")
        self.assertEqual(rules(fs), {"permit-local-command"})

    def test_permit_local_command_no_ok(self):
        self.assertEqual(self.check("PermitLocalCommand no"), [])

    def test_host_block_context_in_message(self):
        fs = self.check("Host legacy\n  StrictHostKeyChecking no\n")
        self.assertIn("Host legacy", fs[0].message)

    def test_unrelated_keywords_ignored(self):
        self.assertEqual(self.check("Compression yes\nServerAliveInterval 60\n"), [])


class ServerRuleTests(unittest.TestCase):
    def check(self, text):
        return scc.check_config(text, "sshd_config", "server")

    def test_permit_root_login_yes_is_error(self):
        fs = self.check("PermitRootLogin yes")
        self.assertEqual(fs[0].rule, "permit-root-login")
        self.assertEqual(fs[0].severity, "error")

    def test_permit_root_login_prohibit_password_ok(self):
        self.assertEqual(self.check("PermitRootLogin prohibit-password"), [])

    def test_permit_root_login_no_ok(self):
        self.assertEqual(self.check("PermitRootLogin no"), [])

    def test_permit_empty_passwords_yes_is_error(self):
        fs = self.check("PermitEmptyPasswords yes")
        self.assertEqual(fs[0].rule, "empty-passwords")
        self.assertEqual(fs[0].severity, "error")

    def test_permit_empty_passwords_no_ok(self):
        self.assertEqual(self.check("PermitEmptyPasswords no"), [])

    def test_password_auth_yes_warning(self):
        fs = self.check("PasswordAuthentication yes")
        self.assertEqual(fs[0].rule, "password-auth")
        self.assertEqual(fs[0].severity, "warning")
        self.assertIn("heuristic", fs[0].message.lower())

    def test_password_auth_no_ok(self):
        self.assertEqual(self.check("PasswordAuthentication no"), [])

    def test_max_auth_tries_above_default_warning(self):
        fs = self.check("MaxAuthTries 10")
        self.assertEqual(rules(fs), {"max-auth-tries-high"})

    def test_max_auth_tries_at_default_ok(self):
        self.assertEqual(self.check("MaxAuthTries 6"), [])

    def test_max_auth_tries_non_numeric_ignored(self):
        self.assertEqual(self.check("MaxAuthTries abc"), [])

    def test_x11_forwarding_yes_warning(self):
        fs = self.check("X11Forwarding yes")
        self.assertEqual(rules(fs), {"x11-forwarding"})

    def test_x11_forwarding_no_ok(self):
        self.assertEqual(self.check("X11Forwarding no"), [])

    def test_server_mode_ignores_client_rules(self):
        self.assertEqual(self.check("ForwardAgent yes"), [])

    def test_client_mode_ignores_server_rules(self):
        fs = scc.check_config("PermitRootLogin yes", "ssh_config", "client")
        self.assertEqual(fs, [])


class ModeDetectionTests(unittest.TestCase):
    def test_sshd_config_is_server(self):
        self.assertEqual(scc.detect_mode("/etc/ssh/sshd_config"), "server")

    def test_sshd_test_config_is_server(self):
        self.assertEqual(scc.detect_mode("sshd_config.test"), "server")

    def test_ssh_config_is_client(self):
        self.assertEqual(scc.detect_mode("/home/u/.ssh/config"), "client")

    def test_anything_else_defaults_client(self):
        self.assertEqual(scc.detect_mode("my.conf"), "client")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_clean_file_exit_zero(self):
        p = self.write("ssh_config", "Host *\n  StrictHostKeyChecking ask\n")
        code, out, _ = run([p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_error_exit_one(self):
        p = self.write("ssh_config", "StrictHostKeyChecking no\n")
        code, out, _ = run([p])
        self.assertEqual(code, 1)
        self.assertIn("strict-host-key-checking-off", out)

    def test_warning_only_exit_zero_by_default(self):
        p = self.write("ssh_config", "ForwardAgent yes\n")
        code, out, _ = run([p])
        self.assertEqual(code, 0)
        self.assertIn("agent-forward", out)

    def test_fail_on_warning_exit_one(self):
        p = self.write("ssh_config", "ForwardAgent yes\n")
        code, _, _ = run(["--fail-on-warning", p])
        self.assertEqual(code, 1)

    def test_ignore_suppresses_rule(self):
        p = self.write("ssh_config", "StrictHostKeyChecking no\n")
        code, out, _ = run(
            ["--ignore", "strict-host-key-checking-off", p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_json_output_shape(self):
        p = self.write("sshd_config", "PermitRootLogin yes\n")
        code, out, _ = run(["--format", "json", p])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["summary"]["errors"], 1)
        self.assertEqual(data["findings"][0]["rule"], "permit-root-login")
        self.assertEqual(data["findings"][0]["line"], 1)

    def test_auto_mode_by_filename(self):
        p = self.write("sshd_config", "PermitRootLogin yes\nForwardAgent yes\n")
        code, out, _ = run([p])
        self.assertEqual(code, 1)
        self.assertIn("permit-root-login", out)
        self.assertNotIn("agent-forward", out)

    def test_mode_override(self):
        p = self.write("custom.conf", "PermitRootLogin yes\n")
        code, out, _ = run(["--mode", "server", p])
        self.assertEqual(code, 1)
        self.assertIn("permit-root-login", out)

    def test_multiple_files_all_checked(self):
        p1 = self.write("ssh_config", "ForwardAgent yes\n")
        p2 = self.write("sshd_config", "PermitRootLogin yes\n")
        code, out, _ = run([p1, p2])
        self.assertEqual(code, 1)
        self.assertIn("agent-forward", out)
        self.assertIn("permit-root-login", out)

    def test_missing_file_exit_two(self):
        code, _, err = run(["/nonexistent/nope.conf"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_text_output_counts(self):
        p = self.write("sshd_config",
                       "PermitRootLogin yes\nX11Forwarding yes\n")
        code, out, _ = run([p])
        self.assertEqual(code, 1)
        self.assertIn("1 error(s), 1 warning(s)", out)

    def test_findings_carry_line_numbers(self):
        p = self.write("ssh_config",
                       "Host *\n\n  StrictHostKeyChecking no\n")
        code, out, _ = run([p])
        self.assertIn(":3 [", out)


if __name__ == "__main__":
    unittest.main()
