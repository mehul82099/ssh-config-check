#!/usr/bin/env python3
"""ssh-config-check - a CI linter for OpenSSH client and server configs.

Reads ssh_config(5) / sshd_config(5) files and flags settings that
weaken authentication or host-key verification: StrictHostKeyChecking
off, known-hosts pointed at /dev/null, agent/X11 forwarding, root login,
empty passwords, and more. Every finding cites the man page it comes
from; heuristic judgments are labeled as heuristics.

Pure standard library.

Sources:
- ssh_config(5): https://man.openbsd.org/ssh_config.5
- sshd_config(5): https://man.openbsd.org/sshd_config.5
"""

import argparse
import json
import os
import sys


class Finding:
    def __init__(self, path, line, rule, severity, message):
        self.path = path
        self.line = line
        self.rule = rule
        self.severity = severity  # "error" or "warning"
        self.message = message

    def as_dict(self):
        return {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


def parse_config(text):
    """Yield (lineno, keyword, value, block). keyword is lowercased.

    ssh_config keywords are case-insensitive and may be written
    'keyword value' or 'keyword=value'. '#' starts a comment at the
    beginning of a line or after whitespace (documented approximation of
    the real quoting rules). Host/Match open a block; the current Host
    block name is carried for context.
    """
    block = None
    out = []
    for lineno, raw in enumerate(text.split("\n"), 1):
        line = raw
        # strip comments: # at line start or preceded by whitespace
        for i, ch in enumerate(line):
            if ch == "#" and (i == 0 or line[i - 1].isspace()):
                line = line[:i]
                break
        line = line.strip()
        if not line:
            continue
        if "=" in line.split(None, 1)[0]:
            kw, _, value = line.partition("=")
            kw, value = kw.strip(), value.strip()
        else:
            parts = line.split(None, 1)
            kw = parts[0]
            value = parts[1].strip() if len(parts) > 1 else ""
        lkw = kw.lower()
        if lkw == "host":
            block = "Host " + value
        elif lkw == "match":
            block = "Match " + value
        out.append((lineno, lkw, value, block))
    return out


def _yes(value):
    return value.lower() == "yes"


def _in_block(block):
    return " (in %s)" % block if block else ""


CLIENT_RULES = {
    "stricthostkeychecking", "userknownhostsfile", "forwardagent",
    "forwardx11", "forwardx11trusted", "permitlocalcommand",
}
SERVER_RULES = {
    "permitrootlogin", "permitemptypasswords", "passwordauthentication",
    "maxauthtries", "x11forwarding",
}


def check_config(text, path, mode):
    findings = []

    def emit(line, rule, severity, message):
        findings.append(Finding(path, line, rule, severity, message))

    for lineno, kw, value, block in parse_config(text):
        loc = _in_block(block if kw not in ("host", "match") else None)
        v = value.lower()

        if mode == "client":
            if kw == "stricthostkeychecking" and v in ("no", "off"):
                emit(lineno, "strict-host-key-checking-off", "error",
                     "StrictHostKeyChecking %s: ssh_config(5) says \"no\" "
                     "makes ssh automatically add new host keys without "
                     "asking, so a man-in-the-middle key swap is accepted "
                     "silently%s." % (value, loc))
            elif kw == "userknownhostsfile" and v == "/dev/null":
                emit(lineno, "known-hosts-dev-null", "error",
                     "UserKnownHostsFile /dev/null discards the host key "
                     "database%s; with StrictHostKeyChecking no this "
                     "disables host key verification entirely." % loc)
            elif kw == "forwardagent" and _yes(v):
                emit(lineno, "agent-forward", "warning",
                     "ForwardAgent yes%s: ssh_config(5) warns agent "
                     "forwarding \"should be enabled with caution\" - a "
                     "user able to bypass file permissions on the remote "
                     "host can authenticate with your local agent's "
                     "identities." % loc)
            elif kw == "forwardx11trusted" and _yes(v):
                emit(lineno, "x11-forward-trusted", "warning",
                     "ForwardX11Trusted yes%s: ssh_config(5) warns of "
                     "keystroke monitoring when trusted X11 forwarding is "
                     "enabled." % loc)
            elif kw == "forwardx11" and _yes(v):
                emit(lineno, "x11-forward", "warning",
                     "ForwardX11 yes%s: ssh_config(5) says X11 forwarding "
                     "\"should be enabled with caution\"." % loc)
            elif kw == "permitlocalcommand" and _yes(v):
                emit(lineno, "permit-local-command", "warning",
                     "PermitLocalCommand yes%s allows local command "
                     "execution via LocalCommand or the '!' escape "
                     "(ssh_config(5))." % loc)

        else:  # server
            if kw == "permitrootlogin" and v == "yes":
                emit(lineno, "permit-root-login", "error",
                     "PermitRootLogin yes allows direct root login; the "
                     "sshd_config(5) default is prohibit-password.")
            elif kw == "permitemptypasswords" and _yes(v):
                emit(lineno, "empty-passwords", "error",
                     "PermitEmptyPasswords yes allows login to accounts "
                     "with empty password strings (sshd_config(5) "
                     "default: no).")
            elif kw == "passwordauthentication" and _yes(v):
                emit(lineno, "password-auth", "warning",
                     "PasswordAuthentication yes (also the default) - "
                     "key-only authentication is the common hardening "
                     "goal; heuristic rule, suppress with --ignore if "
                     "passwords are intended.")
            elif kw == "maxauthtries":
                try:
                    tries = int(value)
                except ValueError:
                    continue
                if tries > 6:
                    emit(lineno, "max-auth-tries-high", "warning",
                         "MaxAuthTries %d is above the sshd_config(5) "
                         "default of 6." % tries)
            elif kw == "x11forwarding" and _yes(v):
                emit(lineno, "x11-forwarding", "warning",
                     "X11Forwarding yes: ssh_config(5) warns X11 "
                     "forwarding \"should be enabled with caution\".")
    return findings


def detect_mode(path):
    base = os.path.basename(path).lower()
    if base.startswith("sshd"):
        return "server"
    return "client"


def format_text(results):
    lines = []
    errors = warnings = 0
    for path, findings in results:
        for f in findings:
            lines.append("%s:%d [%s] %s: %s" % (
                f.path, f.line, f.severity, f.rule, f.message))
            if f.severity == "error":
                errors += 1
            else:
                warnings += 1
    if errors or warnings:
        lines.append("ssh-config-check: %d error(s), %d warning(s)" % (
            errors, warnings))
    else:
        lines.append("ssh-config-check: clean")
    return "\n".join(lines), errors, warnings


def format_json(results, errors, warnings):
    return json.dumps({
        "findings": [f.as_dict() for _, fs in results for f in fs],
        "summary": {"files": len(results), "errors": errors,
                    "warnings": warnings},
    }, indent=2)


def build_parser():
    p = argparse.ArgumentParser(
        prog="ssh-config-check",
        description="Lint OpenSSH client/server configs for weakened "
                    "authentication or host-key verification, per "
                    "ssh_config(5) / sshd_config(5).")
    p.add_argument("configs", nargs="+",
                   help="ssh_config / sshd_config file(s)")
    p.add_argument("--mode", choices=["client", "server", "auto"],
                   default="auto",
                   help="keyword set to apply (default: auto - files "
                        "named sshd* are server, others client)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="suppress a rule by name (repeatable)")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    ignore = set(args.ignore)
    results = []
    for path in args.configs:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            print("ssh-config-check: cannot read %s: %s" % (path, exc),
                  file=sys.stderr)
            return 2
        mode = detect_mode(path) if args.mode == "auto" else args.mode
        findings = [f for f in check_config(text, path, mode)
                    if f.rule not in ignore]
        results.append((path, findings))

    text_out, errors, warnings = format_text(results)
    if args.format == "json":
        print(format_json(results, errors, warnings))
    else:
        print(text_out)
    if errors:
        return 1
    if args.fail_on_warning and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
