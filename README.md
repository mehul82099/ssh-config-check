# ssh-config-check

A CI linter for OpenSSH client (`ssh_config`) and server (`sshd_config`)
files. It flags settings that silently weaken host-key verification or
authentication, so they get caught in review instead of after an
incident:

| Rule | Severity | Why |
|---|---|---|
| `strict-host-key-checking-off` | error | `StrictHostKeyChecking no/off` makes ssh automatically add new host keys without asking, so a man-in-the-middle key swap is accepted silently (ssh_config(5)). |
| `known-hosts-dev-null` | error | `UserKnownHostsFile /dev/null` discards the host key database; combined with `StrictHostKeyChecking no` it disables host key verification entirely (ssh_config(5)). |
| `agent-forward` | warning | `ForwardAgent yes`: ssh_config(5) says agent forwarding "should be enabled with caution" - a user able to bypass file permissions on the remote host can authenticate using your local agent's identities. |
| `x11-forward` / `x11-forward-trusted` | warning | ssh_config(5) says X11 forwarding "should be enabled with caution" and warns of keystroke monitoring when `ForwardX11Trusted` is also enabled. |
| `permit-local-command` | warning | `PermitLocalCommand yes` allows local command execution via `LocalCommand` or the `!` escape (ssh_config(5)). |
| `permit-root-login` | error | `PermitRootLogin yes` allows direct root login; the sshd_config(5) default is `prohibit-password`. |
| `empty-passwords` | error | `PermitEmptyPasswords yes` allows login to accounts with empty password strings; the sshd_config(5) default is `no`. |
| `password-auth` | warning | **Heuristic:** `PasswordAuthentication yes` is also the sshd_config(5) default; key-only authentication is a common hardening goal. Suppress with `--ignore password-auth` if passwords are intended. |
| `max-auth-tries-high` | warning | `MaxAuthTries` above the sshd_config(5) default of 6. |
| `x11-forwarding` | warning | `X11Forwarding yes`: same X11 caution from ssh_config(5), server side. |

It understands real config syntax: case-insensitive keywords,
`keyword value` and `keyword=value` forms, `#` comments, and `Host` /
`Match` blocks (findings name the block they came from).

## Usage

```sh
python3 ssh_config_check.py ~/.ssh/config /etc/ssh/sshd_config
python3 ssh_config_check.py --mode server custom.conf
python3 ssh_config_check.py --ignore password-auth sshd_config
python3 ssh_config_check.py --fail-on-warning --format json ssh_config
```

- Mode is auto-detected by filename (`sshd*` files are linted as server
  configs, everything else as client); override with `--mode`.
- Exit code `0` clean, `1` on errors (or on warnings with
  `--fail-on-warning`), `2` on unreadable input.

Example output:

```
sshd_config:12 [error] permit-root-login: PermitRootLogin yes allows direct root login; the sshd_config(5) default is prohibit-password.
ssh_config:4 [warning] agent-forward: ForwardAgent yes (in Host bastion): ssh_config(5) warns agent forwarding "should be enabled with caution" ...
ssh-config-check: 1 error(s), 1 warning(s)
```

No dependencies beyond the Python 3 standard library. CI runs the test
suite on Ubuntu and Windows against Python 3.9 and 3.13.

## Scope

The tool checks the specific keywords listed above against the semantics
in the OpenSSH man pages. It is not a general sshd hardening audit (it
does not evaluate crypto algorithm lists, AllowUsers/DenyUsers, or
network exposure), and the `password-auth` rule is a heuristic, labeled
as such in its message and here.

## Sources

- ssh_config(5) - OpenBSD man pages: https://man.openbsd.org/ssh_config.5
- sshd_config(5) - OpenBSD man pages: https://man.openbsd.org/sshd_config.5
  (`MaxAuthTries` "The default is 6", `PasswordAuthentication` "The
  default is yes", `PermitEmptyPasswords` "The default is no",
  `PermitRootLogin` "The default is prohibit-password")

## License

MIT
