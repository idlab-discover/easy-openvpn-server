# Notes for agents working on easy-openvpn-server

A snap that runs an OpenVPN server with secure defaults: a udp and a tcp daemon, plus the `easy-openvpn-server` CLI to manage clients. Read the README for what users see.

## How the code fits together

- `easy-openvpn-server/easy_openvpn_server/cli.py` is the CLI and does all the setup. The configure hook runs `easy-openvpn-server setup` on install, refresh and every `snap set`. It creates the CA and keys, and renders the files in `templates/`:
  - `server.conf` → the OpenVPN config of each daemon (`tcp-server.conf`, `udp-server.conf`);
  - `server.env` → `tcp-server.env` / `udp-server.env`, the values `scripts/run.sh` needs;
  - `client.ovpn` → each client's config, which contains its private key.
- `scripts/run.sh` starts each daemon. It sources its `.env` file, sets up NAT and the firewall chain for that daemon (`eovpn-udp-server`, `eovpn-tcp-server`), and removes them again when the daemon stops.
- **The CLI decides, `run.sh` only executes.** Any value `run.sh` needs goes into the `.env` file, shell-quoted. Don't make `run.sh` parse the OpenVPN configs, and don't repeat a decision in Bash.
- Generated files live in `$SNAP_USER_DATA` (`/root/snap/easy-openvpn-server/current/`). Client-specific OpenVPN config goes in `$SNAP_COMMON/ccd/`. OpenVPN drops privileges to `snap_daemon`, and anything it reads after that must be readable by that user. `/root` isn't.
- Files with secrets (keys, `.ovpn`, `.env`) are written with `write_private_file()`, so they're never readable by other users, not even briefly.

## Settings

- User-facing settings are plain snap config keys (`push-default-gateway`, `firewall.client-to-client`, `tcp-server.port`, …), documented in the README and in the `description` in `snapcraft.yaml`. Keep those two in sync.
- Validate new settings with `get_validated_config()`, so that a bad value makes `snap set` fail with a clear message. (The ports and `push-default-gateway` predate this and aren't validated yet.)
- `internal.*` keys are the snap's own state, such as the randomly picked tunnel networks. They aren't meant for users.
- **Add as few settings as possible.** Only add one when there's a real need.
- **Changing a default:** keep the old behavior on existing installs and show a warning (`get_warnings()`) until the admin chooses explicitly; use the new default on fresh installs. `migrate_config()` tells upgrades from fresh installs apart, tracked by `internal.config-generation`. See `firewall.client-to-client` for an example.
- Existing client configs must keep working after an upgrade, unless a release says otherwise in its notes.

## Tests

`tests/harness.sh` is an end-to-end test in LXD. A VM runs the snap, and three containers connect with OpenVPN 2.5, 2.6 and 2.7 clients. A "lan" VM behind the server shows whether traffic really goes through the VPN, and stands in for a cloud metadata service.

```bash
snapcraft pack
tests/harness.sh --snap easy-openvpn-server_*_amd64.snap                 # server on Ubuntu 24.04
tests/harness.sh --snap easy-openvpn-server_*_amd64.snap --server-release 26.04
tests/harness.sh --candidate                                             # test latest/candidate
```

- It installs `latest/stable`, creates clients, upgrades to the snap under test and checks that the old configs still work. Then it runs one scenario per feature, and a fresh install last.
- A run takes 10–15 minutes and needs LXD with VM support (`/dev/kvm`). `--keep` keeps the instances for debugging; `HARNESS_TIMEOUT` (default 45m) limits a run.
- Every change adds or extends the scenario that tests it. In checks, use `check` / `check_not`; use `require` only as an `if` condition, to skip checks that depend on it.

Things that cost a lot of time before:

- In some environments `lxc` (and `snapcraft`) print nothing unless their output goes into a pipe. The harness pipes everything (`lx() { ... | cat; }`); do the same for ad-hoc commands, with `set -o pipefail`.
- With a terminal on stdin, `lxc` goes interactive, and a harness running in the background then hangs forever. The harness does `exec </dev/null`; do the same for ad-hoc `lxc` and `snap` commands.
- Don't edit `tests/harness.sh` while it runs: Bash reads scripts as it goes, so the running harness breaks. `lib.sh` is loaded at startup and is safe to edit.
- With `pipefail`, `... | grep -q` fails when grep exits early and the command before it gets SIGPIPE. Use `grep ... >/dev/null`. `openvpn --help` also exits non-zero: capture its output first.
- `snap run --shell` on the daemon apps hangs: it goes through `run.sh`, which waits for a config. Run the snap's binaries directly instead.
- Unprivileged containers can't use OpenVPN's in-kernel data channel (DCO), so the harness passes `--disable-dco` to clients that support it.
- `pkill -f harness` also matches the shell running the `pkill`.

## Build and release

- `snapcraft pack` builds for the local architecture. `snapcraft remote-build` builds all architectures on Launchpad. An interrupted remote build leaves its recipe on Launchpad.
- Architectures: amd64, arm64, armhf, ppc64el and s390x. riscv64 is left out: Launchpad's riscv64 queue can take days, longer than a CI job may run.
- Stage package names can differ per architecture. On 32-bit architectures, libraries got a `t64` suffix (e.g. `libatm1t64`), while 64-bit ones still resolve the old name. A remote build catches this; a local amd64 build doesn't.
- **Every push to `candidate` releases.** `.github/workflows/release-to-candidate.yml` builds on Launchpad, uploads to `latest/candidate`, runs the harness on 24.04 and 26.04, and opens a "Call for testing" issue (label `testing`). It also runs weekly, so rebuilds pick up security fixes in the bundled packages. Commenting `/promote <revisions> latest/stable` on that issue releases to stable.
- A failed Store upload ("Remote end closed connection") is usually transient: rerun the failed job.

## Working conventions

- **One commit per step.** Each commit does one thing and contains the test for it. A related bugfix found along the way gets its own commit.
- Make changes on a branch and open a PR against `candidate`, unless the maintainer says otherwise.
- Run `shellcheck` on the shell scripts.
- Comments you post on GitHub appear under the maintainer's account: start them with "Claude Code:" (or your agent's name) and end with "_— Claude Code_". Only post when asked.

## Known limitations

- A Linux client with IPv6 completely disabled can't connect: the server always assigns an IPv6 address.
- A fixed address in `ccd/` only works for one of the two daemons: they share the folder but use different tunnel networks.
- With `topology net30`, the server doesn't use the in-kernel data channel (DCO), even when the `ovpn` module is loaded.
- OpenVPN 2.4 and older aren't supported or tested.
