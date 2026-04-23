# SSH Plugin

The `ssh` plugin lets Vultrino hold an SSH password and drive remote
deployments and commands against a host — without the calling agent ever
seeing the password. It ships as a built-in plugin, so no separate
installation step is needed.

Two actions are exposed:

| Action  | What it does                                                    |
|---------|-----------------------------------------------------------------|
| `deploy`| `rsync` a local directory to the remote host over SSH           |
| `run`   | Execute a sequence of shell commands over SSH                   |

Both read their inputs from credential **metadata** by default, so a
credential alias can hold the full recipe for a specific server (source
path, destination, excludes, command list). Agents then invoke the action
against the alias and supply no parameters — which is also how the
override-lock security model works.

## System requirements

`sshpass`, `ssh`, and `rsync` must be on `PATH`.

| macOS (Homebrew) | `brew install hudochenkov/sshpass/sshpass` (and `rsync` is preinstalled) |
| Debian / Ubuntu  | `apt install sshpass rsync openssh-client`                               |
| RHEL / Fedora    | `dnf install sshpass rsync openssh-clients`                              |

The plugin will return a clear "binary not found" error if any of these
are missing; it won't silently fall back.

## Credential type: `ssh_password`

Holds the connection info and the password that will be supplied to
`sshpass` at invocation time.

### Fields

| Field      | Type     | Required | Description                       |
|------------|----------|----------|-----------------------------------|
| `host`     | text     | Yes      | Hostname or IP of the SSH server  |
| `port`     | text     | No       | SSH port (default `22`)           |
| `user`     | text     | Yes      | SSH username                      |
| `password` | password | Yes      | SSH password (stored encrypted)   |

### Adding via CLI

```bash
vultrino add \
  --alias prod-api \
  --type ssh_password \
  --ssh-host deploy.example.com \
  --ssh-user deploy
# prompts for SSH password
```

Add as many credentials as you have targets — each alias is an
independent "instance" with its own host, user, password, and metadata
defaults.

## Configuring per-credential defaults (metadata)

Metadata is free-form key-value on the credential. The plugin looks up
specific keys to populate action inputs. Set them via the `vultrino meta`
subcommand:

```bash
vultrino meta set prod-api deploy.source_dir /path/to/local/dir/
vultrino meta set prod-api deploy.dest_dir   /opt/app/
vultrino meta set prod-api deploy.excludes   '[".git",".env","node_modules","dist"]'

vultrino meta list prod-api
vultrino meta unset prod-api deploy.excludes
```

### Deploy keys

| Key                      | Default        | Description                                                                 |
|--------------------------|----------------|-----------------------------------------------------------------------------|
| `deploy.source_dir`      | —              | Local directory. Trailing `/` is significant to rsync — see `man rsync`.    |
| `deploy.dest_dir`        | —              | Remote directory.                                                           |
| `deploy.excludes`        | `[]`           | JSON array of rsync `--exclude` patterns.                                   |
| `deploy.flags`           | `-avz`         | Rsync flags as a single string.                                             |
| `deploy.timeout_secs`    | `1800` (30min) | Kill local rsync if it exceeds this.                                        |
| `deploy.allow_override`  | `false`        | If `true`, callers can override `source_dir` / `dest_dir` / `excludes` / `flags` in params. |

### Run keys

| Key                     | Default       | Description                                                                  |
|-------------------------|---------------|------------------------------------------------------------------------------|
| `run.commands`          | —             | JSON array of commands. Each runs in its own SSH invocation.                 |
| `run.stop_on_error`     | `false`       | If `true`, halt the sequence on the first non-zero exit.                     |
| `run.interval_ms`       | `0`           | Milliseconds to sleep between commands.                                      |
| `run.timeout_secs`      | `300` (5min)  | Per-command timeout. Local ssh is killed on expiry.                          |
| `run.allow_override`    | `false`       | If `true`, callers can pass a custom `commands` array in params.             |

### Shared keys

| Key                             | Default        | Description                                         |
|---------------------------------|----------------|-----------------------------------------------------|
| `ssh.strict_host_key_checking`  | `accept-new`   | Forwarded to `ssh -o StrictHostKeyChecking=…`. Sensible choices are `accept-new`, `yes`, `no`. |

## Actions

### `ssh.deploy` — rsync a directory

Invoked with zero params, uses metadata defaults:

```bash
vultrino action prod-api ssh.deploy
```

Params (all optional):

| Param         | Locked by override? | Description                                       |
|---------------|--------------------|---------------------------------------------------|
| `dry_run`     | Always allowed     | Run `rsync --dry-run`. Useful for agents to preview. |
| `source_dir`  | Locked             | Requires `deploy.allow_override=true`.            |
| `dest_dir`    | Locked             | Requires `deploy.allow_override=true`.            |
| `excludes`    | Locked             | Requires `deploy.allow_override=true`.            |
| `flags`       | Locked             | Requires `deploy.allow_override=true`.            |
| `timeout_secs`| Always allowed     | Override the configured timeout.                  |

Response body:

```json
{
  "ok": true,
  "exit_code": 0,
  "stdout": "sending incremental file list\n...",
  "stderr": "",
  "duration_ms": 4213,
  "timed_out": false,
  "dry_run": false,
  "command_display": "sshpass -e rsync -avz --exclude=.git -e \"ssh -p 22 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30\" /src/ user@host:/dest/"
}
```

### `ssh.run` — execute a command sequence

```bash
vultrino action prod-api ssh.run
```

Params (all optional):

| Param          | Locked by override? | Description                                         |
|----------------|--------------------|-----------------------------------------------------|
| `commands`     | Locked             | JSON array. Requires `run.allow_override=true`.     |
| `stop_on_error`| Always allowed     | Halt on first non-zero exit.                        |
| `interval_ms`  | Always allowed     | Sleep between commands.                             |
| `timeout_secs` | Always allowed     | Per-command timeout.                                |

Response body:

```json
{
  "ok": true,
  "results": [
    {
      "index": 0,
      "command": "uptime",
      "ok": true,
      "exit_code": 0,
      "stdout": " 13:42:17 up 18 days, ...\n",
      "stderr": "",
      "duration_ms": 742,
      "timed_out": false
    }
  ]
}
```

`ok` at the top level is `true` only if every command returned 0 *and*
none timed out.

## Security model

- **Password never leaves Vultrino.** Agents present a credential alias; the
  plugin resolves it, decrypts the password, and passes it to `sshpass`
  via the `SSHPASS` environment variable — never visible in `ps` output,
  never on disk.
- **Override-locked by default.** An agent cannot pass a custom command
  list or target directory unless the credential's metadata explicitly
  opts in with `run.allow_override=true` / `deploy.allow_override=true`.
  This is intentional: a credential is a fixed recipe, and a prompt-
  injected agent can't turn it into "rm -rf /" without the credential
  owner's opt-in.
- **Host key verification.** `StrictHostKeyChecking=accept-new` is the
  default — trust on first use, reject on key change. Change it via the
  `ssh.strict_host_key_checking` metadata key if you need stricter or
  looser behavior.
- **Timeouts actually kill.** Commands that exceed their timeout have
  the *local* ssh/rsync process sent SIGKILL (`tokio::Command::kill_on_drop(true)`).
  The remote side is best-effort — SIGHUP from the closed SSH channel
  should reach the remote command, but commands that explicitly detach
  from stdio (`nohup`, `disown`, backgrounded processes) can outlive the
  channel. Response carries a `timed_out: bool` so callers don't mistake
  a timeout for a clean exit.

## MCP exposure

Both actions are exposed as MCP tools automatically:

| MCP tool name | Action      |
|---------------|-------------|
| `ssh_deploy`  | `ssh.deploy`|
| `ssh_run`     | `ssh.run`   |

Schemas include all params above plus `credential` and `api_key`.

## Common gotchas

### `bash: command not found` when you know the binary is installed

`ssh host "mycommand"` gives you a **non-interactive, non-login shell**.
It doesn't source `~/.bashrc`, `~/.zshrc`, or (usually) `~/.profile`, so
PATH additions installers wrote there aren't present. Workarounds in
rough order of cleanest-first:

- Reference the absolute path: `/root/.nvm/versions/node/v20/bin/node server.js`.
- Set PATH inline: `PATH=$HOME/.cargo/bin:$PATH my-tool` .
- Shift the command into an existing session that has the right
  environment: `tmux send-keys -t mysession 'my-tool' Enter` — this is
  fire-and-forget (you won't see the command's exit code), so pair with a
  health probe at the end if correctness matters.

### `pkill -f` kills itself

`pkill -f pattern` matches against every process's full argv. The pkill
*you just ran* also contains `pattern` in its argv, so it'll match — and
the shell running it gets killed, causing your SSH connection to drop
with exit status 255.

Use `pkill <name>` without `-f` when matching by process name. If you
really need `-f`, pick a pattern that can't match pkill itself (e.g.
`pkill -f '^/usr/local/bin/myapp'`).

### `tmux send-keys` doesn't report command results

`tmux send-keys` returns 0 as soon as the keystrokes are delivered — not
when the command inside tmux finishes. If you need to know the
deployment actually started, append an explicit probe after the
send-keys command, running over ssh proper:

```json
[
  "tmux send-keys -t app 'bun install && bun run start' Enter",
  "sleep 8 && curl -fsS http://127.0.0.1:3000/health"
]
```

The final command's exit code gives you real status.

## Example: typical deploy + restart flow

For a service running under tmux on a VPS, with the backend process in
a tmux pane named `app`:

```bash
vultrino add \
  --alias prod-api \
  --type ssh_password \
  --ssh-host deploy.example.com \
  --ssh-user deploy

vultrino meta set prod-api deploy.source_dir /path/to/local/backend/
vultrino meta set prod-api deploy.dest_dir   /srv/app/
vultrino meta set prod-api deploy.excludes \
  '[".git",".env","node_modules","dist","tests"]'

vultrino meta set prod-api run.commands '[
  "tmux send-keys -t app C-c",
  "tmux send-keys -t app C-c",
  "sleep 1",
  "pkill -9 mybinary || true",
  "sleep 1",
  "tmux send-keys -t app '\''cd /srv/app && myinstall && myrun'\'' Enter"
]'

# Sanity-check once before relying on it
vultrino action prod-api ssh.deploy -p '{"dry_run": true}'

# Real deploy + restart
vultrino action prod-api ssh.deploy
vultrino action prod-api ssh.run
```

Multiple targets? Just create more aliases with their own metadata —
`staging-api`, `dr-api`, etc. Same plugin, different credentials.
