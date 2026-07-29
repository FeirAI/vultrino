# Postgres Plugin

The `postgres` plugin holds PostgreSQL connection credentials and drives
the two most common "run it from an automation system" operations: SQL
execution (migrations, maintenance) and `pg_dump`-based backups. The
stored password is absent from the calling agent's schema — Vultrino passes it
to the trusted `psql` / `pg_dump` child via the `PGPASSWORD` environment
variable, then drops its exposed copy. It ships as a built-in plugin;
no separate installation step.

Two actions are exposed:

| Action       | What it does                                                      |
|--------------|-------------------------------------------------------------------|
| `run_sql`    | Execute SQL (a raw string or a local `.sql` file) against the DB  |
| `backup`     | Run `pg_dump` and write the output to a local file                |

Both read their inputs from credential **metadata** by default, so a
credential alias can hold the full recipe (which script to run, where
to put backups). Agents then invoke the action against the alias and
supply no parameters — which is how the override-lock security model
works.

## System requirements

`psql` and `pg_dump` must be on `PATH`. These ship together in the
`postgresql-client` package.

| macOS (Homebrew) | `brew install libpq && brew link --force libpq` (or `brew install postgresql@16` for the full server) |
| Debian / Ubuntu  | `apt install postgresql-client`                                                                       |
| RHEL / Fedora    | `dnf install postgresql`                                                                              |

Pick a client version that is greater than or equal to your server's
major version — older clients can fail on dumps from newer servers.

## Credential type: `postgres`

Holds the connection info and password used by both actions.

### Fields

| Field      | Type     | Required | Description                                           |
|------------|----------|----------|-------------------------------------------------------|
| `host`     | text     | Yes      | Hostname or IP of the Postgres server                 |
| `port`     | text     | No       | Postgres port (default `5432`)                        |
| `database` | text     | Yes      | Database name                                         |
| `user`     | text     | Yes      | Postgres role / username                              |
| `password` | password | Yes      | Password (stored encrypted; passed via `PGPASSWORD`)  |
| `sslmode`  | text     | No       | libpq sslmode: `disable`, `allow`, `prefer` (default), `require`, `verify-ca`, `verify-full` |

The default `sslmode` is `prefer` to match libpq's out-of-the-box
behavior and to avoid hard-failing if the server doesn't advertise TLS.
For production remote databases, set it explicitly to `require` or
stronger on the credential.

### Adding via CLI

```bash
vultrino add \
  --alias prod-db \
  --type postgres \
  --pg-host db.example.com \
  --pg-database app_production \
  --pg-user deploy \
  --pg-sslmode require
# prompts for the Postgres password
```

Add as many credentials as you have targets — each alias is an
independent "instance" with its own host, user, password, and metadata
defaults.

## Configuring per-credential defaults (metadata)

Metadata is free-form key-value on the credential. The plugin looks up
specific keys to populate action inputs. Set them via the `vultrino meta`
subcommand:

```bash
vultrino meta set prod-db run_sql.file   /path/to/repo/migrations/apply.sql
vultrino meta set prod-db backup.output_dir /var/backups/postgres/
vultrino meta set prod-db backup.filename_template "{alias}-{date}.sql"

vultrino meta list prod-db
vultrino meta unset prod-db backup.format
```

### `run_sql` keys

| Key                             | Default       | Description                                                                                        |
|---------------------------------|---------------|----------------------------------------------------------------------------------------------------|
| `run_sql.sql`                   | —             | Default raw SQL string (mutually exclusive with `run_sql.file`).                                   |
| `run_sql.file`                  | —             | Default path to a `.sql` file on the local machine.                                                |
| `run_sql.transaction`           | `true`        | Wrap the execution in a single transaction (`--single-transaction` + `ON_ERROR_STOP`).             |
| `run_sql.statement_timeout_ms`  | `0` (off)     | Sets Postgres `statement_timeout` at session start.                                                |
| `run_sql.timeout_secs`          | `600` (10min) | Wall-clock timeout for the `psql` process. Local process is killed on expiry.                      |
| `run_sql.allow_override`        | `false`       | If `true`, callers can pass a custom `sql` or `file` in params.                                    |

### `backup` keys

| Key                         | Default                          | Description                                                                            |
|-----------------------------|----------------------------------|----------------------------------------------------------------------------------------|
| `backup.output_dir`         | —                                | Local directory to write dumps into. Must exist.                                       |
| `backup.filename_template`  | `{alias}-{timestamp}.sql`        | Tokens: `{alias}`, `{date}` (`YYYY-MM-DD`), `{time}` (`HH-MM-SS`), `{timestamp}` (unix seconds). |
| `backup.format`             | `plain`                          | pg_dump format: `plain`, `custom`, `directory`, `tar`.                                 |
| `backup.timeout_secs`       | `1800` (30min)                   | Wall-clock timeout for `pg_dump`.                                                      |
| `backup.allow_override`     | `false`                          | If `true`, callers can pass `output_path` / `format` in params.                        |

## Actions

### `postgres.run_sql` — execute SQL

Invoked with zero params, uses metadata defaults:

```bash
vultrino action prod-db postgres.run_sql
```

Params (all optional):

| Param          | Locked by override? | Description                                                                |
|----------------|--------------------|----------------------------------------------------------------------------|
| `sql`          | Locked             | Raw SQL string. Requires `run_sql.allow_override=true`.                    |
| `file`         | Locked             | Path to a local `.sql` file. Requires `run_sql.allow_override=true`.       |
| `transaction`  | Always allowed     | Wrap in a single transaction (default: `true`).                            |
| `timeout_secs` | Always allowed     | Wall-clock timeout override.                                               |

`sql` and `file` are mutually exclusive. Raw SQL is fed to `psql` via
stdin (not `-c`), so it handles multi-statement scripts, comments, and
`\` meta-commands correctly.

Response body:

```json
{
  "ok": true,
  "exit_code": 0,
  "stdout": "BEGIN\nCREATE TABLE\n...",
  "stderr": "",
  "duration_ms": 213,
  "timed_out": false,
  "source": "file:/path/to/migrations/apply.sql",
  "transaction": true
}
```

### `postgres.backup` — pg_dump to a local file

```bash
vultrino action prod-db postgres.backup
```

Params (all optional):

| Param          | Locked by override? | Description                                                                       |
|----------------|--------------------|-----------------------------------------------------------------------------------|
| `output_path`  | Locked             | Full output file path. Requires `backup.allow_override=true`.                     |
| `format`       | Locked             | Override the format. Requires `backup.allow_override=true`.                       |
| `timeout_secs` | Always allowed     | Wall-clock timeout override.                                                      |

The destination directory must exist before the call — the plugin
refuses to create it, so a mistyped path fails loudly instead of
dumping into `/` unexpectedly.

Response body:

```json
{
  "ok": true,
  "exit_code": 0,
  "stdout": "",
  "stderr": "",
  "duration_ms": 4210,
  "timed_out": false,
  "output_path": "/var/backups/postgres/prod-db-2026-04-24.sql",
  "format": "plain",
  "bytes_written": 12345678
}
```

## Security model

- **Password stays out of the agent response.** Agents present a credential
  alias; the trusted plugin decrypts the password and hands it to `psql` /
  `pg_dump` via the `PGPASSWORD` env var of the child process — not visible in
  `ps`, not on disk.
- **SQL overrides are locked by default.** Raw SQL is code. An agent
  cannot pass a custom `sql` string or `file` path unless the
  credential's metadata explicitly opts in with
  `run_sql.allow_override=true`. With the lock on, the credential is a
  sealed "run our migration script" operation, and a prompt-injected
  agent can't turn it into `DROP TABLE users` or `COPY … TO PROGRAM …`.
- **Backup destinations are locked by default.** Without the lock, an
  agent couldn't redirect a dump to e.g. `/tmp/world-readable/` and
  exfiltrate the DB. The credential controls where dumps go; the agent
  controls only whether to run one.
- **TLS by credential, not by caller.** `sslmode` lives on the
  credential, not in params. Agents can't downgrade it.
- **Timeouts actually kill.** Both `psql` and `pg_dump` run under
  `kill_on_drop(true)` + `stdin(null)`, so an expired timeout sends
  SIGKILL to the local process. On `psql` disconnect, any in-flight
  transaction is rolled back server-side. Partial pg_dump files on
  timeout should be treated as garbage and deleted; the response carries
  `timed_out: bool` so callers can branch cleanly.

## MCP exposure

Both actions are exposed as MCP tools automatically:

| MCP tool name   | Action              |
|-----------------|---------------------|
| `postgres_run_sql` | `postgres.run_sql` |
| `postgres_backup`  | `postgres.backup`  |

Schemas include the params above plus `credential` and `api_key`.

## Common gotchas

### Backup succeeded but file is tiny

If the pg_dump file is only a few hundred bytes of SQL, you almost
certainly got "just the DDL / just the role" — check `stderr` in the
response for a role permission error. pg_dump silently continues past
many auth problems and returns 0. Run the same user manually to verify
they have `SELECT` on everything.

### "FATAL: no pg_hba.conf entry for host"

The Postgres server doesn't permit connections from your client IP.
This is not a Vultrino problem — fix `pg_hba.conf` on the server (add a
matching `host` line) and `SELECT pg_reload_conf()`.

### Client / server major version mismatch

`pg_dump` errors with `server version X.Y; pg_dump version W.Z` when
the client is older than the server. Install a client matching your
server's major version (e.g. `postgresql-client-16` for a 16.x server).

### `run_sql` returns 0 but "nothing happened"

By default the plugin passes `--single-transaction` and
`ON_ERROR_STOP=1`, so a failing statement will exit non-zero. But if
you explicitly set `run_sql.transaction=false`, a failing statement in
the middle of a batch can be skipped and you'll still get `exit_code:
0`. Leave transactions on unless you really mean to opt out.

### Raw SQL mode doesn't support `psql` client-side meta-commands with args

`\i /path/to/other.sql` works (it's handled client-side), but things
like `\copy TABLE FROM 'file.csv'` depend on the client's filesystem.
For file-based migrations, prefer `run_sql.file` with a path the
Vultrino-side user can read.

## Example: migration + nightly backup for a project

```bash
# 1. Store the credential once
vultrino add \
  --alias prod-db \
  --type postgres \
  --pg-host db.example.com \
  --pg-database app_production \
  --pg-user deploy \
  --pg-sslmode require

# 2. Configure per-credential defaults
vultrino meta set prod-db run_sql.file      /srv/app/migrations/apply.sql
vultrino meta set prod-db backup.output_dir /var/backups/postgres
vultrino meta set prod-db backup.filename_template "{alias}-{date}.sql"
vultrino meta set prod-db backup.format     custom

# 3. Apply migrations (agent- or cron-invokable)
vultrino action prod-db postgres.run_sql

# 4. Nightly backup (put this in cron / a scheduler)
vultrino action prod-db postgres.backup
```

Multiple targets? Just add more aliases — `staging-db`, `analytics-db`,
`prod-db-reader-only`. Same plugin, independent recipes.

A common pattern is to pair this plugin with the [SSH
plugin](./ssh.md): `postgres.backup` writes a dump locally, then
`ssh.deploy` rsyncs the backup directory off-site. Each credential
keeps its own blast radius and its own override-lock posture.
