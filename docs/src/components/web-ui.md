# Web UI

The Vultrino Web UI provides a browser-based interface for managing credentials, roles, and API keys.

## Overview

The web interface offers:
- Dashboard with usage statistics
- Credential management (add, view, delete)
- Role-based access control configuration
- API key generation and management
- An Audit Log page (a placeholder: it always shows an empty list)

## Starting the Web UI

```bash
export VULTRINO_PASSWORD="your-password"
vultrino web
# Web UI available at http://127.0.0.1:7879
```

Custom bind address:
```bash
vultrino web --bind 0.0.0.0:8080
```

## Authentication

The web UI requires authentication with the admin credentials set during `vultrino init`.

### Login

Navigate to `http://127.0.0.1:7879` and enter:
- **Username**: The admin username set during init
- **Password**: The admin password set during init

Sessions expire after 24 hours of inactivity.

### Changing Admin Password

Currently, to change the admin password:

1. Delete `admin.json` from the config directory (next to `config.toml`), e.g. on Linux:
   ```bash
   rm ~/.config/vultrino/admin.json
   ```

2. Reinitialize (`--force` is needed because `config.toml` exists; it also rewrites
   `config.toml` with the defaults, so back it up first and restore your settings after):
   ```bash
   vultrino init --force
   ```

For headless deployments, instead set `VULTRINO_ADMIN_USERNAME` and
`VULTRINO_ADMIN_PASSWORD_FILE` (or `VULTRINO_ADMIN_PASSWORD_HASH_FILE`); they are used
only when no `admin.json` exists.

## Pages

### Dashboard

The main dashboard displays:
- Total credentials stored
- Number of roles configured
- Active API keys
- A recent-requests count, currently always 0 (usage history is not shown in the UI)

### Credentials

**List View** (`/credentials`)
- Shows all stored credentials
- Displays alias, type, and creation date
- Credentials are never shown in the UI

**Add Credential** (`/credentials/new`)
- Form to add new credentials
- Supported types: API Key, Basic Auth
- Optional description field

**Delete Credential**
- Click delete button on credential row
- Confirmation required

### Roles

**List View** (`/roles`)
- Shows all configured roles
- Displays permissions and credential scopes

**Create Role** (`/roles/new`)
- Name and description
- Permission checkboxes:
  - Read — List credentials
  - Write — Create credentials
  - Update — Modify credentials
  - Delete — Remove credentials
  - Execute — Use credentials for requests
- Credential scopes (glob patterns)

### API Keys

**List View** (`/keys`)
- Shows all API keys (prefix only)
- Displays assigned role and expiration
- Shows last used timestamp

**Create Key** (`/keys/new`)
- Key name for identification
- Role selection dropdown
- Optional expiration date

**Revoke Key**
- Click revoke button on key row
- Immediate revocation, no confirmation

### Audit Log

**View** (`/audit`)
- Placeholder page: it always renders an empty list
- For usage and admin-change history use the event outbox (`GET /api/v1/events`) and the server logs

## Configuration

### Session Settings

There is no `[web]` section. Sessions expire after 24 hours of inactivity, which is not
configurable. The session cookie is always HttpOnly and SameSite=Strict; it is marked
Secure, and HSTS is sent, only when `[server] mode = "server"` (which assumes a
TLS-terminating reverse proxy in front).

### Binding

For production, bind to localhost and use a reverse proxy. The address is set on the
command line (default `127.0.0.1:7879`):

```bash
vultrino web --bind 127.0.0.1:7879
```

## Security Considerations

### HTTPS

The web UI should always be accessed over HTTPS in production. Use a reverse proxy like nginx or Caddy for TLS termination.

### Session Security

- Sessions are stored server-side
- Session IDs are cryptographically random
- Cookies are HTTP-only and secure (when behind HTTPS)

### CSRF Protection

Forms include CSRF tokens to prevent cross-site request forgery.

### Rate Limiting

Login attempts are rate-limited to prevent brute force attacks.

## Screenshots

### Login Page
```
┌─────────────────────────────────────────┐
│           Vultrino                      │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │ Username                        │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │ Password                        │    │
│  └─────────────────────────────────┘    │
│                                         │
│  [ Sign in ]                            │
│                                         │
└─────────────────────────────────────────┘
```

### Dashboard
```
┌─────────────────────────────────────────────────────────────┐
│  Vultrino    Credentials  Roles  API Keys  Audit   [Logout] │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │    5    │  │    3    │  │    2    │  │   127   │        │
│  │ Creds   │  │ Roles   │  │ Keys    │  │ Requests│        │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │
│                                                             │
│  Recent Activity                                            │
│  ───────────────────────────────────────────────────        │
│  10:30  github-api     GET /user                           │
│  10:28  stripe-api     POST /v1/charges                    │
│  10:25  github-api     GET /repos                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Credentials List
```
┌─────────────────────────────────────────────────────────────┐
│  Credentials                              [ + New Credential]│
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Alias          Type        Created         Actions         │
│  ─────────────────────────────────────────────────────      │
│  github-api     api_key     Jan 15, 2024    [Delete]        │
│  stripe-api     api_key     Jan 16, 2024    [Delete]        │
│  jira-api       basic_auth  Jan 17, 2024    [Delete]        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### "Invalid credentials" error

- Verify username and password match those set during `vultrino init`
- Check that `admin.json` exists in the config directory (next to `config.toml`), or that the `VULTRINO_ADMIN_*` variables are set

### Session expires immediately

- Ensure cookies are enabled in your browser
- The session cookie is marked Secure only when `[server] mode = "server"`; in that mode, reach the UI over HTTPS through the reverse proxy

### Cannot access from external machine

- By default, the web UI binds to localhost only
- Use a reverse proxy to expose it securely
- Never bind directly to 0.0.0.0 in production without TLS

### Blank page or errors

- Check browser console for JavaScript errors
- Verify the server is running: `curl http://127.0.0.1:7879/login`
- Check server logs for errors
