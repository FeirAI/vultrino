# VPS / Server Deployment

Deploy Vultrino on a VPS or dedicated server for team access and production use.

## Prerequisites

- Linux server (Ubuntu 22.04+ recommended)
- Domain name (optional but recommended)
- TLS certificate (Let's Encrypt)

## Installation

```bash
# Download latest release
curl -L https://github.com/feir-ai/vultrino/releases/latest/download/vultrino-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/

# Create vultrino user
sudo useradd -r -s /bin/false vultrino

# Create directories
sudo mkdir -p /etc/vultrino /var/lib/vultrino
sudo chown vultrino:vultrino /var/lib/vultrino
```

## Configuration

Create `/etc/vultrino/config.toml`:

```toml
[server]
# `mode = "server"` enables the stricter server posture. `vultrino web` binds
# 127.0.0.1:7879 by default (the systemd unit below sets it explicitly with --bind).
mode = "server"

[storage]
backend = "file"

[storage.file]
path = "/var/lib/vultrino/credentials.enc"

[logging]
level = "info"
audit_file = "/var/log/vultrino/audit.log"

[mcp]
enabled = true
transport = "stdio"
```

## Systemd Services

### Web UI Service

Create `/etc/systemd/system/vultrino-web.service`:

```ini
[Unit]
Description=Vultrino Web UI
After=network.target

[Service]
Type=simple
User=vultrino
Group=vultrino
Environment="VULTRINO_PASSWORD=your-secure-password"
Environment="VULTRINO_CONFIG=/etc/vultrino/config.toml"
ExecStart=/usr/local/bin/vultrino web --bind 127.0.0.1:7879
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/vultrino
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

The single `vultrino web` process serves the HTTP JSON API (`/api/v1/…`), the
connector routes (`/mcp`, `/llm`), and the admin UI — there is no separate proxy
service. (`vultrino serve` no longer starts an API server.)

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vultrino-web
sudo systemctl start vultrino-web
```

## Reverse Proxy Setup

### Nginx

Install nginx and certbot:

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

Create `/etc/nginx/sites-available/vultrino`:

```nginx
server {
    listen 80;
    server_name vultrino.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vultrino.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/vultrino.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vultrino.yourdomain.com/privkey.pem;

    # Web UI + JSON API (both served by vultrino web on 7879)
    location / {
        proxy_pass http://127.0.0.1:7879;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and get certificate:

```bash
sudo ln -s /etc/nginx/sites-available/vultrino /etc/nginx/sites-enabled/
sudo certbot --nginx -d vultrino.yourdomain.com
sudo systemctl reload nginx
```

### Caddy (Alternative)

Create `/etc/caddy/Caddyfile`:

```
vultrino.yourdomain.com {
    reverse_proxy 127.0.0.1:7879
}
```

## Firewall Configuration

```bash
# Allow only HTTPS
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp  # SSH
sudo ufw enable
```

## Initialize Credentials

```bash
# Set password
export VULTRINO_PASSWORD="your-secure-password"

# Initialize (as vultrino user)
sudo -u vultrino VULTRINO_PASSWORD="$VULTRINO_PASSWORD" vultrino init

# Add credentials
sudo -u vultrino VULTRINO_PASSWORD="$VULTRINO_PASSWORD" vultrino add --alias github-api --key ghp_xxx
```

## Security Checklist

- [ ] Strong storage password (32+ characters)
- [ ] Strong admin password
- [ ] TLS enabled (HTTPS only)
- [ ] Firewall configured
- [ ] Audit logging enabled
- [ ] Regular backups of `/var/lib/vultrino/`
- [ ] API keys have expiration dates
- [ ] Roles use principle of least privilege

## Monitoring

### Check service status
```bash
sudo systemctl status vultrino-web
```

### View logs
```bash
sudo journalctl -u vultrino-web -f
sudo tail -f /var/log/vultrino/audit.log
```

### Health check
```bash
curl -s http://127.0.0.1:7879/login | head -1
```

## Backup & Restore

### Backup
```bash
sudo tar -czf vultrino-backup-$(date +%Y%m%d).tar.gz \
    /etc/vultrino \
    /var/lib/vultrino
```

### Restore
```bash
sudo tar -xzf vultrino-backup-YYYYMMDD.tar.gz -C /
sudo systemctl restart vultrino-web
```
