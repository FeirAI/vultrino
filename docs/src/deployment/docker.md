# Docker Deployment

Run Vultrino in containers for easy deployment and isolation.

## Quick Start

```bash
docker run -d \
  --name vultrino \
  -p 127.0.0.1:7879:7879 \
  -e VULTRINO_PASSWORD=your-secure-password \
  -e VULTRINO_POLICY_HASH_SECRET=a-stable-random-secret \
  -e VULTRINO_ADMIN_USERNAME=admin \
  -e VULTRINO_ADMIN_PASSWORD=your-admin-password \
  -v vultrino-data:/data \
  -v "$PWD/config.toml:/etc/vultrino/config.toml:ro" \
  ghcr.io/feirai/vultrino:latest \
  --config /etc/vultrino/config.toml web --bind 0.0.0.0:7879
```

`vultrino web` refuses to start without `VULTRINO_POLICY_HASH_SECRET` (keep it the
same across restarts) and without an admin login (`admin.json`, or
`VULTRINO_ADMIN_USERNAME` plus `VULTRINO_ADMIN_PASSWORD`, or their `_FILE` /
`VULTRINO_ADMIN_PASSWORD_HASH` variants). The image declares no volume: the vault is
written to `/data` only if the config passed with `--config` sets
`[storage.file] path = "/data/credentials.enc"`. Otherwise it is written under the
container user's home directory and is lost with the container. The mounted
directory must be writable by uid 65532.

Vultrino has no built-in TLS and serves plain HTTP. Publish the port only on a
trusted network or behind a TLS-terminating reverse proxy, and in that case set
`[server] mode = "server"` (Secure session cookie and HSTS). Behind a proxy that
sets `X-Forwarded-For`, also set `VULTRINO_TRUST_FORWARDED_FOR=1`, or all clients
share one login lockout bucket.

## Dockerfile

Use the `Dockerfile` in the repository rather than writing your own. It is a
multi-stage build: `cargo build --release --locked --bin vultrino` on a Rust bookworm
image (the toolchain is pinned by `rust-toolchain.toml`), then a
`gcr.io/distroless/cc-debian12:nonroot` runtime that runs as uid 65532. The runtime
image has no shell, package manager or `curl`, declares no volume, and its default
command is `web --bind 0.0.0.0:7879`.

## Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  vultrino-web:
    image: ghcr.io/feirai/vultrino:latest
    command: --config /etc/vultrino/config.toml web --bind 0.0.0.0:7879
    ports:
      - "127.0.0.1:7879:7879"
    environment:
      - VULTRINO_PASSWORD=${VULTRINO_PASSWORD}
      - VULTRINO_POLICY_HASH_SECRET=${VULTRINO_POLICY_HASH_SECRET}
      - VULTRINO_ADMIN_USERNAME=${VULTRINO_ADMIN_USERNAME}
      - VULTRINO_ADMIN_PASSWORD=${VULTRINO_ADMIN_PASSWORD}
    volumes:
      - vultrino-data:/data
      - ./config.toml:/etc/vultrino/config.toml:ro
    restart: unless-stopped
    # No container healthcheck: the image has no shell or curl. Probe
    # GET /api/v1/health from the host or the orchestrator instead.

volumes:
  vultrino-data:
```

Create `.env`:

```bash
VULTRINO_PASSWORD=your-secure-password
VULTRINO_POLICY_HASH_SECRET=a-stable-random-secret
VULTRINO_ADMIN_USERNAME=admin
VULTRINO_ADMIN_PASSWORD=your-admin-password
```

Run:

```bash
docker-compose up -d
```

## With Traefik (Reverse Proxy)

The Traefik and Kubernetes examples below are abbreviated: like the Quick Start, they
also need `VULTRINO_POLICY_HASH_SECRET`, an admin login (`VULTRINO_ADMIN_USERNAME` plus
`VULTRINO_ADMIN_PASSWORD_FILE`) and a config passed with `--config` whose
`[storage.file] path` points into the mounted volume. Without them `vultrino web`
refuses to start, or keeps its vault outside the volume. Behind the proxy, set
`[server] mode = "server"` and `VULTRINO_TRUST_FORWARDED_FOR=1`.

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=you@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  vultrino:
    image: ghcr.io/feirai/vultrino:latest
    command: web --bind 0.0.0.0:7879
    environment:
      - VULTRINO_PASSWORD=${VULTRINO_PASSWORD}
    volumes:
      - vultrino-data:/data
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.vultrino.rule=Host(`vultrino.yourdomain.com`)"
      - "traefik.http.routers.vultrino.entrypoints=websecure"
      - "traefik.http.routers.vultrino.tls.certresolver=letsencrypt"
      - "traefik.http.services.vultrino.loadbalancer.server.port=7879"

volumes:
  vultrino-data:
  letsencrypt:
```

## Kubernetes

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vultrino
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vultrino
  template:
    metadata:
      labels:
        app: vultrino
    spec:
      containers:
        - name: vultrino-web
          image: ghcr.io/feirai/vultrino:latest
          args: ["web", "--bind", "0.0.0.0:7879"]
          ports:
            - containerPort: 7879
          env:
            - name: VULTRINO_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: vultrino-secrets
                  key: password
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: vultrino-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: vultrino
spec:
  selector:
    app: vultrino
  ports:
    - port: 80
      targetPort: 7879
---
apiVersion: v1
kind: Secret
metadata:
  name: vultrino-secrets
type: Opaque
stringData:
  password: your-secure-password
```

## Building the Image

```bash
# Clone repository
git clone https://github.com/FeirAI/vultrino.git
cd vultrino

# Build image
docker build -t vultrino:local .

# Run
docker run -d \
  --name vultrino \
  -p 7879:7879 \
  -e VULTRINO_PASSWORD=test \
  -v vultrino-data:/data \
  vultrino:local
```

Add the other required variables from [Environment Variables](#environment-variables);
the image's default command is `web --bind 0.0.0.0:7879` (`vultrino:local web` on its
own would listen on 127.0.0.1 inside the container, which the published port cannot
reach).

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `VULTRINO_PASSWORD` | Storage encryption password (or `VULTRINO_PASSWORD_FILE`) | Yes |
| `VULTRINO_POLICY_HASH_SECRET` | Stable random secret; `vultrino web` refuses to start without it | Yes |
| `VULTRINO_ADMIN_USERNAME` + `VULTRINO_ADMIN_PASSWORD` | Web UI admin login when no `admin.json` exists (`_FILE` and `VULTRINO_ADMIN_PASSWORD_HASH` variants accepted) | Yes, unless `admin.json` exists |
| `VULTRINO_TRUST_FORWARDED_FOR` | Set to `1` only behind a trusted proxy that sets `X-Forwarded-For` | No |
| `RUST_LOG` | Log level | No |

There is no `VULTRINO_CONFIG` variable: pass `--config <path>` before the subcommand
(for example `--config /etc/vultrino/config.toml web --bind 0.0.0.0:7879`).

## Volumes

| Path | Description |
|------|-------------|
| `/data` | Credential storage, only when the config passed with `--config` sets `[storage.file] path` under `/data`; must be writable by uid 65532 |
| `/etc/vultrino/config.toml` | Configuration file, read only when passed with `--config` |

## Initializing in Docker

```bash
# `vultrino init` writes config.toml and admin.json to the container user's
# config directory (it ignores --config), so in a throwaway container they are
# lost. Set VULTRINO_ADMIN_USERNAME and VULTRINO_ADMIN_PASSWORD_FILE on the web
# container instead (see Environment Variables).

# Add a credential (pass the same config so the vault lands in /data)
docker run -it --rm \
  -e VULTRINO_PASSWORD=your-password \
  -v vultrino-data:/data \
  -v "$PWD/config.toml:/etc/vultrino/config.toml:ro" \
  ghcr.io/feirai/vultrino:latest \
  --config /etc/vultrino/config.toml add --alias github-api --key ghp_xxx
```

## Health Checks

```bash
# Check the web UI
curl -f http://localhost:7879/login

# Check the JSON API (no auth required)
curl -f http://localhost:7879/api/v1/health
```
