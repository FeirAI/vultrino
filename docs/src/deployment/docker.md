# Docker Deployment

Run Vultrino in containers for easy deployment and isolation.

## Quick Start

```bash
docker run -d \
  --name vultrino \
  -p 7879:7879 \
  -e VULTRINO_PASSWORD=your-secure-password \
  -v vultrino-data:/data \
  ghcr.io/feirai/vultrino:latest web
```

## Dockerfile

```dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/vultrino /usr/local/bin/

# Create non-root user
RUN useradd -r -s /bin/false vultrino
USER vultrino

WORKDIR /data
VOLUME ["/data"]

EXPOSE 7879

ENTRYPOINT ["vultrino"]
CMD ["web"]
```

## Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  vultrino-web:
    image: ghcr.io/feirai/vultrino:latest
    command: web --bind 0.0.0.0:7879
    ports:
      - "7879:7879"
    environment:
      - VULTRINO_PASSWORD=${VULTRINO_PASSWORD}
    volumes:
      - vultrino-data:/data
      - ./config.toml:/etc/vultrino/config.toml:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7879/login"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  vultrino-data:
```

Create `.env`:

```bash
VULTRINO_PASSWORD=your-secure-password
```

Run:

```bash
docker-compose up -d
```

## With Traefik (Reverse Proxy)

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
  vultrino:local web
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `VULTRINO_PASSWORD` | Storage encryption password | Yes |
| `VULTRINO_CONFIG` | Path to config file | No |
| `RUST_LOG` | Log level | No |

## Volumes

| Path | Description |
|------|-------------|
| `/data` | Credential storage and state |
| `/etc/vultrino/config.toml` | Configuration file (optional) |

## Initializing in Docker

```bash
# Initialize (creates admin credentials)
docker run -it --rm \
  -v vultrino-data:/data \
  ghcr.io/feirai/vultrino:latest \
  init

# Add a credential
docker run -it --rm \
  -e VULTRINO_PASSWORD=your-password \
  -v vultrino-data:/data \
  ghcr.io/feirai/vultrino:latest \
  add --alias github-api --key ghp_xxx
```

## Health Checks

```bash
# Check the web UI
curl -f http://localhost:7879/login

# Check the JSON API (no auth required)
curl -f http://localhost:7879/api/v1/health
```
