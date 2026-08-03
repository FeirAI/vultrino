# Vultrino — credential proxy (in-path PEP).
# reqwest uses rustls-tls (no OpenSSL). Default image: glibc build → distroless/cc
# (glibc + libgcc + CA certs for HTTPS egress). A static musl → distroless/static
# build is a viable size optimization later.
#
# Runtime expectations (set by the orchestrator, not baked into the image):
#   - Mount encrypted vault storage (e.g. credentials.enc) read/write; keep rootfs RO otherwise.
#   - Prefer VULTRINO_PASSWORD_FILE (secret file mount) over an env-literal password.
# syntax=docker/dockerfile:1

ARG RUST_VERSION=1
FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
# Cargo caches speed rebuilds; the binary is copied OUT of the target cache-mount within the RUN
# (cache mounts are not persisted into the image layer). --locked pins to Cargo.lock.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin vultrino && \
    mkdir -p /out && cp /src/target/release/vultrino /out/vultrino

# Distroless cc + nonroot (uid 65532): glibc + libgcc + CA bundle, no shell/pkg-manager.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/vultrino /usr/local/bin/vultrino
USER 65532:65532
EXPOSE 7879
# K8s drives the HTTP /api/v1/health probe (NOT /healthz). web serves the in-path PEP on 7879.
ENTRYPOINT ["/usr/local/bin/vultrino"]
CMD ["web", "--bind", "0.0.0.0:7879"]
