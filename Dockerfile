# vultrino — enforce plane (the in-path PEP, the crown-jewel image).
# Holds every provider secret + the vault password in memory at runtime → runs on a DEDICATED,
# tainted, node-isolated pool (see muntin/deploy/k8s). reqwest uses rustls-tls (no OpenSSL), so a
# fully-static musl build → distroless/static is viable as a size optimization; this default uses
# the robust glibc build → distroless/cc (ships glibc + libgcc + CA certs for HTTPS egress).
#
# RUNTIME (set by the k8s StatefulSet, not the image):
#   - the encrypted vault (credentials.enc) is a RWO PersistentVolume mount; rootfs is read-only
#     except that mount. Point vultrino's storage at the mount via config.toml / env.
#   - VULTRINO_PASSWORD_FILE is a CSI-mounted secret FILE (never an env literal, never a layer).
# Base tags float here; CI resolves+pins by @sha256 before push (muntin/deploy/k8s/ci).
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
