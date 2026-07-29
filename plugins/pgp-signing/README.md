# Archived ABI v1 fixture

This directory is retained only as an incompatibility fixture for the former
WASM ABI v1. Do not install or deploy it.

ABI v1 serialized private credential material into an untrusted WASM guest.
Vultrino now requires ABI v2, whose request contains only a non-secret
credential handle. Installation and loading fail closed when this module
reports version 1.

PGP signing will remain unavailable as a WASM extension until Vultrino exposes
a narrow host-side signing capability that does not disclose the private key to
the guest. The built-in credential-aware plugins remain the supported trusted
execution boundary.
