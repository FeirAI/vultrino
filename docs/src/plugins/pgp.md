# PGP Signing Plugin (archived)

The repository's PGP module targets the former WASM ABI v1 and is not a
deployable plugin. ABI v1 serialized private credential material into guest
memory; Vultrino now rejects it during installation and loading.

WASM ABI v2 gives an untrusted guest only the selected credential's alias and
type. It has no generic credential-read operation and currently exposes no
host-side PGP signing capability. Consequently, PGP signing through an external
WASM plugin is unavailable.

The source and binary under `plugins/pgp-signing/` are retained only as a
negative compatibility fixture. Do not install them. A future PGP integration
must keep the private key in Vultrino and expose only narrow host operations such
as `sign` and `public_key`; restoring plaintext key transfer to WASM is not an
acceptable migration.
