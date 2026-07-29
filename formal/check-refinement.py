#!/usr/bin/env python3
"""Structural Rust↔Lean refinement gate for Vultrino's critical seams.

This is intentionally narrow. It does not claim semantic equivalence of Tokio;
it prevents the implementation objects and choke points the proof depends on
from silently drifting away from the checked model.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"refinement check: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def block(text: str, start: str) -> str:
    match = re.search(start + r"\s+where\n(?P<body>(?:  .+\n)+)", text)
    if not match:
        fail(f"could not locate {start!r}")
    return match.group("body")


lean = (ROOT / "formal/lean/Vultrino/Types.lean").read_text()
rust = (ROOT / "src/formal_kernel.rs").read_text()
server = (ROOT / "src/server/mod.rs").read_text()
wasm = (ROOT / "src/plugins/wasm/runtime.rs").read_text()
lib = (ROOT / "src/lib.rs").read_text()
storage = (ROOT / "src/storage/file.rs").read_text()
approval = (ROOT / "src/approval/mod.rs").read_text()
installer = (ROOT / "src/plugins/installer.rs").read_text()
main = (ROOT / "src/main.rs").read_text()
kani_runner = (ROOT / "formal/run-kani.sh").read_text()

if not lib.startswith("#![forbid(unsafe_code)]") or not main.startswith("#![forbid(unsafe_code)]"):
    fail("the library and production CLI must both forbid unsafe Rust")

lean_fields = re.findall(r"^  ([a-zA-Z][a-zA-Z0-9]*)\s+:", block(lean, r"structure RequestBinding"), re.M)
rust_match = re.search(r"pub struct ExecutionBinding \{(?P<body>.*?)\n\}", rust, re.S)
if not rust_match:
    fail("Rust ExecutionBinding missing")
rust_fields = re.findall(r"^    pub ([a-z_]+):", rust_match.group("body"), re.M)
expected_lean = [
    "approvalId", "epoch", "tenant", "principal", "credential", "action",
    "paramsDigest", "ruleDigest",
]
expected_rust = [
    "approval_id", "epoch", "tenant", "principal", "credential", "action",
    "params_digest", "rule_digest",
]
if lean_fields != expected_lean:
    fail(f"Lean RequestBinding fields drifted: {lean_fields!r}")
if rust_fields != expected_rust:
    fail(f"Rust ExecutionBinding fields drifted: {rust_fields!r}")

if "credential_handle: WasmCredentialHandle" not in wasm:
    fail("WASM request no longer carries the non-secret credential handle")
if re.search(r"WasmRequest\s*\{[^}]*\bcredential\s*:", wasm, re.S):
    fail("WASM request regained a plaintext-capable credential field")
if "request.credential.data" in wasm or "to_value(&request.credential" in wasm:
    fail("WASM adapter serializes CredentialData")

if "#[serde(skip)]\n    pub(crate) updated_credential" not in lib:
    fail("public ExecuteResponse can serialize or expose credential refresh material")
if "plaintext Secret serialization is restricted to the encrypted vault codec" not in lib:
    fail("Secret serialization is no longer guarded by the private vault capability")
if not re.search(r"HmacApiKey\s*\{.*?api_key:\s*Secret,.*?api_secret:\s*Secret,", lib, re.S):
    fail("both halves of the HMAC credential must remain private Secret values")

buffered = len(re.findall(r"\.execute\(plugin_request\)", server))
streaming = len(re.findall(r"\.execute_streaming\(plugin_request\)", server))
if (buffered, streaming) != (1, 1):
    fail(f"plugin dispatch seam count changed: buffered={buffered}, streaming={streaming}")
for signature in (
    "authorized: crate::formal_kernel::Authorized<ActionPayload>",
    "let ActionPayload {",
):
    if server.count(signature) < 2:
        fail(f"both dispatch variants are not permit-bound: missing {signature!r}")

if "wrapping_add(1)" in storage and "execution_epoch" in storage:
    fail("approval execution epoch may wrap")
if "grant_witness_for_epoch(epoch)" not in storage:
    fail("durable claim no longer derives an epoch-bound grant under the lock")
if "confine_response(" not in server:
    fail("buffered low sink no longer requires PublicResponse confinement")
if "has_unredactable_secret(" not in server:
    fail("streaming path no longer falls back to whole-response confinement for short secrets")

if server.count("confine_plugin_execution_error(error, &secret_material)") != 2:
    fail("both post-dispatch error paths must classify connector diagnostics")
if "diagnostic_may_contain_secret(&error.to_string(), secrets)" not in server:
    fail("connector diagnostics no longer use the finite secret-form classifier")
if "RunError::committed(e.into())" in server:
    fail("connector-provided diagnostics can reach a public or persisted error sink")

if "approval.validate_vault_shape()" not in storage:
    fail("decrypted approval records no longer pass the invariant validator")
if "self.approval_rule.is_some() || self.effective_required_approvals() > 1" not in approval:
    fail("multi-principal controller separation no longer covers every recipe")

abi_validation = installer.find("WasmPlugin::from_directory(staging_path.clone())")
plugin_copy = installer.find("self.copy_plugin(&staging_path, &target_dir)")
if abi_validation < 0 or plugin_copy < 0 or abi_validation > plugin_copy:
    fail("WASM ABI validation must happen before installation copies the module")

required_kani_harnesses = (
    "direct_permit_truth_table_is_exact",
    "execution_epoch_never_wraps",
    "zero_approvers_never_satisfy",
    "satisfaction_never_underfills_a_slot",
    "greedy_matches_exhaustive_assignment_at_bound_5",
    "satisfaction_is_monotone_in_availability",
    "malformed_recipes_never_satisfy",
    "recipe_cap_prevents_need_overflow",
    "class_slot_contribution_agrees_with_satisfaction",
)
missing_harnesses = [name for name in required_kani_harnesses if name not in kani_runner]
if missing_harnesses:
    fail(f"Kani runner dropped required harnesses: {missing_harnesses!r}")

print("refinement check: PASS (8 binding fields; 2 permit-bound dispatch variants; 9 Kani harnesses; WASM/egress/error/vault sinks confined)")
