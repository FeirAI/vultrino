#!/usr/bin/env python3
"""Structural Rust↔Lean refinement gate for Vultrino's critical seams.

This is intentionally narrow. It does not claim semantic equivalence of Tokio;
it prevents the implementation objects and choke points the proof depends on
from silently drifting away from the checked model.
"""

from pathlib import Path
import hashlib
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
policy = (ROOT / "src/policy/mod.rs").read_text()
api = (ROOT / "src/web/api.rs").read_text()
tenant_assert = (ROOT / "src/govder/tenant_assert.rs").read_text()
authority_lean = (ROOT / "formal/lean/Vultrino/Approval/Authority.lean").read_text()
approval_model_lean = (ROOT / "formal/lean/Vultrino/Approval/Model.lean").read_text()
action_authority_lean = (ROOT / "formal/lean/Vultrino/Approval/ActionAuthority.lean").read_text()
criticality_lean = (ROOT / "formal/lean/Vultrino/Approval/Criticality.lean").read_text()
method_authority_lean = (ROOT / "formal/lean/Vultrino/Action/MethodAuthority.lean").read_text()
confinement_lean = (ROOT / "formal/lean/Vultrino/Credentials/Confinement.lean").read_text()
startup_lean = (ROOT / "formal/lean/Vultrino/Configuration/Startup.lean").read_text()
config = (ROOT / "src/config/mod.rs").read_text()
config_types = (ROOT / "src/config/types.rs").read_text()
capability = (ROOT / "src/capability/mod.rs").read_text()
internal_http_capability_tests = (ROOT / "tests/capability_internal_http_toolcall.rs").read_text()
workload_exchange = (ROOT / "src/web/workload_exchange.rs").read_text()
web_mod = (ROOT / "src/web/mod.rs").read_text()
web_server = (ROOT / "src/web/server.rs").read_text()
startup_security_tests = (ROOT / "tests/startup_security_integration.rs").read_text()
approval_integration_tests = (ROOT / "tests/approval_token_integration.rs").read_text()
web_smoke_tests = (ROOT / "tests/web_smoke.rs").read_text()

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
for hook in (
    "resp.body.clear();",
    "pub fn confine_stream_headers(",
    "released_tail: Zeroizing<Vec<u8>>",
    "self.admit_output(out)",
    "fn admit_output(&mut self",
    "pub fn terminate_with(&mut self",
):
    if hook not in server and hook not in (ROOT / "src/egress.rs").read_text():
        fail(f"final egress postcondition hook missing: {hook!r}")
if "crate::egress::confine_stream_headers(&mut headers, &forms)" not in server:
    fail("streamed headers no longer pass the final declared-form postcondition")
if server.count("scrubber.terminate_with(SSE_ERROR_FRAME)") < 4:
    fail("stream terminal frames no longer pass the compositional output gate")
for theorem in (
    "retained_tail_covers_every_possible_crossing_start",
    "suffix_gate_preserves_stream_confinement",
    "admitted_chunk_extends_stream_safely",
    "unsafe_chunk_is_rejected",
    "reachable_public_stream_excludes_every_declared_form",
):
    if f"theorem {theorem}" not in confinement_lean:
        fail(f"Lean stream-confinement theorem missing: {theorem}")
for test in (
    "confined_response_fallback_cannot_repeat_a_secret_from_its_own_diagnostic",
    "stream_scrubber_rejects_a_marker_that_reconstructs_the_secret",
    "stream_terminal_frame_is_withheld_when_it_contains_a_secret",
    "streamed_headers_are_cleared_when_the_marker_contains_a_secret",
):
    if f"fn {test}" not in (ROOT / "src/egress.rs").read_text():
        fail(f"egress postcondition regression test missing: {test}")

startup_validation = main.find(
    "let security_startup = vultrino::web::validate_security_startup(config)?"
)
strict_web_assignment = main.find(
    "config.enforcement.require_declared_capabilities = true;"
)
vault_access = main.find("let admin_auth = load_admin_auth(config).await?", startup_validation)
if min(strict_web_assignment, startup_validation, vault_access) < 0 or not (
    strict_web_assignment < startup_validation < vault_access
):
    fail("web strictness and security validation must precede vault/admin-auth access")
if "if !config.enforcement.require_declared_capabilities" not in web_mod:
    fail("validated production web startup no longer requires strict capability declarations")
if "pub require_declared_capabilities: bool" not in config:
    fail("runtime enforcement config lost the strict catalog posture")
if "require_declared_capabilities: raw.require_declared_capabilities" not in config_types:
    fail("parsed strict catalog posture no longer reaches runtime configuration")
if "WebServer::new_with_security_startup(" not in main or "security_startup," not in main:
    fail("production web server no longer consumes the validated security snapshot")
for ownership_hook in (
    "vultrino_config: crate::config::Config",
    "pub fn config(&self) -> &crate::config::Config",
    "(self.vultrino_config, self.workload_verifier)",
):
    if ownership_hook not in web_mod:
        fail(f"opaque startup witness no longer owns exact validated inputs: {ownership_hook!r}")
for hook in (
    "pub(crate) enum WorkloadVerifier",
    "Configured(Arc<Vec<Zeroizing<Vec<u8>>>>)",
    "pub(crate) fn from_env()",
    "pub(crate) fn startup_result(&self)",
):
    if hook not in workload_exchange:
        fail(f"startup-snapshotted workload verifier hook missing: {hook!r}")
if "workload_verifier: super::workload_exchange::WorkloadVerifier" not in web_server:
    fail("web AppState no longer stores the workload verifier snapshot")
if "security_startup.into_parts()" not in web_server:
    fail("validated config and workload verifier are not consumed together")
validated_constructor_start = web_server.find("pub fn new_with_security_startup(")
validated_constructor_end = web_server.find(
    "fn new_with_workload_verifier(", validated_constructor_start
)
if validated_constructor_start < 0 or validated_constructor_end < 0:
    fail("could not isolate validated production web constructor")
if "WorkloadVerifier::from_env()" in web_server[
    validated_constructor_start:validated_constructor_end
]:
    fail("validated production constructor rereads workload verifier authority")
exchange_start = workload_exchange.find("pub async fn exchange_workload_token(")
exchange_end = workload_exchange.find("pub async fn runtime_control(", exchange_start)
if exchange_start < 0 or exchange_end < 0:
    fail("could not isolate workload exchange handler")
if "std::env::" in workload_exchange[exchange_start:exchange_end]:
    fail("workload exchange handler rereads process environment per request")
for theorem in (
    "web_start_implies_strict_catalog",
    "web_start_implies_policy_hash_configured",
    "enabled_exchange_start_implies_valid_verifier",
    "invalid_security_config_refuses_before_listen",
):
    if f"theorem {theorem}" not in startup_lean:
        fail(f"Lean startup-security theorem missing: {theorem}")
for test in (
    "web_refuses_to_start_without_policy_hash_secret",
    "enabled_exchange_refuses_to_start_without_valid_verifier",
):
    if f"fn {test}" not in startup_security_tests:
        fail(f"production startup negative control missing: {test}")
if "async fn verifier_is_snapshotted_before_requests" not in (
    ROOT / "tests/workload_exchange_integration.rs"
).read_text():
    fail("workload verifier snapshot regression test missing")

for hook in (
    "enum IrreversibilityResolution",
    "AmbiguousCanonical",
    "fn automatically_requires_approval(self) -> bool",
    "Self::HumanFloor | Self::AmbiguousCanonical",
    "async fn resolve_irreversibility_for_action(",
    'return IrreversibilityResolution::Unavailable;',
):
    if hook not in server:
        fail(f"criticality-to-approval refinement hook missing: {hook!r}")
if '!matches!(reversibility.trim(), "reversible")' not in approval:
    fail("unknown stored reversibility no longer fails to the human floor")
if "fn reversibility_wire_values_fail_closed_to_human_floor" not in approval:
    fail("reversibility parser no longer has unknown/blank fail-closed controls")
criticality_snapshot = server.find("let irreversibility = self")
unavailable_refusal = server.find(
    "matches!(irreversibility, IrreversibilityResolution::Unavailable)",
    criticality_snapshot,
)
strict_undeclared_refusal = server.find(
    "self.config.enforcement.require_declared_capabilities",
    unavailable_refusal,
)
criticality_force = server.find(
    "if irreversibility.automatically_requires_approval()", strict_undeclared_refusal
)
approval_branch = server.find("if needs_approval {", criticality_force)
if min(
    criticality_snapshot,
    unavailable_refusal,
    strict_undeclared_refusal,
    criticality_force,
    approval_branch,
) < 0 or not (
    criticality_snapshot
    < unavailable_refusal
    < strict_undeclared_refusal
    < criticality_force
    < approval_branch
):
    fail("trusted criticality snapshot must refuse or force approval before the shared branch")
if "let trusted_irreversible = irreversibility.trusted_human_floor();" not in server:
    fail("approval stamp no longer consumes the same criticality snapshot that forced gating")
if "async fn resolve_irreversibility_for_action(\n        &self,\n        credential_alias: &str," not in server:
    fail("criticality lookup is no longer bound to the executing credential")
if "cap.credential_ref.trim() == credential_alias.trim()" not in server:
    fail("strict catalog lookup can borrow a declaration from another credential")
if "approval.bind_capability_authority(" not in server:
    fail("approval-open no longer freezes its catalog authority class")
if "capability_authority: Option<CapabilityAuthorityClass>" not in approval:
    fail("persisted approvals lost the private catalog authority snapshot")
resume = server.find("async fn resume_approved(")
resume_catalog = server.find("let current_capability_authority = self", resume)
resume_policy = server.find("evaluate_readonly_full", resume_catalog)
resume_permit = server.find("ExecutionPermit::approved", resume_policy)
if min(resume, resume_catalog, resume_policy, resume_permit) < 0 or not (
    resume < resume_catalog < resume_policy < resume_permit
):
    fail("approval resume must revalidate catalog authority before policy and permit issuance")
label_lookup = server.find("async fn resolve_irreversibility_for_action(")
label_miss = server.find("return IrreversibilityResolution::Undeclared;", label_lookup)
canonical_ambiguity = server.find(
    "return IrreversibilityResolution::AmbiguousCanonical;", label_miss
)
canonical_collection = server.find("let canonical: Vec<_>", canonical_ambiguity)
if min(label_lookup, label_miss, canonical_ambiguity, canonical_collection) < 0 or not (
    label_lookup < label_miss < canonical_ambiguity < canonical_collection
):
    fail("exact-label miss or shared canonical ambiguity can borrow a sibling declaration")
preview_lookup = server.find("async fn approval_preview_for_action(")
preview_label = server.find("if let Some(label)", preview_lookup)
preview_exact_only = server.find("let cap = exact.next()?;", preview_label)
preview_canonical_guard = server.find(
    "if self.config.canonical_action_has_labels(canonical_action)", preview_exact_only
)
preview_canonical = server.find("let mut canonical = caps", preview_canonical_guard)
if min(
    preview_lookup,
    preview_label,
    preview_exact_only,
    preview_canonical_guard,
    preview_canonical,
) < 0 or not (
    preview_lookup
    < preview_label
    < preview_exact_only
    < preview_canonical_guard
    < preview_canonical
):
    fail("approval preview no longer preserves the exact-label/ambiguity boundary")
for theorem in (
    "declared_human_floor_never_direct",
    "unavailable_catalog_never_direct",
    "ambiguous_canonical_never_direct",
    "strict_catalog_undeclared_never_direct",
    "direct_excludes_human_floor_and_unavailable",
    "strict_catalog_direct_implies_reversible",
    "changed_catalog_authority_refuses_resume",
    "approval_resume_implies_same_catalog_authority",
    "unavailable_catalog_refuses_approval_resume",
):
    if f"theorem {theorem}" not in criticality_lean:
        fail(f"Lean criticality-gating theorem missing: {theorem}")
for test in (
    "declared_irreversible_capability_cannot_take_the_direct_path",
    "disabled_approvals_refuse_declared_irreversible_capability",
    "strict_catalog_refuses_undeclared_action_before_dispatch",
    "strict_catalog_refuses_label_that_only_matches_a_canonical_sibling",
    "strict_catalog_refuses_declaration_for_different_credential",
    "approval_resume_refuses_changed_capability_authority",
    "shared_canonical_alias_cannot_take_the_direct_path",
    "exact_labels_and_previews_never_borrow_canonical_siblings",
):
    test_source = approval_integration_tests if test != (
        "exact_labels_and_previews_never_borrow_canonical_siblings"
    ) else server
    if f"async fn {test}" not in test_source:
        fail(f"criticality direct-path negative control missing: {test}")
money_helper_start = web_smoke_tests.find("async fn execute_labelled_money_action(")
money_helper_end = web_smoke_tests.find(
    "\n}\n\n/// THE ACTION-CLASS AXIS", money_helper_start
)
if money_helper_start < 0 or money_helper_end < 0:
    fail("could not isolate labeled-money approval fixture")
if 'with_metadata("require_approval", "true")' in web_smoke_tests[
    money_helper_start:money_helper_end
]:
    fail("positive money fixture regained a second approval signal and no longer proves criticality forces gating")
if "async fn the_gate_is_found_when_it_is_keyed_by_the_govder_action_label" not in web_smoke_tests:
    fail("automatic human-floor gating lacks the authoritative-recipe positive control")

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

for hook in (
    "verify_tenant_assertion(",
    "original_uri.path()",
    "original_uri.query().unwrap_or(\"\")",
    "&body_bytes",
    "govder.assertion_ttl.min(MAX_BROKER_ASSERTION_TTL)",
    '"missing_approver_identity"',
    "let approver = if verified_broker_assertion",
    "VERIFIED_IDENTITY_PREFIX",
):
    if hook not in api and hook not in approval:
        fail(f"broker approval assertion refinement hook missing: {hook!r}")
missing_identity_guard = api.find('"missing_approver_identity"')
identity_namespace = api.find("let approver = if verified_broker_assertion")
approval_transition = api.find(".decide_approval(", identity_namespace)
if (
    missing_identity_guard < 0
    or identity_namespace < 0
    or approval_transition < 0
    or not missing_identity_guard < identity_namespace < approval_transition
):
    fail("non-blank approval identity guard must precede namespacing and transition")
for hook in (
    "tenant.as_slice() != expected_tenant.as_bytes()",
    "remaining < 0",
    "max_ttl.as_secs()",
    "mac.verify_slice(&supplied_mac)",
):
    if hook not in tenant_assert:
        fail(f"inbound tenant assertion verifier hook missing: {hook!r}")
for theorem in (
    "verified_broker_identity_is_exact",
    "changed_binding_rejected",
    "aggregator_claim_is_not_independent",
    "verified_broker_claim_is_independent",
    "verified_broker_claim_is_named",
):
    if f"theorem {theorem}" not in authority_lean:
        fail(f"Lean approval authority theorem missing: {theorem}")
if "if need_agent_reviewer > 0" not in approval:
    fail("agent-reviewer recipes are no longer hard-rejected by the runtime evaluator")
if "theorem agent_reviewer_recipe_is_unsatisfiable" not in approval_model_lean:
    fail("Lean model no longer proves agent-reviewer recipes unsatisfiable")
if "theorem supported_recipe_satisfies_every_floor" not in approval_model_lean:
    fail("Lean model no longer proves supported recipes satisfy every authority floor")
if "pub fn canonical_action_has_labels" not in config:
    fail("canonical action-label ambiguity detector is missing")
alias_ambiguity = server.find("let canonical_label_ambiguous =")
exact_rule_return = server.find("GateRuleAnswer::Rule(_) => return Ok(answer)", alias_ambiguity)
alias_refusal = server.find("if canonical_label_ambiguous {", exact_rule_return)
numeric_fallback = server.find("Ok(match first_inconclusive", alias_refusal)
if min(alias_ambiguity, exact_rule_return, alias_refusal, numeric_fallback) < 0 or not (
    alias_ambiguity < exact_rule_return < alias_refusal < numeric_fallback
):
    fail("canonical alias ambiguity must allow an exact rule then refuse before numeric fallback")
for theorem in (
    "canonical_alias_without_rule_is_refused",
    "canonical_alias_inconclusive_is_refused",
    "exact_canonical_rule_remains_authoritative",
):
    if f"theorem {theorem}" not in action_authority_lean:
        fail(f"Lean action-authority theorem missing: {theorem}")
for hook in (
    "self.resolve_pinned_http_method()?",
    'if args_obj.contains_key("method")',
    "let method = capability.resolve_pinned_http_method()?",
    'params.insert("method".to_string(), serde_json::json!(method))',
):
    if hook not in capability:
        fail(f"internal HTTP method-authority refinement hook missing: {hook!r}")
caller_method_rejection = capability.find('if args_obj.contains_key("method")')
operator_resolution = capability.find(
    "let method = capability.resolve_pinned_http_method()?", caller_method_rejection
)
plugin_params_merge = capability.find("for (k, v) in &capability.target.plugin_params", operator_resolution)
final_method_pin = capability.find(
    'params.insert("method".to_string(), serde_json::json!(method))', plugin_params_merge
)
if min(caller_method_rejection, operator_resolution, plugin_params_merge, final_method_pin) < 0 or not (
    caller_method_rejection < operator_resolution < plugin_params_merge < final_method_pin
):
    fail("caller method rejection and final operator method pin ordering drifted")
for theorem in (
    "successful_method_is_operator_method",
    "caller_method_is_rejected",
):
    if f"theorem {theorem}" not in method_authority_lean:
        fail(f"Lean method-authority theorem missing: {theorem}")
for test in (
    "a_caller_supplied_method_is_refused_and_never_widens_the_verb",
    "a_caller_supplied_method_is_refused_even_when_it_matches_the_pin",
):
    if f"async fn {test}" not in internal_http_capability_tests:
        fail(f"internal HTTP method-authority integration test missing: {test}")

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

for hook in (
    "fn fixed_window_transition(",
    "let transition = fixed_window_transition(",
    "if max == 0 || window_secs == 0",
    'include_str!("../../formal/vectors/rate_limiter_traces.json")',
):
    if hook not in policy:
        fail(f"fixed-window refinement hook missing: {hook}")
trace_path = ROOT / "formal/vectors/rate_limiter_traces.json"
trace_sha256 = hashlib.sha256(trace_path.read_bytes()).hexdigest()
expected_trace_sha256 = "ab102718048eb7fd40d045daf1e5b1c0ab355361e0b5a7352e4cd7ed0f8b86ec"
if trace_sha256 != expected_trace_sha256:
    fail(
        "Rust-generated fixed-window trace fixture drifted: "
        f"got {trace_sha256}, want {expected_trace_sha256}"
    )

print("refinement check: PASS (8 execution binding fields; exact-bound named broker approval authority; credential-bound criticality with open-to-resume catalog continuity; declared human-floor capabilities cannot dispatch directly; fail-closed canonical action aliases; operator-pinned internal HTTP method; startup-validated policy/workload secrets; disabled agent-reviewer recipes; 2 permit-bound dispatch variants; 9 Kani harnesses; WASM/buffered+streaming egress/error/vault/limiter sinks confined; rate-trace sha256 pinned)")
