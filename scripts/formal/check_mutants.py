#!/usr/bin/env python3
"""Run the mutants listed in formal/claims.json and require each to be killed.

One scratch git worktree (detached at HEAD) is used; each mutant is applied,
the detector is run, and the tree is restored to HEAD (scratch_cache_dirs
survive), sequentially in place. See README.md.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import formal_kit as fk  # noqa: E402


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
                          errors="replace", check=check)


def run_detector_full(cmd: str, cwd: Path, timeout: int,
                      env: Optional[Dict[str, str]] = None) -> Tuple[str, int, str]:
    """Run a shell command in its own process group. Returns (status, code, output)
    where status is pass, fail or timeout and output is the full combined output."""
    p = subprocess.Popen(cmd, shell=True, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace", start_new_session=True, env=env)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)  # only the group we started
        except ProcessLookupError:
            pass
        out, _ = p.communicate()
        return "timeout", -1, out or ""
    return ("pass" if p.returncode == 0 else "fail"), p.returncode, out or ""


def run_detector(cmd: str, cwd: Path, timeout: int,
                 env: Optional[Dict[str, str]] = None) -> Tuple[str, int, str]:
    """Like run_detector_full but the output is cut to its last 1500 characters."""
    st, rc, out = run_detector_full(cmd, cwd, timeout, env)
    return st, rc, out[-1500:]


# ---- detector vacuity guard ----------------------------------------------

_CARGO_RUNNING = re.compile(r"^\s*running (\d+) tests?\b", re.M)
_CARGO_RESULT = re.compile(r"^test result: \w+\. (\d+) passed;", re.M)
_GO_OK_LINE = re.compile(r"^ok\s+\S+.*$", re.M)
_BUILD_BREAK = re.compile(r"error\[E\d+\]|could not compile|build failed|\[build failed\]|cannot find |"
                          r"undefined: |syntax error|error: aborting due to", re.I)


def vacuity_problem(kind: str, cmd: str, out: str) -> Optional[str]:
    """Reason the baseline run of a detector proves nothing, or None when it ran tests.
    kind: auto (decided from the output), cargo, go, or custom (no check)."""
    if kind == "custom":
        return None
    cargo = _CARGO_RUNNING.findall(out)
    gomark = bool(re.search(r"^(?:ok|FAIL|\?)\s+\S+|^--- (?:PASS|FAIL)|^=== RUN|no tests to run", out, re.M))
    if kind == "auto":
        if cargo:
            kind = "cargo"
        elif gomark or re.search(r"\bgo test\b", cmd):
            kind = "go"
        elif re.search(r"\bcargo\s+(?:\+\S+\s+)?(?:test|nextest)\b", cmd):
            kind = "cargo"
        else:
            return ("cannot tell whether this detector ran any test (its output looks neither like cargo test nor "
                    "go test); if it is a proof or a custom check, set \"detector_kind\": \"custom\" on the claim")
    if kind == "cargo":
        if not cargo:
            return "cargo test output has no 'running N tests' line, so no test binary ran"
        if all(int(n) == 0 for n in cargo):
            return "every 'running N tests' line says 0 tests: the test filter matched nothing"
        res = _CARGO_RESULT.findall(out)
        if res and all(int(n) == 0 for n in res):
            return "no test passed ('0 passed' in every test result): the filter matched nothing or all tests are ignored"
        return None
    # go
    if re.search(r"\s-v(?:\s|$)|-test\.v", cmd) and not re.search(r"^=== RUN", out, re.M):
        return "go test -v output has no '=== RUN' line: -run matched nothing"
    # the package line decides when there is one: `[no tests to run]` can follow coverage text (-cover), and
    # with -v a parent test prints `--- PASS` even when -run matched none of its subtests
    oks = _GO_OK_LINE.findall(out)
    ran = [ln for ln in oks if "[no tests to run]" not in ln] if oks else re.findall(r"^--- PASS", out, re.M)
    if not ran:
        return "go test ran no test ('no tests to run' or no test files in every package)"
    return None


def restore_tree(scratch: Path, keep: List[str], base: str) -> bool:
    """Undo everything a detector or patch did to the scratch tree: HEAD, index and tracked files back
    to base (also undoes a detector's `git add` or commit), untracked and ignored files removed (nested
    repositories too) except the configured cache dirs. True when clean."""
    _git(scratch, "reset", "-q", "--hard", base, check=False)
    args = ["clean", "-ffdxq"]
    for k in keep:
        args += ["-e", "/" + k.strip("/")]
    _git(scratch, *args, check=False)
    if _git(scratch, "rev-parse", "HEAD", check=False).stdout.strip() != base:
        return False
    kept = [k.strip("/") for k in keep]
    # the kept caches are excluded by pathspec so a large one (a Lake package tree) is not listed file by file
    st = _git(scratch, "status", "--porcelain", "-z", "--untracked-files=all", "--ignored", "--", ".",
              *[":(exclude,literal)" + k for k in kept], check=False)
    if st.returncode != 0:
        return False
    left = [e[3:].rstrip("/") for e in st.stdout.split("\0") if e]
    return not [p for p in left if not any(p == k or p.startswith(k + "/") for k in kept)]


def created_paths(scratch: Path, patch: Path) -> List[str]:
    """Paths the patch creates (from `git apply --summary`, which applies nothing)."""
    r = _git(scratch, "apply", "--summary", str(patch), check=False)
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("create mode "):
            parts = line.split(" ", 3)
            if len(parts) == 4:
                out.append(parts[3].strip('"'))
    return out


def neutralize_drift_lock(scratch: Path, claims_rel: Optional[Path]) -> None:
    """Rewrite the scratch tree's claims.json cover hashes to the mutated source, so a
    detector that runs check_claims.py (directly, or hidden inside a make target or a
    script) cannot kill the mutant through the drift lock alone. The scratch tree is
    restored after the detector runs, like any other edit."""
    if claims_rel is None or not (scratch / claims_rel).is_file():
        return
    import check_claims as cc  # same directory, already on sys.path
    try:
        data = fk.load_claims(scratch / claims_rel)
        if fk.validate_schema(data):
            return
        cc.relock(scratch / claims_rel, cc.evaluate_covers(scratch, data), None)
    except (fk.KitError, OSError, ValueError, KeyError):
        return


def select(specs: List[fk.MutantSpec], tier: str, only: Optional[str]) -> List[fk.MutantSpec]:
    if only:
        return [s for s in specs if s.id == only]
    if tier == "fast":
        return [s for s in specs if s.tier == "fast"]
    return list(specs)


def run(root: Path, claims_path: Path, tier: str = "full", only: Optional[str] = None,
        timeout: int = 900, scratch: Optional[Path] = None, json_path: Optional[Path] = None,
        out=sys.stdout, allow_empty: bool = False, cargo_target_dir: Optional[Path] = None) -> int:
    data = fk.load_claims(claims_path)
    errs = fk.validate_schema(data)
    specs, rerrs = fk.resolve_mutants(data)
    errs += rerrs
    if errs:
        for e in errs:
            print("ERROR  %s" % e, file=out)
        return 2
    chosen = select(specs, tier, only)
    if only and not chosen:
        print("ERROR  no mutant with id %s" % only, file=out)
        return 2
    if not chosen:
        if specs and not allow_empty:
            print("ERROR  no mutants selected (tier=%s) but the claims list %d mutant(s); a gate that selects "
                  "nothing checks nothing. Set \"tier\" on the mutants (see README) or pass --allow-empty."
                  % (tier, len(specs)), file=out)
            return 1
        print("no mutants selected (tier=%s)" % tier, file=out)
        return 0
    if _git(root, "status", "--porcelain", "--untracked-files=no", check=False).stdout.strip():
        print("WARNING  tracked files are modified; the scratch tree is built from HEAD, so uncommitted "
              "changes are NOT tested", file=out)
    keep = list(data.get("scratch_cache_dirs", []))
    tmp_made = None
    if scratch is None:
        tmp_made = Path(tempfile.mkdtemp(prefix="formal-mutants-"))
        scratch = tmp_made / "wt"
    else:
        scratch = Path(scratch).resolve()
        if scratch.is_file():
            print("ERROR  --scratch %s is a file, not a directory" % scratch, file=out)
            return 2
        if scratch.exists() and any(scratch.iterdir()):
            print("ERROR  --scratch %s exists and is not empty" % scratch, file=out)
            return 2
    try:
        claims_rel = claims_path.resolve().relative_to(root.resolve())
    except ValueError:
        claims_rel = None
    # Rust builds use their OWN target dir, never the caller's CARGO_TARGET_DIR: cargo compares source mtimes, so
    # a shared target could serve binaries built from another tree (stale or mutated) to a detector.
    own_target = None
    if cargo_target_dir is None:
        if tmp_made is not None:
            own_target = tmp_made / "cargo-target"
        else:
            # a fresh directory, so the cleanup below can never remove one the caller already had
            scratch.parent.mkdir(parents=True, exist_ok=True)
            own_target = Path(tempfile.mkdtemp(prefix=scratch.name + "-cargo-target-", dir=str(scratch.parent)))
        cargo_target_dir = own_target
    env = dict(os.environ, CARGO_TARGET_DIR=str(Path(cargo_target_dir).resolve()))
    print("formal kit v%s; cargo target dir %s" % (fk.KIT_VERSION, env["CARGO_TARGET_DIR"]), file=out)
    results: List[Dict] = []
    baseline: List[Dict] = []
    created = False
    code = 0
    try:
        r = _git(root, "worktree", "add", "--detach", str(scratch), "HEAD", check=False)
        if r.returncode != 0:
            print("ERROR  cannot create scratch worktree: %s" % r.stderr.strip(), file=out)
            code = 2
            return code
        created = True
        base = _git(scratch, "rev-parse", "HEAD").stdout.strip()
        if claims_rel is not None and not (scratch / claims_rel).exists():
            print("WARNING  %s is not in HEAD" % claims_rel, file=out)
        # baseline: every distinct detector must pass on the unmutated tree
        seen = {}
        for s in chosen:
            if s.detector not in seen:
                if "check_claims" in s.detector:
                    print("WARNING  detector %r runs check_claims.py. The kit relocks the scratch claims after "
                          "applying each mutant, so the drift lock cannot kill it, but a detector should run the "
                          "proof or test, not the claims checker" % s.detector, file=out)
                st, rc, full = run_detector_full(s.detector, scratch, timeout, env)
                tail = full[-1500:]
                vac = vacuity_problem(s.kind, s.detector, full) if st == "pass" else None
                if vac:
                    st, tail = "vacuous", "vacuous detector: " + vac
                seen[s.detector] = (st, rc, tail)
                baseline.append({"detector": s.detector, "status": st, "code": rc})
                print("%s  baseline: %s" % ("ok  " if st == "pass" else "FAIL", s.detector), file=out)
                if st != "pass":
                    print("      " + tail.strip().replace("\n", "\n      ")[-600:], file=out)
                if _git(scratch, "status", "--porcelain", "--untracked-files=all", check=False).stdout.strip():
                    print("NOTE  baseline detector changed the scratch tree; restoring it", file=out)
                if not restore_tree(scratch, keep, base):
                    print("ERROR  could not restore the scratch tree after the baseline run", file=out)
                    code = 2
                    return code
        if any(v[0] != "pass" for v in seen.values()):
            print("baseline failed: the detector does not pass on the unmutated tree, so no mutant result "
                  "would mean anything", file=out)
            code = 1
        else:
            claims_by_id = {c["id"]: c for c in data["claims"]}

            def cover_hashes(claim_id: str) -> List[str]:
                hs = []
                for cv in claims_by_id[claim_id].get("covers", []):
                    try:
                        hs.append(fk.symbol_hash(scratch, cv["path"], cv["symbol"]))
                    except fk.KitError as e:
                        hs.append("unreadable:" + str(e))
                return hs
            for s in chosen:
                patch = (scratch / "formal" / "mutants" / (s.id + ".patch"))
                row = {"id": s.id, "claim": s.claim, "tier": s.tier, "status": "", "detail": "", "seconds": 0.0}
                results.append(row)
                if not patch.is_file():
                    row.update(status="error", detail="patch file missing in HEAD")
                    continue
                chk = _git(scratch, "apply", "--check", str(patch), check=False)
                if chk.returncode != 0:
                    row.update(status="error", detail="patch does not apply: " + chk.stderr.strip()[:300])
                    continue
                before = cover_hashes(s.claim)
                new_files = created_paths(scratch, patch)
                ap = _git(scratch, "apply", str(patch), check=False)
                if ap.returncode != 0:
                    row.update(status="error", detail="patch apply failed: " + ap.stderr.strip()[:300])
                    continue
                touched = before != cover_hashes(s.claim)
                neutralize_drift_lock(scratch, claims_rel)
                t0 = time.time()
                st, rc, tail = run_detector(s.detector, scratch, timeout, dict(env, FORMAL_KIT_MUTATED_TREE="1"))
                row["seconds"] = round(time.time() - t0, 1)
                # full restore after every mutant run: tracked files back to HEAD (undoes the patch and any
                # edit the detector made), untracked and ignored files removed (a file the patch created, or
                # one the detector generated) except the configured cache dirs; a file the patch created
                # inside a cache dir would survive the clean, so that is checked too
                restored = restore_tree(scratch, keep, base)
                leaked = [p for p in new_files if (scratch / p).exists() or (scratch / p).is_symlink()] if restored else []
                if not restored or leaked:
                    row.update(status="error", detail="could not restore the scratch tree%s; aborting" % (
                        " (the patch-created %s survived in a scratch_cache_dirs entry)" % ", ".join(leaked)
                        if leaked else ""))
                    break
                if st == "fail" and not touched:
                    row.update(status="error", detail="vacuous kill: the patch changed no symbol listed in the "
                                                      "claim's covers (detector exit %d), so it does not show the "
                                                      "gate bites on covered code" % rc)
                elif st == "fail":
                    note = ""
                    if _BUILD_BREAK.search(tail):
                        note = " (WARNING: the output looks like a build failure, a compile-break is a weak kill; review the mutant)"
                    row.update(status="killed", detail="detector exit %d%s" % (rc, note))
                elif st == "pass":
                    row.update(status="SURVIVED", detail="detector still passes with the mutant applied")
                else:
                    row.update(status="error", detail="detector timed out after %ds (not counted as a kill)" % timeout)
            for row in results:
                print("%-9s %s (claim %s, tier %s) %s" % (row["status"], row["id"], row["claim"], row["tier"],
                                                         row["detail"]), file=out)
            if any(r["status"] != "killed" for r in results):
                code = 1
            skipped = len(chosen) - len(results)
            if skipped:
                print("ERROR  %d mutant(s) not run after an abort" % skipped, file=out)
                code = 1
            print("%d mutant(s): %d killed, %d survived, %d error" % (
                len(results), sum(r["status"] == "killed" for r in results),
                sum(r["status"] == "SURVIVED" for r in results), sum(r["status"] == "error" for r in results)), file=out)
    finally:
        if own_target is not None and own_target.exists():
            shutil.rmtree(own_target, ignore_errors=True)
        if created:
            _git(root, "worktree", "remove", "--force", str(scratch), check=False)
            _git(root, "worktree", "prune", check=False)
        if scratch.exists():
            shutil.rmtree(scratch, ignore_errors=True)
        if tmp_made is not None:
            shutil.rmtree(tmp_made, ignore_errors=True)
        if json_path:
            Path(json_path).write_text(json.dumps({"tier": tier, "baseline": baseline, "results": results,
                                                    "exit": code}, indent=2) + "\n", encoding="utf-8")
    return code


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root")
    ap.add_argument("--claims")
    ap.add_argument("--tier", choices=fk.TIERS, default="full",
                    help="fast: only tier fast; full (default): every mutant")
    ap.add_argument("--only", help="run just this mutant id")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per detector run")
    ap.add_argument("--scratch", help="scratch worktree path (default: a temp dir)")
    ap.add_argument("--json", help="write a JSON report here")
    ap.add_argument("--cargo-target-dir",
                    help="CARGO_TARGET_DIR for the detectors (default: a private dir beside the scratch tree, "
                         "removed afterwards; never the caller's CARGO_TARGET_DIR)")
    ap.add_argument("--version", action="version", version="formal kit %s" % fk.KIT_VERSION)
    ap.add_argument("--allow-empty", action="store_true",
                    help="do not fail when the selected tier has no mutants although the claims list some")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve() if a.root else fk.git_toplevel(Path.cwd())
    claims = Path(a.claims) if a.claims else root / "formal" / "claims.json"
    try:
        return run(root, claims, a.tier, a.only, a.timeout, Path(a.scratch) if a.scratch else None,
                   Path(a.json) if a.json else None,
                   allow_empty=a.allow_empty,
                   cargo_target_dir=Path(a.cargo_target_dir) if a.cargo_target_dir else None)
    except fk.KitError as e:
        print("ERROR  %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
