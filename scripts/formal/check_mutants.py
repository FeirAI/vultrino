#!/usr/bin/env python3
"""Run the mutants listed in formal/claims.json and require each to be killed.

One scratch git worktree (detached at HEAD) is used; each mutant is applied,
the detector is run, and the patch is reverted, sequentially in place so build
caches keyed on absolute paths stay valid. See README.md.
"""
from __future__ import annotations

import argparse
import json
import os
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


def run_detector(cmd: str, cwd: Path, timeout: int) -> Tuple[str, int, str]:
    """Run a shell command in its own process group. Returns (status, code, tail)
    where status is pass, fail or timeout."""
    p = subprocess.Popen(cmd, shell=True, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace", start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)  # only the group we started
        except ProcessLookupError:
            pass
        out, _ = p.communicate()
        return "timeout", -1, (out or "")[-1500:]
    return ("pass" if p.returncode == 0 else "fail"), p.returncode, (out or "")[-1500:]


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
        out=sys.stdout, allow_empty: bool = False) -> int:
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
    tmp_made = None
    if scratch is None:
        tmp_made = Path(tempfile.mkdtemp(prefix="formal-mutants-"))
        scratch = tmp_made / "wt"
    else:
        scratch = Path(scratch).resolve()
        if scratch.exists() and any(scratch.iterdir()):
            print("ERROR  --scratch %s exists and is not empty" % scratch, file=out)
            return 2
    try:
        claims_rel = claims_path.resolve().relative_to(root.resolve())
    except ValueError:
        claims_rel = None
    results: List[Dict] = []
    baseline: List[Dict] = []
    created = False
    code = 0
    try:
        r = _git(root, "worktree", "add", "--detach", str(scratch), "HEAD", check=False)
        if r.returncode != 0:
            print("ERROR  cannot create scratch worktree: %s" % r.stderr.strip(), file=out)
            return 2
        created = True
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
                st, rc, tail = run_detector(s.detector, scratch, timeout)
                seen[s.detector] = (st, rc, tail)
                baseline.append({"detector": s.detector, "status": st, "code": rc})
                print("%s  baseline: %s" % ("ok  " if st == "pass" else "FAIL", s.detector), file=out)
                if st != "pass":
                    print("      " + tail.strip().replace("\n", "\n      ")[-600:], file=out)
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
                st, rc, tail = run_detector(s.detector, scratch, timeout)
                row["seconds"] = round(time.time() - t0, 1)
                rv = _git(scratch, "apply", "-R", str(patch), check=False)
                dirty = _git(scratch, "diff", "--quiet", check=False).returncode != 0
                if rv.returncode != 0 or dirty:
                    _git(scratch, "checkout", "--", ".", check=False)
                # a file the patch created survives a failed `apply -R` (checkout only
                # restores tracked files); remove it so it cannot leak into the next mutant
                for rel in new_files:
                    p = scratch / rel
                    tracked = _git(scratch, "ls-files", "--error-unmatch", "--", rel, check=False).returncode == 0
                    if not tracked and (p.is_file() or p.is_symlink()):
                        p.unlink()
                leaked = [rel for rel in new_files if (scratch / rel).exists()
                          and _git(scratch, "ls-files", "--error-unmatch", "--", rel, check=False).returncode != 0]
                if _git(scratch, "diff", "--quiet", check=False).returncode != 0 or leaked:
                    row.update(status="error", detail="could not restore the scratch tree; aborting")
                    break
                if st == "fail" and not touched:
                    row.update(status="error", detail="vacuous kill: the patch changed no symbol listed in the "
                                                      "claim's covers (detector exit %d), so it does not show the "
                                                      "gate bites on covered code" % rc)
                elif st == "fail":
                    row.update(status="killed", detail="detector exit %d" % rc)
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
    ap.add_argument("--allow-empty", action="store_true",
                    help="do not fail when the selected tier has no mutants although the claims list some")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve() if a.root else fk.git_toplevel(Path.cwd())
    claims = Path(a.claims) if a.claims else root / "formal" / "claims.json"
    try:
        return run(root, claims, a.tier, a.only, a.timeout, Path(a.scratch) if a.scratch else None,
                   Path(a.json) if a.json else None,
                   allow_empty=a.allow_empty)
    except fk.KitError as e:
        print("ERROR  %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
