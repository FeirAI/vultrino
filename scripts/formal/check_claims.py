#!/usr/bin/env python3
"""Validate formal/claims.json against the repository (see README.md).

Checks: schema and unique ids, artifact paths, gate job ids, ci-required
equality, drift-lock hashes (covers), mutant patch files, overclaim denylist.
Exit status is non-zero on any failure.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import formal_kit as fk  # noqa: E402

SKIP_DIRS = {".git", "target", "node_modules", ".worktrees", "vendor", "dist", ".venv"}


class Report:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, bool, str]] = []

    def ok(self, check: str, msg: str = "") -> None:
        self.rows.append((check, True, msg))

    def fail(self, check: str, msg: str) -> None:
        self.rows.append((check, False, msg))

    def warn(self, check: str, msg: str) -> None:
        self.rows.append((check, True, "WARNING: " + msg))

    @property
    def failed(self) -> bool:
        return any(not ok for _, ok, _ in self.rows)

    def render(self) -> str:
        lines = []
        for check, ok, msg in self.rows:
            lines.append("%s  %s%s" % ("PASS" if ok else "FAIL", check, (": " + msg) if msg else ""))
        bad = sum(1 for _, ok, _ in self.rows if not ok)
        lines.append("")
        lines.append("%d check(s), %d failure(s)" % (len(self.rows), bad))
        return "\n".join(lines)


# ---- check pieces --------------------------------------------------------

def check_artifacts(root: Path, data: dict, rep: Report) -> None:
    for c in data.get("claims", []):
        for a in c.get("artifacts", []):
            if (root / a).exists():
                rep.ok("artifact %s" % a, c["id"])
            else:
                rep.fail("artifact %s" % a, "claim %s: path does not exist" % c["id"])


def check_gates(parsed, wf_errors, data: dict, rep: Report) -> None:
    for rel, err in wf_errors.items():
        rep.fail("workflow parse %s" % rel, err)
    ids = {jid for jobs in parsed.values() for jid in jobs}
    for c in data.get("claims", []):
        for g in c.get("gates", []):
            if g in ids:
                rep.ok("gate %s" % g, c["id"])
            elif wf_errors:
                rep.fail("gate %s" % g, "claim %s: cannot confirm, a workflow failed to parse" % c["id"])
            else:
                rep.fail("gate %s" % g, "claim %s: no job with this id in .github/workflows" % c["id"])


def check_ci_required(parsed, wf_errors, data: dict, rep: Report) -> None:
    holders = [rel for rel, jobs in parsed.items() if "ci-required" in jobs]
    if wf_errors and not holders:
        rep.fail("ci-required", "cannot locate ci-required: a workflow failed to parse")
        return
    if len(holders) != 1:
        rep.fail("ci-required", "expected exactly one workflow with a ci-required job, found %d (%s)"
                 % (len(holders), ", ".join(holders) or "none"))
        return
    rel = holders[0]
    jobs = parsed[rel]
    gate = jobs["ci-required"]
    exempt = {e["job"]: e["reason"] for e in data.get("ci_required_exempt", [])}
    problems = []
    for j in exempt:
        if j not in jobs:
            problems.append("exempt job %s does not exist in %s" % (j, rel))
        elif jobs[j].has_if:
            problems.append("exempt job %s already has a job-level if (exemption is redundant)" % j)
    if gate.needs is None:
        rep.fail("ci-required", "%s: ci-required has no needs" % rel)
        return
    cond = {e["job"]: e["reason"] for e in data.get("ci_required_conditional", [])}
    for j in cond:
        if j in exempt:
            problems.append("job %s is in both ci_required_exempt and ci_required_conditional" % j)
        if j not in jobs:
            problems.append("conditional job %s does not exist in %s" % (j, rel))
        else:
            if not jobs[j].has_if:
                problems.append("conditional job %s has no job-level if (declare it only for jobs that have one)" % j)
            if j not in gate.needs:
                problems.append("conditional job %s is not in ci-required needs (declare it only if the gate waits for it)" % j)
    expected = ({j for j, job in jobs.items() if j != "ci-required" and not job.has_if and j not in exempt}
                | {j for j in cond if j in jobs and j in gate.needs and jobs[j].has_if})
    actual = set(gate.needs)
    for j in sorted(actual & set(exempt)):
        problems.append("exempt job %s is in ci-required needs" % j)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected - set(exempt))
    if missing:
        problems.append("jobs with no job-level if missing from needs: %s" % ", ".join(missing))
    if extra:
        problems.append("needs entries that are not unconditional jobs of %s: %s" % (rel, ", ".join(extra)))
    if len(gate.needs) != len(actual):
        problems.append("duplicate entries in needs")
    if problems:
        for p in problems:
            rep.fail("ci-required", p)
    else:
        rep.ok("ci-required", "%s needs == %d jobs (%d declared conditional)" % (rel, len(expected), len(cond)))


class CoverResult:
    def __init__(self, ci: int, vi: int, cid: str, path: str, symbol: str, recorded: str,
                 current: Optional[str], error: Optional[str]) -> None:
        self.ci, self.vi, self.cid, self.path, self.symbol = ci, vi, cid, path, symbol
        self.recorded, self.current, self.error = recorded, current, error

    @property
    def matches(self) -> bool:
        return self.error is None and self.current == self.recorded


def evaluate_covers(root: Path, data: dict) -> List[CoverResult]:
    results = []
    cache: Dict[Tuple[str, str], Tuple[Optional[str], Optional[str]]] = {}
    for ci, c in enumerate(data.get("claims", [])):
        for vi, cv in enumerate(c.get("covers", [])):
            key = (cv["path"], cv["symbol"])
            if key not in cache:
                try:
                    cache[key] = (fk.symbol_hash(root, cv["path"], cv["symbol"]), None)
                except fk.KitError as e:
                    cache[key] = (None, str(e))
                except (OSError, UnicodeDecodeError) as e:
                    cache[key] = (None, "cannot read %s: %s" % (cv["path"], e))
            cur, err = cache[key]
            results.append(CoverResult(ci, vi, c["id"], cv["path"], cv["symbol"], cv["sha256"], cur, err))
    return results


def report_covers(results: List[CoverResult], rep: Report) -> None:
    for r in results:
        name = "covers %s %s" % (r.path, r.symbol)
        if r.error:
            rep.fail(name, "claim %s: %s" % (r.cid, r.error))
        elif r.matches:
            rep.ok(name, r.cid)
        else:
            rep.fail(name, "claim %s: source changed (recorded %s, current %s); review the claim, then --relock"
                     % (r.cid, r.recorded[:12] or "<empty>", r.current[:12]))


def relock(claims_path: Path, results: List[CoverResult], only: Optional[List[str]]) -> List[str]:
    """Rewrite mismatched hashes. Returns human-readable change lines."""
    def selected(r: CoverResult) -> bool:
        if not only:
            return True
        return any(o == r.path or o == "%s:%s" % (r.path, r.symbol) for o in only)

    changes = [r for r in results if r.error is None and not r.matches and selected(r)]
    if not changes:
        return []
    text = claims_path.read_text(encoding="utf-8")
    pat = re.compile(r'("sha256"\s*:\s*")([0-9a-fA-F]*)(")')
    found = list(pat.finditer(text))
    if len(found) == len(results):
        repl = {(r.ci, r.vi): r.current for r in changes}
        order = [(r.ci, r.vi) for r in results]
        out, last = [], 0
        for key, m in zip(order, found):
            out.append(text[last : m.start(2)])
            out.append(repl.get(key, m.group(2)))
            last = m.end(2)
        out.append(text[last:])
        claims_path.write_text("".join(out), encoding="utf-8")
    else:
        data = json.loads(text)
        for r in changes:
            data["claims"][r.ci]["covers"][r.vi]["sha256"] = r.current
        claims_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return ["relocked %s %s (claim %s): %s -> %s" % (r.path, r.symbol, r.cid, r.recorded[:12] or "<empty>", r.current[:12])
            for r in changes]


def check_mutants_files(root: Path, data: dict, rep: Report) -> None:
    specs, errs = fk.resolve_mutants(data)
    for e in errs:
        rep.fail("mutants", e)
    referenced: Set[str] = set()
    for c in data.get("claims", []):
        for m in c.get("mutants", []):
            referenced.add(m)
            p = root / "formal" / "mutants" / (m + ".patch")
            if p.is_file():
                rep.ok("mutant %s" % m, c["id"])
            else:
                rep.fail("mutant %s" % m, "claim %s: formal/mutants/%s.patch is missing" % (c["id"], m))
    d = root / "formal" / "mutants"
    if d.is_dir():
        for p in sorted(d.glob("*.patch")):
            if p.stem not in referenced:
                rep.warn("mutant file %s" % p.name, "not referenced by any claim")


def _glob_to_re(g: str) -> "re.Pattern[str]":
    out, i = [], 0
    while i < len(g):
        if g.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif g.startswith("**", i):
            out.append(".*")
            i += 2
        elif g[i] == "*":
            out.append("[^/]*")
            i += 1
        elif g[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(g[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def list_files(root: Path) -> List[str]:
    try:
        out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=str(root),
                             capture_output=True, check=True).stdout
        return [p for p in out.decode("utf-8", "replace").split("\0") if p]
    except (subprocess.CalledProcessError, FileNotFoundError):
        files = []
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for f in fns:
                files.append((Path(dp) / f).relative_to(root).as_posix())
        return files


def _collapse_ws(s: str) -> str:
    return " ".join(s.lower().split())


def find_phrases(text: str, phrases: List[str]) -> List[Tuple[int, str]]:
    """(line, phrase) for every occurrence of a phrase in text, ignoring case
    and treating any run of whitespace (including a line break) as one space,
    so a phrase wrapped across lines in a hard-wrapped document is still found.
    phrases must already be passed through _collapse_ws."""
    low = text.lower()
    chars: List[str] = []
    line_of: List[int] = []
    line = 1
    prev_space = False
    for ch in low:
        if ch.isspace():
            if not prev_space:
                chars.append(" ")
                line_of.append(line)
            prev_space = True
            if ch == "\n":
                line += 1
        else:
            chars.append(ch)
            line_of.append(line)
            prev_space = False
    norm = "".join(chars)
    hits = []
    for ph in phrases:
        k = norm.find(ph)
        while k >= 0:
            hits.append((line_of[k], ph))
            k = norm.find(ph, k + 1)
    return sorted(hits)


def check_denylist(root: Path, data: dict, claims_rel: str, rep: Report) -> None:
    dl = data.get("overclaim_denylist") or {}
    phrases = [_collapse_ws(p) for p in dl.get("phrases", []) if _collapse_ws(p)]
    globs = [_glob_to_re(g) for g in dl.get("globs", [])]
    if not phrases:
        rep.ok("overclaim denylist", "no phrases configured")
        return
    if not globs:
        rep.fail("overclaim denylist", "phrases are configured but globs is empty, so nothing is scanned")
        return
    hits = []
    scanned = 0
    for rel in list_files(root):
        if rel == claims_rel or not any(g.match(rel) for g in globs):
            continue
        p = root / rel
        if not p.is_file():
            continue
        try:
            raw = p.read_bytes()
        except OSError as e:
            rep.fail("overclaim denylist", "%s: cannot read: %s" % (rel, e))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            # scan anyway (an ASCII phrase is still found) rather than skip the file
            text = raw.decode("utf-8", errors="replace")
            rep.warn("overclaim denylist", "%s is not valid UTF-8; scanned with replacement characters" % rel)
        scanned += 1
        for no, ph in find_phrases(text, phrases):
            hits.append("%s:%d contains %r" % (rel, no, ph))
    if scanned == 0:
        rep.fail("overclaim denylist", "globs matched no files; a typo would otherwise pass silently")
    elif hits:
        for h in hits:
            rep.fail("overclaim denylist", h)
    else:
        rep.ok("overclaim denylist", "%d file(s) scanned, %d phrase(s)" % (scanned, len(phrases)))


def run_detectors(root: Path, data: dict, rep: Report, timeout: int) -> None:
    for c in data.get("claims", []):
        try:
            r = subprocess.run(c["detector"], shell=True, cwd=str(root), capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout)
            if r.returncode == 0:
                rep.ok("detector %s" % c["id"])
            else:
                rep.fail("detector %s" % c["id"], "exit %d" % r.returncode)
        except subprocess.TimeoutExpired:
            rep.fail("detector %s" % c["id"], "timed out after %ds" % timeout)


def run_all(root: Path, claims_path: Path, do_relock: bool = False, only: Optional[List[str]] = None,
            detectors: bool = False, timeout: int = 1800) -> Tuple[Report, List[str]]:
    rep = Report()
    changes: List[str] = []
    try:
        data = fk.load_claims(claims_path)
    except fk.KitError as e:
        rep.fail("claims file", str(e))
        return rep, changes
    errs = fk.validate_schema(data)
    if errs:
        for e in errs:
            rep.fail("schema", e)
        return rep, changes
    rep.ok("schema", "%d claims" % len(data["claims"]))
    check_artifacts(root, data, rep)
    parsed, wf_errors = fk.load_workflows(root)
    check_gates(parsed, wf_errors, data, rep)
    check_ci_required(parsed, wf_errors, data, rep)
    results = evaluate_covers(root, data)
    if do_relock:
        changes = relock(claims_path, results, only)
        data = fk.load_claims(claims_path)
        results = evaluate_covers(root, data)
    report_covers(results, rep)
    check_mutants_files(root, data, rep)
    try:
        claims_rel = claims_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        claims_rel = ""
    check_denylist(root, data, claims_rel, rep)
    if detectors:
        run_detectors(root, data, rep, timeout)
    return rep, changes


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", help="repository root (default: git toplevel of cwd)")
    ap.add_argument("--claims", help="claims file (default: <root>/formal/claims.json)")
    ap.add_argument("--relock", action="store_true", help="rewrite mismatched cover hashes (deliberate; review the diff)")
    ap.add_argument("--symbol", action="append", default=[], metavar="PATH[:SYMBOL]",
                    help="with --relock, restrict to this cover (repeatable)")
    ap.add_argument("--run-detectors", action="store_true", help="also run every claim detector on this tree")
    ap.add_argument("--timeout", type=int, default=1800)
    a = ap.parse_args(argv)
    root = Path(a.root).resolve() if a.root else fk.git_toplevel(Path.cwd())
    claims = Path(a.claims) if a.claims else root / "formal" / "claims.json"
    rep, changes = run_all(root, claims, a.relock, a.symbol or None, a.run_detectors, a.timeout)
    for c in changes:
        print(c)
    print(rep.render())
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
