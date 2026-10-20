#!/usr/bin/env python3
"""Split the formal register's mutants into N deterministic shards for the nightly full tier.

    shard_register.py --shards N --list              print every shard's mutant ids and counts
    shard_register.py --shards N --index K --write   rewrite formal/claims.json to shard K only

check_mutants.py takes one mutant id (--only) or a whole tier, nothing in between, and the kit is
a shared, drift-locked copy that this repository does not edit. So a shard job narrows the REGISTER
instead: --write drops every mutant that is not in shard K from the claims' mutant lists and from the
top-level mutants map, and drops the claims left with none. The job then commits that file in its
own throwaway checkout (never pushed) and runs `check_mutants.py --tier full` on it, so the kit
keeps its drift-lock neutralisation, vacuity checks and one baseline run per detector.

Mutants are grouped by detector (a baseline run of an expensive detector, for example a proof, is
paid once per shard that holds one of its mutants) and the groups are dealt, largest first, to the
shard with the least load. The assignment depends only on the register, so every shard job computes
the same partition. Every mutant lands in exactly one shard; --write verifies that before writing.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "formal"))
import formal_kit as fk  # noqa: E402

BASELINE_WEIGHT = 2  # a detector's baseline run counts as this many mutants when balancing


def partition(data, shards):
    specs, errs = fk.resolve_mutants(data)
    errs += fk.validate_schema(data)
    if errs:
        raise SystemExit("register does not validate: " + "; ".join(errs[:5]))
    groups = {}
    for s in specs:
        groups.setdefault(s.detector, []).append(s.id)
    order = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    load = [0] * shards
    out = [[] for _ in range(shards)]
    for _, ids in order:
        k = min(range(shards), key=lambda i: (load[i], i))
        out[k].extend(ids)
        load[k] += len(ids) + BASELINE_WEIGHT
    out = [sorted(x) for x in out]
    flat = [i for x in out for i in x]
    if sorted(flat) != sorted(s.id for s in specs) or len(set(flat)) != len(flat):
        raise SystemExit("internal error: shards do not cover every mutant exactly once")
    return out


def narrow(data, keep):
    keep = set(keep)
    d = json.loads(json.dumps(data))
    claims = []
    for c in d["claims"]:
        c["mutants"] = [m for m in c.get("mutants", []) if m in keep]
        if c["mutants"]:
            claims.append(c)
    d["claims"] = claims
    d["mutants"] = {k: v for k, v in d.get("mutants", {}).items() if k in keep}
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--shards", type=int, required=True)
    ap.add_argument("--index", type=int)
    ap.add_argument("--claims", default="formal/claims.json")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    if a.shards < 1:
        raise SystemExit("--shards must be at least 1")
    path = Path(a.claims)
    data = json.loads(path.read_text(encoding="utf-8"))
    parts = partition(data, a.shards)
    if a.list:
        for i, ids in enumerate(parts):
            print("shard %d: %d mutants" % (i, len(ids)))
            for m in ids:
                print("  " + m)
        print("total: %d mutants in %d shards, each exactly once" % (sum(len(p) for p in parts), a.shards))
    if a.write:
        if a.index is None or not 0 <= a.index < a.shards:
            raise SystemExit("--write needs --index in 0..shards-1")
        if not parts[a.index]:
            raise SystemExit("shard %d is empty; use fewer shards" % a.index)
        nd = narrow(data, parts[a.index])
        errs = fk.validate_schema(nd)
        if errs:
            raise SystemExit("narrowed register does not validate: " + "; ".join(errs[:5]))
        path.write_text(json.dumps(nd, indent=2) + "\n", encoding="utf-8")
        print("shard %d of %d: %d mutants, %d claims" % (a.index, a.shards, len(parts[a.index]), len(nd["claims"])))


if __name__ == "__main__":
    main()
