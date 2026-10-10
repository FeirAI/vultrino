#!/usr/bin/env python3
"""check_vectors_lock.py: keep the cross-plane golden-vector copies honest.

Every repo of the Feir AI stack keeps the signed wire-format vectors it produces or consumes in
vectors/ at its root, and pins each file's sha256 in vectors/vectors.lock:

  {"schema": 1, "repo": "govder", "files": [
     {"file": "tenant-assertion.v1.json", "owner": "govder", "sha256": "<hex>"}, ...]}

The owner repo generates a file (from an independent reference, see vectors/README.md); every
consumer keeps a byte-identical copy and pins the same sha256. This script is identical in every
repo (Python 3 standard library only).

Checks (exit 1 on any failure):
  * the lock parses, names this repo, and lists each file once with an owner and a sha256;
  * every listed file exists under vectors/ and hashes to its pin;
  * every *.json under vectors/ is listed (an unpinned vector file is an error).
With --peer NAME=PATH (repeatable; PATH is a checkout of repo NAME), also:
  * for every file this repo lists whose owner is NAME, NAME's lock lists it with the same pin and
    NAME's copy hashes to it (a vendored copy matches its source);
  * for every file this repo owns that NAME also lists, NAME pins the same sha256.
--update rewrites the pins of the listed files from the bytes on disk (deliberate; review the
diff). It never adds or removes entries.
"""
import argparse
import hashlib
import json
import os
import sys


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lock(root):
    path = os.path.join(root, "vectors", "vectors.lock")
    with open(path, "rb") as f:
        lock = json.loads(f.read().decode("utf-8"))
    return path, lock


def validate_lock(lock, where):
    errs = []
    if not isinstance(lock, dict) or lock.get("schema") != 1:
        return ["%s: schema must be 1" % where]
    if not isinstance(lock.get("repo"), str) or not lock["repo"]:
        errs.append("%s: missing repo name" % where)
    files = lock.get("files")
    if not isinstance(files, list) or not files:
        errs.append("%s: files must be a non-empty list" % where)
        return errs
    seen = set()
    for i, e in enumerate(files):
        if not isinstance(e, dict) or set(e) - {"file", "owner", "sha256", "$comment"}:
            errs.append("%s: entry %d has unknown or missing keys" % (where, i))
            continue
        for k in ("file", "owner", "sha256"):
            if not isinstance(e.get(k), str) or not e[k]:
                errs.append("%s: entry %d: %s must be a non-empty string" % (where, i, k))
        f = e.get("file", "")
        if "/" in f or "\\" in f or f.startswith("."):
            errs.append("%s: entry %d: file must be a plain name under vectors/: %r" % (where, i, f))
        if f in seen:
            errs.append("%s: %s listed twice" % (where, f))
        seen.add(f)
        s = e.get("sha256", "")
        if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
            errs.append("%s: %s: sha256 must be 64 lowercase hex characters" % (where, f))
    return errs


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="repo root (default: current directory)")
    ap.add_argument("--update", action="store_true", help="rewrite pins from the files on disk")
    ap.add_argument("--peer", action="append", default=[], metavar="NAME=PATH",
                    help="a checkout of another repo to cross-check against (repeatable)")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    lock_path, lock = load_lock(root)
    errs = validate_lock(lock, lock_path)
    if errs:
        print("\n".join("FAIL " + e for e in errs))
        return 1
    me = lock["repo"]
    vdir = os.path.join(root, "vectors")

    if args.update:
        for e in lock["files"]:
            e["sha256"] = sha256_file(os.path.join(vdir, e["file"]))
        with open(lock_path, "w", encoding="utf-8") as f:
            json.dump(lock, f, indent=2)
            f.write("\n")
        print("updated %s" % lock_path)

    listed = {e["file"]: e for e in lock["files"]}
    for name in sorted(os.listdir(vdir)):
        if name.endswith(".json") and name not in listed:
            errs.append("vectors/%s is not pinned in vectors/vectors.lock" % name)
    for f, e in sorted(listed.items()):
        p = os.path.join(vdir, f)
        if not os.path.isfile(p):
            errs.append("vectors/%s is pinned but missing" % f)
            continue
        got = sha256_file(p)
        if got != e["sha256"]:
            errs.append("vectors/%s: sha256 %s does not match the pin %s (owner %s)" % (f, got, e["sha256"], e["owner"]))
        else:
            print("ok   vectors/%s (owner %s%s)" % (f, e["owner"], ", owned here" if e["owner"] == me else ", vendored"))

    for spec in args.peer:
        if "=" not in spec:
            errs.append("--peer must be NAME=PATH, got %r" % spec)
            continue
        pname, ppath = spec.split("=", 1)
        try:
            plock_path, plock = load_lock(ppath)
        except (OSError, ValueError) as exc:
            errs.append("peer %s: cannot read vectors/vectors.lock under %s: %s" % (pname, ppath, exc))
            continue
        perrs = validate_lock(plock, plock_path)
        if perrs:
            errs.extend(perrs)
            continue
        if plock["repo"] != pname:
            errs.append("peer %s: its lock names repo %r" % (pname, plock["repo"]))
            continue
        plisted = {e["file"]: e for e in plock["files"]}
        for f, e in sorted(listed.items()):
            if e["owner"] == pname:
                pe = plisted.get(f)
                if pe is None:
                    errs.append("vectors/%s: owner %s does not list it" % (f, pname))
                    continue
                if pe["owner"] != pname or pe["sha256"] != e["sha256"]:
                    errs.append("vectors/%s: pinned %s here but %s in owner %s" % (f, e["sha256"], pe["sha256"], pname))
                    continue
                psha = sha256_file(os.path.join(ppath, "vectors", f))
                if psha != e["sha256"]:
                    errs.append("vectors/%s: owner %s's copy hashes to %s, not the pin" % (f, pname, psha))
                    continue
                print("ok   vectors/%s matches its source in %s" % (f, pname))
            elif e["owner"] == me and f in plisted:
                if plisted[f]["sha256"] != e["sha256"] or plisted[f]["owner"] != me:
                    errs.append("vectors/%s: owned here (%s) but %s pins %s (owner %s)" % (
                        f, e["sha256"], pname, plisted[f]["sha256"], plisted[f]["owner"]))
                else:
                    print("ok   vectors/%s: consumer %s pins the same bytes" % (f, pname))

    if errs:
        print("\n".join("FAIL " + e for e in errs))
        return 1
    print("vectors.lock: %d file(s) pinned in %s" % (len(listed), me))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
