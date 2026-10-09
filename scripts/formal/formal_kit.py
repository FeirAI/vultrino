"""Shared library for the formal kit (Python 3 standard library only).

Three parts:
  * a minimal indentation-aware reader for GitHub workflow files (jobs, if, needs)
  * a symbol extractor for Go and Rust that finds a declaration and its matching
    closing brace, skipping strings, raw strings, char literals and comments
  * claims.json loading and schema validation

Everything here fails loudly (raises KitError) on input it cannot parse, rather
than guessing. See README.md for the documented limits.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

KIT_VERSION = "2"
SCHEMA_VERSION = 1
METHODS = (
    "lean", "kani", "tla", "aeneas", "exhaustive", "differential-vectors",
    "fuzz", "property", "mutation", "e2e", "test",
)
TIERS = ("fast", "full")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
MUTANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class KitError(Exception):
    """Raised when the kit cannot safely interpret its input."""


# ---------------------------------------------------------------------------
# Source masking and brace matching
# ---------------------------------------------------------------------------

def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _is_ident_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def mask_source(text: str, lang: str) -> str:
    """Return text of the same length with comments, string contents and char
    literals blanked (newlines kept). String literals keep a leading and a
    trailing double quote so that `extern "C"` still looks like a string.
    lang is "go" or "rust". Raises KitError on an unterminated construct."""
    if lang not in ("go", "rust"):
        raise KitError("unknown language %r" % lang)
    rust = lang == "rust"
    n = len(text)
    out = list(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    def blank_string(a: int, b: int) -> None:
        blank(a, b)
        out[a] = '"'
        out[b - 1] = '"'

    def scan_quoted(start: int, quote: str, allow_newline: bool) -> int:
        """start is the index of the opening quote; returns index after close."""
        j = start + 1
        while j < n:
            ch = text[j]
            if ch == "\\":
                j += 2
                continue
            if ch == quote:
                return j + 1
            if ch == "\n" and not allow_newline:
                raise KitError("unterminated literal at line %d" % _line_of(text, start))
            j += 1
        raise KitError("unterminated literal at line %d" % _line_of(text, start))

    i = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and nxt == "*":
            if rust:
                depth = 1
                j = i + 2
                while j < n and depth:
                    if text.startswith("/*", j):
                        depth += 1
                        j += 2
                    elif text.startswith("*/", j):
                        depth -= 1
                        j += 2
                    else:
                        j += 1
                if depth:
                    raise KitError("unterminated block comment at line %d" % _line_of(text, i))
                end = j
            else:
                j = text.find("*/", i + 2)
                if j < 0:
                    raise KitError("unterminated block comment at line %d" % _line_of(text, i))
                end = j + 2
            blank(i, end)
            i = end
            continue
        if not rust:
            if c == "`":
                j = text.find("`", i + 1)
                if j < 0:
                    raise KitError("unterminated raw string at line %d" % _line_of(text, i))
                blank_string(i, j + 1)
                i = j + 1
                continue
            if c == '"':
                end = scan_quoted(i, '"', False)
                blank_string(i, end)
                i = end
                continue
            if c == "'":
                if nxt == "\\":
                    j = i + 3
                    k = text.find("'", j)
                else:
                    k = i + 2 if text[i + 2 : i + 3] == "'" else -1
                if k < 0 or "\n" in text[i:k]:
                    raise KitError("bad rune literal at line %d" % _line_of(text, i))
                blank(i, k + 1)
                i = k + 1
                continue
            i += 1
            continue
        # ---- Rust ----
        if c in "rbc" and (i == 0 or not _is_ident_char(text[i - 1])):
            j = i
            if c in "bc":
                j += 1
            if j < n and text[j] == "r":
                k = j + 1
                h = 0
                while k < n and text[k] == "#":
                    h += 1
                    k += 1
                if k < n and text[k] == '"':
                    closing = '"' + "#" * h
                    e = text.find(closing, k + 1)
                    if e < 0:
                        raise KitError("unterminated raw string at line %d" % _line_of(text, i))
                    end = e + len(closing)
                    blank_string(i, end)
                    i = end
                    continue
            elif c in "bc" and j < n and text[j] == '"':
                end = scan_quoted(j, '"', True)
                blank_string(i, end)
                i = end
                continue
        if c == '"':
            end = scan_quoted(i, '"', True)
            blank_string(i, end)
            i = end
            continue
        if c == "'":
            if nxt == "\\":
                k = text.find("'", i + 3)
                if k < 0:
                    raise KitError("bad char literal at line %d" % _line_of(text, i))
                blank(i, k + 1)
                i = k + 1
                continue
            if text[i + 2 : i + 3] == "'" and nxt != "":
                blank(i, i + 3)
                i += 3
                continue
            i += 1  # lifetime or label: not a literal
            continue
        i += 1
    return "".join(out)


def match_brace(masked: str, open_idx: int) -> int:
    """Index of the `}` matching the `{` at open_idx in already-masked text."""
    if masked[open_idx] != "{":
        raise KitError("match_brace: not at an open brace")
    depth = 0
    for j in range(open_idx, len(masked)):
        ch = masked[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
    raise KitError("unbalanced braces from line %d" % _line_of(masked, open_idx))


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------

@dataclass
class Decl:
    names: Set[str]
    start: int
    end: int
    label: str


def normalize(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"))


def hash_text(text: str) -> str:
    return hashlib.sha256(normalize(text).encode("utf-8")).hexdigest()


_GO_FUNC = re.compile(
    r"^func\b[ \t]*(?:\(([^)\n]*)\)[ \t]*)?([^\W\d]\w*)[ \t]*(?=[\[(])", re.M)
_GO_RECV = re.compile(r"^\s*(?:[^\W\d]\w*\s+)?(\*?)\s*([^\W\d]\w*)\s*(?:\[[^\]]*\])?\s*$")


def _go_body_end(masked: str, pos: int) -> int:
    n = len(masked)
    depth = 0
    i = pos
    while i < n:
        c = masked[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "{":
            before = masked[max(0, i - 12) : i].rstrip()
            if depth > 0 or before.endswith("interface") or before.endswith("struct"):
                i = match_brace(masked, i) + 1
                continue
            return match_brace(masked, i) + 1
        elif c == "\n" and depth == 0:
            return i
        i += 1
    return n


def find_go_decls(text: str) -> List[Decl]:
    masked = mask_source(text, "go")
    decls = []
    for m in _GO_FUNC.finditer(masked):
        recv, name = m.group(1), m.group(2)
        end = _go_body_end(masked, m.end())
        names = {name}
        label = name
        if recv is None:
            names.add("func " + name)
        if recv is not None:
            rm = _GO_RECV.match(recv)
            if not rm:
                raise KitError("cannot parse Go receiver %r at line %d" % (recv, _line_of(text, m.start())))
            ptr, typ = rm.group(1), rm.group(2)
            names.add("%s.%s" % (typ, name))
            if ptr:
                names.add("(*%s).%s" % (typ, name))
            label = ("(*%s).%s" if ptr else "%s.%s") % (typ, name)
        decls.append(Decl(names, m.start(), end, label))
    return decls


_RS_FN = re.compile(
    r"^([ \t]*)(?:#\[[^\]\n]*\][ \t]*)*"
    r"(?:pub(?:[ \t]*\([^)\n]*\))?[ \t]+)?"
    r"(?:(?:default|const|async|unsafe|safe|extern(?:[ \t]+\"[^\"\n]*\")?)[ \t]+)*"
    r"fn[ \t]+(?:r#)?([^\W\d]\w*)", re.M)
_RS_ITEM = re.compile(
    r"^[ \t]*(?:#\[[^\]\n]*\][ \t]*)*"
    r"(?:pub(?:[ \t]*\([^)\n]*\))?[ \t]+)?"
    r"(?:(?P<kw1>const|static)[ \t]+(?:mut[ \t]+)?(?:r#)?(?P<n1>[^\W\d]\w*)(?=[ \t]*:)"
    r"|(?P<kw2>type)[ \t]+(?:r#)?(?P<n2>[^\W\d]\w*)(?=[ \t]*(?:<|=|;|:|where\b)))", re.M)
_RS_IMPL = re.compile(r"^[ \t]*(?:#\[[^\]\n]*\][ \t]*)*(?:unsafe[ \t]+)?impl\b", re.M)
_RS_TRAIT = re.compile(
    r"^[ \t]*(?:#\[[^\]\n]*\][ \t]*)*(?:pub(?:[ \t]*\([^)\n]*\))?[ \t]+)?(?:unsafe[ \t]+)?(?:auto[ \t]+)?trait[ \t]+([^\W\d]\w*)", re.M)
_RS_MOD = re.compile(
    r"^[ \t]*(?:#\[[^\]\n]*\][ \t]*)*(?:pub(?:[ \t]*\([^)\n]*\))?[ \t]+)?mod[ \t]+([^\W\d]\w*)[ \t]*\{", re.M)


def _rs_scan_to_brace(masked: str, pos: int) -> Tuple[int, str]:
    """From pos, find the first `{` or `;` at paren/bracket/angle depth 0.
    Returns (index, char). Angle brackets are counted only outside parens and
    brackets (where `<`/`>` can only be generics; `->` is skipped), so a
    const-generic block such as `Foo<{ N }>` in a signature is stepped over
    instead of being taken as the body."""
    depth = 0
    angle = 0
    i = pos
    n = len(masked)
    while i < n:
        c = masked[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and c == "-" and masked[i + 1 : i + 2] == ">":
            i += 2
            continue
        elif depth == 0 and c == "<":
            angle += 1
        elif depth == 0 and c == ">":
            angle -= 1
            if angle < 0:
                raise KitError("unbalanced angle brackets in signature at line %d" % _line_of(masked, i))
        elif depth == 0 and angle > 0 and c == "{":
            i = match_brace(masked, i) + 1
            continue
        elif depth == 0 and c in "{;":
            return i, c
        i += 1
    raise KitError("no body or terminator found from line %d" % _line_of(masked, pos))


def _rs_item_end(masked: str, pos: int) -> int:
    """End (exclusive) of a const/static/type item: the first `;` at bracket,
    brace and paren depth 0, so multi-line array, table and struct literals are
    stepped over. Strings and comments are already masked."""
    depth = 0
    for i in range(pos, len(masked)):
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                raise KitError("unbalanced brackets in item at line %d" % _line_of(masked, pos))
        elif c == ";" and depth == 0:
            return i + 1
    raise KitError("item starting at line %d has no terminating ';'" % _line_of(masked, pos))


def _strip_angle_prefix(s: str) -> str:
    s = s.lstrip()
    if not s.startswith("<"):
        return s
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == "-" and s[i + 1 : i + 2] == ">":
            i += 2
            continue
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
            if depth == 0:
                return s[i + 1 :].lstrip()
        i += 1
    raise KitError("unbalanced generics in impl header %r" % s[:40])


def _split_top_for(s: str) -> Tuple[Optional[str], str]:
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == "-" and s[i + 1 : i + 2] == ">":
            i += 2
            continue
        if c in "<([":
            depth += 1
        elif c in ">)]":
            depth -= 1
        elif depth == 0 and re.match(r"\bfor\b", s[i:]) and (i == 0 or not _is_ident_char(s[i - 1])):
            return s[:i], s[i + 3 :]
        i += 1
    return None, s


def _norm_hdr(s: str) -> str:
    """Normalize header or symbol text: collapse whitespace and drop spaces next to
    punctuation, so `From< String >  for S` equals `From<String> for S`."""
    s = re.sub(r"\s+", " ", s.strip())
    return re.sub(r" ?([<>(),\[\]&:;]) ?", r"\1", s)


def _last_path_ident(s: str) -> Optional[str]:
    s = s.strip().lstrip("&").strip()
    s = re.sub(r"^(?:'\w+\s+)?(?:mut\s+|dyn\s+)*", "", s)
    m = re.match(r"([^\W\d]\w*(?:::[^\W\d]\w*)*)", s)
    if not m:
        return None
    return m.group(1).split("::")[-1]


def find_rust_decls(text: str) -> List[Decl]:
    masked = mask_source(text, "rust")
    # containers
    containers = []  # (kind, name, trait, body_start, body_end)
    for m in _RS_IMPL.finditer(masked):
        brace, ch = _rs_scan_to_brace(masked, m.end())
        if ch != "{":
            raise KitError("impl without body at line %d" % _line_of(text, m.start()))
        header = masked[m.end() : brace]
        header = re.split(r"\bwhere\b", header, maxsplit=1)[0]
        header = _strip_angle_prefix(header).lstrip("!").strip()
        trait_part, type_part = _split_top_for(header)
        containers.append(("impl", _last_path_ident(type_part),
                           _last_path_ident(trait_part) if trait_part else None,
                           brace, match_brace(masked, brace),
                           _norm_hdr(trait_part) if trait_part else None, _norm_hdr(type_part)))
    for m in _RS_TRAIT.finditer(masked):
        brace, ch = _rs_scan_to_brace(masked, m.end())
        if ch == "{":
            containers.append(("trait", m.group(1), None, brace, match_brace(masked, brace), None, None))
    for m in _RS_MOD.finditer(masked):
        brace = m.end() - 1
        containers.append(("mod", m.group(1), None, brace, match_brace(masked, brace), None, None))

    fns = []
    for m in _RS_FN.finditer(masked):
        name = m.group(2)
        pos, ch = _rs_scan_to_brace(masked, m.end())
        end = match_brace(masked, pos) + 1 if ch == "{" else pos + 1
        fns.append((m.start(), end, name))
    entries = [(s0, e0, n0, "fn") for s0, e0, n0 in fns]
    for m in _RS_ITEM.finditer(masked):
        kw = m.group("kw1") or m.group("kw2")
        name = m.group("n1") or m.group("n2")
        if kw == "const" and name == "_":
            continue
        if any(s2 < m.start() < e2 for s2, e2, _ in fns):
            continue  # local const/static/type inside a fn body: covered by the fn's hash
        entries.append((m.start(), _rs_item_end(masked, m.end()), name, kw))
    entries.sort()
    decls = []
    for start, end, name, kw in entries:
        if kw == "fn" and any(s2 < start and start < e2 for s2, e2, _ in fns):
            continue  # nested fn: covered by the enclosing fn's hash
        inside = [c for c in containers if c[3] < start < c[4]]
        inside.sort(key=lambda c: c[3])
        names = {name}
        label = name
        in_item = any(c[0] in ("impl", "trait") for c in inside)
        if not in_item:
            names.add(kw + " " + name)
            chain0 = [c[1] for c in inside if c[0] == "mod"]
            names.add("::".join(["crate"] + chain0 + [name]))
        if inside:
            inner = inside[-1]
            kind, cname, trait = inner[0], inner[1], inner[2]
            if kind == "impl":
                tfull, tyfull = inner[5], inner[6]
                if tfull:
                    full = "%s for %s::%s" % (tfull, tyfull, name)
                else:
                    full = "impl %s::%s" % (tyfull, name)
                    if cname:
                        names.add("impl %s::%s" % (cname, name))
                names.add(full)
                label = full
            if kind in ("impl", "trait") and cname:
                names.add("%s::%s" % (cname, name))
                if kind == "trait":
                    label = "%s::%s" % (cname, name)
                if trait and kind == "impl":
                    names.add("%s for %s::%s" % (trait, cname, name))
            elif kind == "mod":
                chain = [c[1] for c in inside if c[0] == "mod"]
                for k in range(len(chain)):
                    names.add("::".join(chain[k:] + [name]))
                label = "::".join(chain + [name])
        decls.append(Decl(names, start, end, label))
    return decls


def find_decls(path: str, text: str) -> List[Decl]:
    if path.endswith(".go"):
        return find_go_decls(text)
    if path.endswith(".rs"):
        return find_rust_decls(text)
    raise KitError("symbol extraction supports only .go and .rs files, not %s (use symbol \"*\")" % path)


def symbol_source(path: str, text: str, symbol: str) -> str:
    """Source text covered by `symbol` in the file, or raise KitError."""
    if symbol == "*":
        return text
    decls = find_decls(path, text)
    hits = [d for d in decls if symbol in d.names]
    if not hits:
        ns = _norm_hdr(symbol)
        hits = [d for d in decls if ns in {_norm_hdr(n) for n in d.names}]
    if not hits:
        raise KitError("symbol %r not found in %s" % (symbol, path))
    if len(hits) > 1:
        parts = []
        stuck = []
        for d in hits:
            others = set().union(*[o.names for o in hits if o is not d])
            uniq = sorted(d.names - others, key=lambda n: (len(n), n))
            line = _line_of(text, d.start)
            if uniq:
                parts.append("%s (line %d) is addressable as %s" % (d.label, line, " or ".join(repr(u) for u in uniq[:3])))
            else:
                stuck.append("line %d" % line)
                parts.append("%s (line %d)" % (d.label, line))
        msg = "symbol %r is ambiguous in %s: %s." % (symbol, path, "; ".join(parts))
        if stuck:
            msg += (" no qualifier separates the declarations at %s (for example cfg twins); "
                    "lock the whole file with symbol \"*\" instead." % ", ".join(stuck))
        raise KitError(msg)
    d = hits[0]
    return text[d.start : d.end]


def symbol_hash(root: Path, path: str, symbol: str) -> str:
    p = (root / path)
    if not p.is_file():
        raise KitError("file %s does not exist" % path)
    text = p.read_text(encoding="utf-8")
    return hash_text(symbol_source(path, text, symbol))


# ---------------------------------------------------------------------------
# Minimal workflow YAML reader
# ---------------------------------------------------------------------------

class YamlError(KitError):
    pass


@dataclass
class Job:
    id: str
    line: int
    has_if: bool = False
    if_expr: str = ""
    needs: Optional[List[str]] = None


@dataclass
class _Line:
    no: int
    indent: int
    text: str  # comment-stripped, right-stripped, no indent


def _strip_comment(s: str) -> str:
    quote = None
    out = []
    for i, ch in enumerate(s):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        prev = s[i - 1] if i else " "
        if ch in "\"'" and (i == 0 or prev in " \t[,{"):
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or prev in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


_BLOCK_RE = re.compile(r"(?:^|:\s+)[|>][+-]?\d?[+-]?$")
_BLOCK_ONLY = re.compile(r"^[|>][+-]?\d?[+-]?$")


def _logical_lines(text: str, source: str) -> List[_Line]:
    lines = []
    in_block = False
    threshold = 0
    docs = 0
    for no, raw in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))
        if in_block:
            if stripped == "" or indent > threshold:
                continue
            in_block = False
        if stripped == "":
            continue
        if raw[indent : indent + 1] == "\t" or "\t" in raw[:indent]:
            raise YamlError("%s:%d: tab in indentation is not supported" % (source, no))
        if indent == 0 and raw.startswith("---"):
            docs += 1
            if docs > 1:
                raise YamlError("%s:%d: multiple YAML documents are not supported" % (source, no))
            if raw.strip() != "---":
                raise YamlError("%s:%d: content after document marker is not supported" % (source, no))
            continue
        if indent == 0 and raw.startswith("..."):
            continue
        body = _strip_comment(raw[indent:])
        if body == "":
            continue
        lines.append(_Line(no, indent, body))
        rest = body
        col = indent
        dashed = False
        while rest.startswith("- ") or rest == "-":
            dashed = True
            k = 1
            while rest[k : k + 1] == " ":
                k += 1
            col += k
            rest = rest[k:]
        if _BLOCK_ONLY.match(rest) and dashed:
            in_block, threshold = True, indent
        elif _BLOCK_RE.search(rest):
            in_block, threshold = True, col
    return lines


_JOB_HEADER = re.compile(r"^(?:\"([A-Za-z0-9_-]+)\"|'([A-Za-z0-9_-]+)'|([A-Za-z0-9_-]+))\s*:\s*$")
_KEY_RE = re.compile(r"^(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z0-9_.<-]+))\s*:(?:\s+(.*))?$")


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _parse_needs_items(items: List[str], source: str, no: int) -> List[str]:
    out = []
    for it in items:
        it = _unquote(it)
        if it == "":
            continue
        if any(ch in it for ch in "{}[]:$&*!|>"):
            raise YamlError("%s:%d: unsupported needs entry %r" % (source, no, it))
        out.append(it)
    return out


def parse_workflow_jobs(text: str, source: str = "<workflow>") -> Dict[str, Job]:
    """Return {job id: Job} for the top-level jobs map of a workflow file."""
    lines = _logical_lines(text, source)
    jobs_idx = [i for i, l in enumerate(lines) if l.indent == 0 and re.match(r"^jobs\s*:", l.text)]
    if len(jobs_idx) != 1:
        raise YamlError("%s: expected exactly one top-level jobs: key, found %d" % (source, len(jobs_idx)))
    start = jobs_idx[0]
    if lines[start].text.strip() != "jobs:":
        raise YamlError("%s:%d: jobs: must be a block mapping (flow style or aliases unsupported)" % (source, lines[start].no))
    # jobs section runs until the next indent-0 line
    section = []
    for l in lines[start + 1 :]:
        if l.indent == 0:
            break
        section.append(l)
    if not section:
        raise YamlError("%s: jobs: is empty" % source)
    jindent = section[0].indent
    jobs: Dict[str, Job] = {}
    i = 0
    while i < len(section):
        l = section[i]
        if l.indent != jindent:
            raise YamlError("%s:%d: unexpected indentation inside jobs (expected %d, got %d)"
                            % (source, l.no, jindent, l.indent))
        hm = _JOB_HEADER.match(l.text)
        if not hm:
            raise YamlError("%s:%d: cannot parse job header %r (anchors, aliases and flow style are unsupported)"
                            % (source, l.no, l.text))
        jid = hm.group(1) or hm.group(2) or hm.group(3)
        if jid in jobs:
            raise YamlError("%s:%d: duplicate job id %r" % (source, l.no, jid))
        j = i + 1
        body = []
        while j < len(section) and section[j].indent > jindent:
            body.append(section[j])
            j += 1
        if not body:
            raise YamlError("%s:%d: job %r has no body" % (source, l.no, jid))
        job = Job(jid, l.no)
        kindent = body[0].indent
        k = 0
        compact_ok = False  # a `- ` item at the key indent right after a key with no value
        while k < len(body):
            b = body[k]
            if b.indent < kindent:
                raise YamlError("%s:%d: inconsistent indentation in job %r" % (source, b.no, jid))
            if b.indent != kindent:
                k += 1
                continue
            if b.text.startswith("- ") or b.text == "-":
                if compact_ok:
                    # compact block sequence (for example `steps:` then `- uses:` at the
                    # same indent); its items are not job-level keys
                    k += 1
                    continue
                raise YamlError("%s:%d: unexpected sequence item in job %r (a `- ` line at the key indent is "
                                "accepted only right after a key with no value, other than needs and if)"
                                % (source, b.no, jid))
            if b.text.startswith("<<") or b.text.startswith("*") or b.text.startswith("&"):
                raise YamlError("%s:%d: YAML merge keys, anchors and aliases are not supported" % (source, b.no))
            km = _KEY_RE.match(b.text)
            if not km:
                raise YamlError("%s:%d: cannot parse key line %r in job %r" % (source, b.no, b.text, jid))
            key = km.group(1) or km.group(2) or km.group(3)
            val = (km.group(4) or "").strip()
            compact_ok = val == "" and key not in ("needs", "if")
            if val.startswith("&") or val.startswith("*") or val.startswith("!"):
                raise YamlError("%s:%d: anchors, aliases and tags are not supported (%r)" % (source, b.no, val))
            if key == "if":
                if job.has_if:
                    raise YamlError("%s:%d: duplicate if in job %r" % (source, b.no, jid))
                has_children = k + 1 < len(body) and body[k + 1].indent > kindent
                if val == "" and not has_children:
                    raise YamlError("%s:%d: empty if in job %r" % (source, b.no, jid))
                job.has_if = True
                job.if_expr = val
            elif key == "needs":
                if job.needs is not None:
                    raise YamlError("%s:%d: duplicate needs in job %r" % (source, b.no, jid))
                if val.startswith("["):
                    buf = val
                    kk = k
                    while "]" not in buf:
                        kk += 1
                        if kk >= len(body):
                            raise YamlError("%s:%d: unterminated needs list in job %r" % (source, b.no, jid))
                        buf += " " + body[kk].text
                    close = buf.index("]")
                    if buf[close + 1 :].strip():
                        raise YamlError("%s:%d: trailing text after needs list in job %r" % (source, b.no, jid))
                    job.needs = _parse_needs_items(buf[1:close].split(","), source, b.no)
                elif val == "":
                    items = []
                    kk = k + 1
                    while kk < len(body) and body[kk].indent > kindent:
                        t = body[kk].text
                        if not (t.startswith("- ") or t == "-"):
                            raise YamlError("%s:%d: needs block list entry expected, got %r" % (source, body[kk].no, t))
                        items.append(t[2:])
                        kk += 1
                    if not items:
                        raise YamlError("%s:%d: empty needs in job %r (block list items must be indented deeper than the `needs:` key; "
                                        "a list at the same indent as the key is not supported)" % (source, b.no, jid))
                    job.needs = _parse_needs_items(items, source, b.no)
                else:
                    job.needs = _parse_needs_items([val], source, b.no)
            k += 1
        jobs[jid] = job
        i = j
    return jobs


def load_workflows(root: Path) -> Tuple[Dict[str, Dict[str, Job]], Dict[str, str]]:
    """Parse every workflow. Returns (parsed, errors) keyed by relative path."""
    parsed: Dict[str, Dict[str, Job]] = {}
    errors: Dict[str, str] = {}
    wdir = root / ".github" / "workflows"
    if not wdir.is_dir():
        return parsed, errors
    for p in sorted(list(wdir.glob("*.yml")) + list(wdir.glob("*.yaml"))):
        rel = p.relative_to(root).as_posix()
        try:
            parsed[rel] = parse_workflow_jobs(p.read_text(encoding="utf-8"), rel)
        except KitError as e:
            errors[rel] = str(e)
    return parsed, errors


# ---------------------------------------------------------------------------
# claims.json
# ---------------------------------------------------------------------------

TOP_KEYS = {"schema", "$comment", "overclaim_denylist", "ci_required_exempt", "ci_required_conditional", "mutants", "claims",
            "formal_docs", "scratch_cache_dirs"}
CLAIM_KEYS = {"id", "statement", "method", "artifacts", "gates", "detector", "covers", "mutants",
              "evidence_run", "does_not_establish", "detector_kind", "$comment"}
DETECTOR_KINDS = ("auto", "cargo", "go", "custom")
DEFAULT_DOCS = ["docs/dev/FORMAL.md"]


def load_claims(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise KitError("claims file %s not found" % path)
    except json.JSONDecodeError as e:
        raise KitError("claims file %s is not valid JSON: %s" % (path, e))
    if not isinstance(data, dict):
        raise KitError("claims file top level must be an object")
    return data


def _safe_rel(p: str) -> bool:
    return bool(p) and not p.startswith("/") and ".." not in Path(p).parts


def validate_schema(data: dict) -> List[str]:
    errs: List[str] = []
    if data.get("schema") != SCHEMA_VERSION:
        errs.append("schema must be %d, got %r" % (SCHEMA_VERSION, data.get("schema")))
    for k in data:
        if k not in TOP_KEYS:
            errs.append("unknown top-level key %r" % k)
    claims = data.get("claims")
    if not isinstance(claims, list) or not claims:
        errs.append("claims must be a non-empty list")
        claims = []
    seen: Set[str] = set()
    for idx, c in enumerate(claims):
        where = "claims[%d]" % idx
        if not isinstance(c, dict):
            errs.append("%s must be an object" % where)
            continue
        cid = c.get("id")
        if not isinstance(cid, str) or not ID_RE.match(cid):
            errs.append("%s: id must match %s" % (where, ID_RE.pattern))
        else:
            where = "claim %s" % cid
            if cid in seen:
                errs.append("duplicate claim id %s" % cid)
            seen.add(cid)
        for k in c:
            if k not in CLAIM_KEYS:
                errs.append("%s: unknown key %r" % (where, k))
        for k in ("statement", "detector", "does_not_establish"):
            if not isinstance(c.get(k), str) or not c.get(k).strip():
                errs.append("%s: %s must be a non-empty string" % (where, k))
        if c.get("method") not in METHODS:
            errs.append("%s: method must be one of %s" % (where, ", ".join(METHODS)))
        for k, nonempty in (("artifacts", False), ("gates", True), ("mutants", True)):
            v = c.get(k)
            if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
                errs.append("%s: %s must be a list of non-empty strings" % (where, k))
            elif nonempty and not v:
                errs.append("%s: %s must not be empty" % (where, k))
            elif k == "artifacts":
                for a in v:
                    if not _safe_rel(a):
                        errs.append("%s: artifact path %r must be relative and stay inside the repo" % (where, a))
            elif k == "mutants":
                for m in v:
                    if not MUTANT_ID_RE.match(m):
                        errs.append("%s: bad mutant id %r" % (where, m))
        cov = c.get("covers")
        if not isinstance(cov, list) or not cov:
            errs.append("%s: covers must be a non-empty list" % where)
        else:
            for ci, e in enumerate(cov):
                if (not isinstance(e, dict) or set(e) - {"path", "symbol", "sha256"}
                        or not isinstance(e.get("path"), str) or not isinstance(e.get("symbol"), str)
                        or not isinstance(e.get("sha256"), str)):
                    errs.append("%s: covers[%d] must be {path, symbol, sha256} strings" % (where, ci))
                elif not _safe_rel(e["path"]) or not e["symbol"]:
                    errs.append("%s: covers[%d] has an unsafe path or empty symbol" % (where, ci))
        if "detector_kind" in c and c["detector_kind"] not in DETECTOR_KINDS:
            errs.append("%s: detector_kind must be one of %s" % (where, ", ".join(DETECTOR_KINDS)))
        ev = c.get("evidence_run")
        if ev is not None and not (isinstance(ev, int) and not isinstance(ev, bool)) and not (isinstance(ev, str) and ev.isdigit()):
            errs.append("%s: evidence_run must be a GitHub run id (digits)" % where)
    dl = data.get("overclaim_denylist", {})
    if not isinstance(dl, dict) or set(dl) - {"phrases", "globs"} or \
            any(not isinstance(dl.get(k, []), list) or not all(isinstance(x, str) and x for x in dl.get(k, []))
                for k in ("phrases", "globs")):
        errs.append("overclaim_denylist must be {phrases: [str], globs: [str]}")
    ex = data.get("ci_required_exempt", [])
    if not isinstance(ex, list) or any(
            not isinstance(e, dict) or set(e) != {"job", "reason"} or not isinstance(e["job"], str)
            or not isinstance(e["reason"], str) or not e["reason"].strip() for e in ex):
        errs.append("ci_required_exempt must be a list of {job, reason} with a non-empty reason")
    cc = data.get("ci_required_conditional", [])
    if not isinstance(cc, list) or any(
            not isinstance(e, dict) or set(e) != {"job", "reason"} or not isinstance(e["job"], str)
            or not isinstance(e["reason"], str) or not e["reason"].strip() for e in cc):
        errs.append("ci_required_conditional must be a list of {job, reason} with a non-empty reason")
    for key in ("formal_docs", "scratch_cache_dirs"):
        v = data.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and _safe_rel(x) for x in v):
            errs.append("%s must be a list of relative paths inside the repo" % key)
    mm = data.get("mutants", {})
    if not isinstance(mm, dict):
        errs.append("mutants must be a map {id: {tier, claim, detector?}}")
    else:
        for mid, e in mm.items():
            if not MUTANT_ID_RE.match(mid):
                errs.append("bad mutant id %r in mutants map" % mid)
            if not isinstance(e, dict) or set(e) - {"tier", "claim", "detector", "detector_kind"}:
                errs.append("mutants[%s] must be an object with tier/claim/detector/detector_kind" % mid)
                continue
            if "tier" in e and e["tier"] not in TIERS:
                errs.append("mutants[%s].tier must be fast or full" % mid)
            if "detector" in e and (not isinstance(e["detector"], str) or not e["detector"].strip()):
                errs.append("mutants[%s].detector must be a non-empty string" % mid)
            if "detector_kind" in e and e["detector_kind"] not in DETECTOR_KINDS:
                errs.append("mutants[%s].detector_kind must be one of %s" % (mid, ", ".join(DETECTOR_KINDS)))
            if "claim" in e and not isinstance(e["claim"], str):
                errs.append("mutants[%s].claim must be a claim id" % mid)
    return errs


@dataclass
class MutantSpec:
    id: str
    tier: str
    claim: str
    detector: str
    kind: str = "auto"


def resolve_mutants(data: dict) -> Tuple[List[MutantSpec], List[str]]:
    """Resolve each mutant id to (tier, claim, detector). Returns (specs, errors)."""
    errs: List[str] = []
    claims = {c["id"]: c for c in data.get("claims", []) if isinstance(c, dict) and "id" in c}
    mm = data.get("mutants", {}) if isinstance(data.get("mutants", {}), dict) else {}
    owners: Dict[str, List[str]] = {}
    for cid, c in claims.items():
        for m in c.get("mutants", []) if isinstance(c.get("mutants"), list) else []:
            owners.setdefault(m, []).append(cid)
    for mid, e in mm.items():
        if mid not in owners:
            errs.append("mutants map entry %s is not listed by any claim" % mid)
        if isinstance(e, dict) and "claim" in e:
            if e["claim"] not in claims:
                errs.append("mutants[%s].claim %r is not a claim id" % (mid, e["claim"]))
            elif mid not in owners or e["claim"] not in owners[mid]:
                errs.append("mutants[%s].claim %s does not list that mutant" % (mid, e["claim"]))
    specs = []
    for mid in sorted(owners):
        e = mm.get(mid, {}) if isinstance(mm.get(mid, {}), dict) else {}
        cl = e.get("claim")
        if cl is None:
            if len(owners[mid]) > 1:
                errs.append("mutant %s is listed by several claims (%s); set claim in the mutants map"
                            % (mid, ", ".join(owners[mid])))
                continue
            cl = owners[mid][0]
        if cl not in claims:
            continue
        det = e.get("detector") or claims[cl].get("detector", "")
        # the kind describes the command that runs: a mutant with its own detector does not inherit the
        # claim's kind (a custom proof claim would otherwise exempt an overriding `cargo test` from the guard)
        kind = e.get("detector_kind") or ("auto" if e.get("detector") else claims[cl].get("detector_kind", "auto"))
        specs.append(MutantSpec(mid, e.get("tier", "full"), cl, det, kind))
    return specs, errs


def git_toplevel(cwd: Path) -> Path:
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=str(cwd), capture_output=True,
                             text=True, check=True).stdout.strip()
        return Path(out)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return cwd
