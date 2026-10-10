#!/usr/bin/env python3
"""Generate vectors/outbox-signature.v1.json: golden vectors for vultrino's signed outbox.

vultrino signs every outbox delivery body with `Govder-Signature: sha256=<hex>`, where hex is the
lowercase hex of HMAC-SHA256(key, body) over the EXACT body bytes. Two seams use it:
  * relationship A/K (the meter feed): leria polls GET /api/v1/events and verifies each event;
  * relationship E (approval pushes): govder's approval webhook verifies the pushed body;
govder's activity feed also verifies the polled feed when it holds the key.

This is an INDEPENDENT reference (Python standard library only); it shares no code with
vultrino's sign_body (src/outbox.rs) or any verifier. Run from the repo root:
  python3 scripts/vectors/gen_outbox_signature.py > vectors/outbox-signature.v1.json
The output is deterministic. Consumers keep byte-identical copies pinned in vectors/vectors.lock.
"""
import base64
import hashlib
import hmac
import json
import random
import sys

SPEC = [
    "Header (push) or page field (poll): Govder-Signature = 'sha256=' + 64 lowercase hex characters of HMAC-SHA256(key, body).",
    "body is the EXACT delivery body bytes: for a push, the HTTP request body; for a poll page, the raw bytes of the event's 'body' JSON value as they appear in the page (a consumer must not re-marshal it).",
    "The delivery body carries 'sequence' and 'subject' itself (src/outbox.rs delivery_body), so the per-event ordering metadata is inside the signed bytes. The page's next_cursor is not signed.",
    "A verifier accepts iff the value is exactly 'sha256=' followed by 64 characters of [0-9a-f] and equals the HMAC under one accepted key (constant-time compare). Uppercase hex, another prefix, surrounding whitespace, or any other length is malformed and rejected.",
]

KEY = "outbox-signature-vector-key-A-0001"
OTHER = "outbox-signature-vector-key-other"


def sig(key, body):
    return "sha256=" + hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def b64(b):
    return base64.b64encode(b).decode("ascii")


vectors = []


def add(vid, note, body, signature, expect, reason=None):
    v = {"id": vid, "note": note, "key": KEY, "body_b64": b64(body), "signature": signature, "expect": expect}
    if reason:
        v["reason"] = reason
    vectors.append(v)


METER = (b'{"created_at":"2026-01-02T03:04:05.123456Z","event":"meter.observed","payload":{"amount":1,'
         b'"asset":"api-calls","confidence":"low","correlation_id":"req-01","cost_source":"gateway-observed",'
         b'"dims":{"credential":"openai","model":"gpt-5.4-mini","tenant":"acme"},"event_id":"req-01",'
         b'"occurred_at":"2026-01-02T03:04:05Z","principal":"agent:acme/support-bot"},"sequence":42,'
         b'"subject":"agent:acme/support-bot"}')
APPROVAL = (b'{"created_at":"2026-01-02T03:04:06Z","event":"approval.decided","payload":{"approval_id":"appr_01HZX",'
            b'"approver":"verified:sub-alice","outcome":"approved","tenant":"acme"},"sequence":43,'
            b'"subject":"approval:appr_01HZX"}')
UNICODE = '{"event":"meter.observed","payload":{"principal":"café 中 \U0001f600"},"sequence":7,"subject":"s"}'.encode("utf-8")

add("meter-observed", "a meter.observed delivery body (relationship A/K)", METER, sig(KEY, METER), "accept")
add("approval-decided", "an approval delivery body (relationship E)", APPROVAL, sig(KEY, APPROVAL), "accept")
add("unicode-body", "UTF-8 body bytes are signed as they are", UNICODE, sig(KEY, UNICODE), "accept")
add("empty-body", "the empty body", b"", sig(KEY, b""), "accept")
add("binary-body", "arbitrary bytes", bytes([0, 255, 10, 13, 34]), sig(KEY, bytes([0, 255, 10, 13, 34])), "accept")

good = sig(KEY, METER)
add("uppercase-hex", "uppercase hex digits are malformed", METER, "sha256=" + good[7:].upper(), "reject", "malformed")
add("prefix-uppercase", "the prefix is lowercase", METER, "SHA256=" + good[7:], "reject", "malformed")
add("prefix-colon", "'sha256:' is not the prefix", METER, "sha256:" + good[7:], "reject", "malformed")
add("no-prefix", "bare hex", METER, good[7:], "reject", "malformed")
add("leading-space", "surrounding whitespace is not trimmed", METER, " " + good, "reject", "malformed")
add("trailing-newline", "surrounding whitespace is not trimmed", METER, good + "\n", "reject", "malformed")
add("hex-63", "one hex digit short", METER, good[:-1], "reject", "malformed")
add("hex-65", "one hex digit extra", METER, good + "0", "reject", "malformed")
add("empty-signature", "no signature", METER, "", "reject", "malformed")
add("prefix-only", "prefix without digest", METER, "sha256=", "reject", "malformed")
add("wrong-key", "signed with another key", METER, sig(OTHER, METER), "reject", "bad_mac")
add("body-one-byte", "the sequence in the body changed 42 -> 43", METER.replace(b'"sequence":42', b'"sequence":43'),
    good, "reject", "bad_mac")
add("body-trailing-newline", "a byte appended to the body", METER + b"\n", good, "reject", "bad_mac")

rng = random.Random(20261009)
for i in range(32):
    body = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 1, 7, 33, 120])))
    s = sig(KEY, body)
    add("corpus-%02d" % i, "seeded corpus: accept", body, s, "accept")
    pos = rng.randrange(7, len(s))
    repl = rng.choice([c for c in "0123456789abcdef" if c != s[pos]])
    add("corpus-%02d-mutant" % i, "seeded corpus: one hex digit changed at %d" % pos, body,
        s[:pos] + repl + s[pos + 1:], "reject", "bad_mac")

# Poll pages: the consumer must verify the raw bytes of each event's "body" value.
pages = []
SPACED = b'{ "sequence": 9, "subject": "agent:acme/x", "event": "meter.observed", "payload": {"principal": "caf\\u00e9"} }'
CANON = json.dumps(json.loads(SPACED.decode()), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def page(events):
    parts = ['{"body":%s,"signature":"%s"}' % (b.decode("utf-8"), s) for (b, s) in events]
    return ('{"events":[' + ",".join(parts) + '],"next_cursor":9}').encode("utf-8")


pages.append({"id": "page-raw-bytes", "note": "the body is signed as it appears (spaces, escaped unicode, unsorted keys): accept",
              "key": KEY, "page_b64": b64(page([(SPACED, sig(KEY, SPACED))])), "expect": ["accept"]})
pages.append({"id": "page-remarshaled-signature", "note": "signed over a re-marshaled form of the body, not its bytes: reject",
              "key": KEY, "page_b64": b64(page([(SPACED, sig(KEY, CANON))])), "expect": ["reject"]})
pages.append({"id": "page-two-events", "note": "two events: accept, then a tampered one: reject",
              "key": KEY, "page_b64": b64(page([(METER, sig(KEY, METER)), (APPROVAL, sig(KEY, METER))])),
              "expect": ["accept", "reject"]})

out = {
    "format": "feir.outbox-signature",
    "version": 1,
    "owner": "vultrino",
    "header": "Govder-Signature",
    "generator": "scripts/vectors/gen_outbox_signature.py (independent Python reference, stdlib only)",
    "spec": SPEC,
    "consumers": [
        "vultrino src/outbox.rs sign_body (producer)",
        "leria internal/gatewaypoll (meter feed, A/K) via internal/outbox VerifyBodyAny",
        "govder internal/enforce ApprovalReceiver.VerifySignature (approval webhook, E) and internal/runtime verifyOutboxSig (activity feed)",
    ],
    "vectors": vectors,
    "pages": pages,
}
json.dump(out, sys.stdout, indent=1, ensure_ascii=True)
sys.stdout.write("\n")
