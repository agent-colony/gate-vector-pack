#!/usr/bin/env python3
"""A small example gate for the vector pack.

The pack does not ship the gate it was built against; it ships cases with
pinned expected verdicts. This file is a reference target that implements the
same mechanical checks the cases exercise, so the pack can be run end to end:

  * secret and key material, including inside code fences;
  * link count against a venue cap;
  * a link allowlist for a venue that has one;
  * shapes of internal references (discussion comment ids, memory paths);
  * prose that names an authority as having accepted the text;
  * a draft's front-matter ``sha256`` must equal the digest of its body.

It is deliberately small and is not a complete publishing gate. Point the pack
at your own gate instead; this file shows the verdict contract (exit 0 PASS,
exit 1 HOLD, exit 2 ERROR) in about a hundred lines.

Usage:
    python3 -I example_gate.py --body body.txt --venue forumforagents
    python3 -I example_gate.py --draft draft.md

Exit codes: 0 every check passed, 1 a check failed, 2 usage or file error.
Stdlib only; no network.
"""

import argparse
import hashlib
import re
import sys

MAX_LINKS = {"forumforagents": 3, "thecolony": 10}
DEFAULT_MAX_LINKS = 3

# A venue's own rule about which destinations are allowed. Each entry is a
# complete URL: scheme, host and path must match exactly.
ALLOWED_LINKS = {
    "thecolony": frozenset(
        {
            "https://github.com/runkora/kora",
            "https://runkora.io",
        }
    ),
}

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

SECRET_PATTERNS = (
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("a GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("a GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("an API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("an AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("a Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("a bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
)

INTERNAL_SHAPES = (
    ("a discussion comment id", re.compile(r"\bdiscussioncomment-\d+|\bDC_kwDO")),
    ("a memory path", re.compile(r"(?<![\w./])memory/[\w./-]+\.md\b")),
    ("an inbox reference", re.compile(r"\bInbox:\s*\w+")),
)

# Prose that presents a named person or role as having accepted the text.
CLEARANCE_RE = re.compile(
    r"(?i)\b(?:accepted|approved|signed off)\s+by\s+[A-Z][\w.-]+"
)

FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)
SHA_LINE_RE = re.compile(r"(?m)^sha256:\s*([0-9a-f]{64})\s*$")


def body_findings(text, venue):
    """Return a list of findings for a plain body."""
    findings = []

    for label, regex in SECRET_PATTERNS:
        match = regex.search(text)
        if match:
            fragment = match.group(0)[:40]
            findings.append("secret: found %s (%r)" % (label, fragment))

    urls = [url.rstrip(".,;:!?") for url in URL_RE.findall(text)]
    cap = MAX_LINKS.get(venue, DEFAULT_MAX_LINKS)
    if len(urls) > cap:
        findings.append("link cap: %d links, venue %s permits %d" % (len(urls), venue, cap))
    allowed = ALLOWED_LINKS.get(venue)
    if allowed:
        for url in urls:
            if url not in allowed:
                findings.append("wrong destination: %r is not on the %s allowlist" % (url, venue))

    for label, regex in INTERNAL_SHAPES:
        if regex.search(text):
            findings.append("internal shape: %s" % label)

    if CLEARANCE_RE.search(text):
        findings.append("forged acceptance: prose names an authority as having accepted the text")

    return findings


def draft_findings(text):
    """Check a draft with front matter and a pinned body hash."""
    findings = []
    match = FRONT_MATTER_RE.match(text)
    if not match:
        return ["draft: no front matter block"]
    front, body = match.group(1), match.group(2)
    pinned = SHA_LINE_RE.search(front)
    if not pinned:
        return ["draft: front matter has no sha256"]
    digest = hashlib.sha256(body.lstrip("\n").encode("utf-8")).hexdigest()
    if pinned.group(1) != digest:
        findings.append(
            "revision swap: front matter pins %s, body hashes to %s"
            % (pinned.group(1), digest)
        )
    findings.extend(body_findings(body, "forumforagents"))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Example gate for the vector pack.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--body", help="body file to check")
    group.add_argument("--draft", help="draft file with front matter to check")
    parser.add_argument("--venue", default="forumforagents", help="venue key")
    args = parser.parse_args(argv)

    try:
        text = open(args.body or args.draft, encoding="utf-8").read()
    except OSError as exc:
        print("ERROR: cannot read input: %s" % exc, file=sys.stderr)
        return 2

    if args.draft:
        findings = draft_findings(text)
    else:
        findings = body_findings(text, args.venue)

    if findings:
        for finding in findings:
            print("HOLD: %s" % finding)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
