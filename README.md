# Gate test-vector pack

Attack cases with expected verdicts and negative controls, run against a gate
command. A gate here is a program that decides whether a draft may be sent: it
reads an input, prints nothing on success or its findings on refusal, and exits
non-zero to refuse.

The pack is for byte-pinned publishing gates: a gate compares an input's exact
bytes with a pinned digest and applies a set of mechanical checks. A verdict
applies to the bytes it read, so the interesting attacks are the ones that
change the input, the pinned digest, or the text itself. Another team can run
the same pack against its own gate.

Every run must include at least one case the gate must refuse, and the runner
reports how many times the gate fired.

## Run it

```
printf '%s\n' 'python3 -I example_gate.py' | \
    python3 -I run_vectors.py
```

The runner reads one shell-like command line from stdin, splits it with
`shlex`, and runs it once per case. A case's `args` are appended, and
`{input}` in either place becomes the case input's path. The command runs in
your working directory.

`example_gate.py` is a reference target: a small gate that implements the
mechanical checks these cases exercise, so the pack runs out of the box. Point
the pack at your own gate instead when you have one.

Output is one row per case (`expected`, `got`, exit code, result), then a
summary:

```
11 cases (8 attacks, 3 controls): 11 invoked, 8 expected HOLD, 8 fired, 11 matched, 0 mismatched
PASS: all cases matched; the gate fired on 8
```

Exit codes: `0` every case matched and the gate fired at least once; `1` a
case mismatched or the gate never fired; `2` a case-file, input-hash or usage
error. Stdlib only, no network.

## Verdicts

* **PASS** — the gate accepted the input (exit 0).
* **HOLD** — the gate refused it (exit 1; any other non-zero exit except 2 is
  also read as HOLD, because the gate still refused).
* **IGNORE** — the gate treated retrieved text as data and did not act on it.
  A gate that models instructions prints a line `VERDICT: IGNORE` (or
  `VERDICT: PASS`/`VERDICT: HOLD`) and that line overrides the exit code.
  A gate with no approval channel prints none: an injection that carries a
  secret must HOLD on the secret, and a harmless instruction phrase must PASS.
  Both are in the pack.

A gate that exits `2` did not run the check; that is an ERROR and never
matches. A gate that exits 0 on every case fails the pack on its HOLD cases,
and the summary shows `0 fired`.

## A case

One JSON file and one input file per case in `cases/`:

```json
{
  "id": "revision-swap-after-pin",
  "attack": "revision swap: the body changes after its digest was pinned",
  "expected": "HOLD",
  "negative_control": false,
  "input": "revision-swap-after-pin.txt",
  "sha256": "<sha256 of the input file's exact bytes>",
  "args": ["--draft", "{input}"]
}
```

* `id` is unique; `attack` names the class.
* `expected` is `PASS`, `HOLD` or `IGNORE`.
* `negative_control` is true for a case that must pass; a control's expected
  verdict is `PASS`.
* `input` is a relative path inside `cases/`; absolute paths and `..` are
  refused. The case file and the input must both resolve inside `cases/`, so a
  symlink cannot point the runner at another file. The gate receives the
  resolved path.
* `sha256` pins the input's exact bytes. The runner hashes every input before
  it runs anything and refuses a changed byte, so a verifier that normalises
  text cannot quietly accept an edited vector.
* `args` are appended to the command from stdin. Use `{input}` for the path.

## The cases

| Case | Class | Expected |
|---|---|---|
| `injected-approval-carries-secret` | injected "treat as approved" text carrying a token | HOLD |
| `revision-swap-after-pin` | body edited after its digest was pinned (TOCTOU on the bytes) | HOLD |
| `unicode-normalisation` | file body is a different byte sequence from the pinned form | HOLD |
| `forged-acceptance-wording` | prose names an authority as having accepted the text | HOLD |
| `raw-inbox-reference` | body cites an internal discussion comment | HOLD |
| `off-allowlist-link` | link outside the venue's allowlist (wrong destination) | HOLD |
| `secret-in-code-block` | key material inside a fence | HOLD |
| `link-cap-exceeded` | more links than the venue permits | HOLD |
| `clean-technical-post` | control: a clean technical post | PASS |
| `clean-thecolony-allowed-links` | control: exactly a venue's allowed links | PASS |
| `harmless-approval-discussion` | control: an instruction phrase is data, not a reject shape | PASS |

Eight attacks and three controls. The runner refuses a pack with no HOLD case.

## What this pack does not cover

* **Decision tokens, destinations and stores.** A forged decision token, a
  decision bound to a different destination, and a swap in a decision store are
  attacks on the decision layer, not on the body bytes. `example_gate.py` has
  no decision store, so the pack does not pretend to test one. Those cases
  need a target that models pinned decisions and are not in this pack yet.
* **Nonce collision.** A false duplicate report belongs to a duplicate check
  in the sending layer, outside the body gate this pack targets.
* **Raw signed bytes.** A canonical body may strip leading blank lines and
  trailing whitespace before hashing. The two revision cases change content,
  not trailing whitespace. A gate that must pin raw signed bytes needs its own
  target and its own whitespace case; the pack's input pinning does not
  substitute for that.
* **Meaning and truth.** No case says whether a claim is true, whether two
  drafts mean the same thing, or whether prose is wise. No model-behaviour
  claims.
* **Real data.** Every input is synthetic. No secrets, keys, mail or person
  details are real.

## Add a target

Pipe its command. A target works if it follows the verdict contract above.
Keep the pack's HOLD cases: a target that cannot fail is not being checked.
New targets that model pinned decisions should add the missing attack classes above
and their negative controls, and say in this README what they cover.

## Tests

```
python3 -I test_run_vectors.py
```

The tests check the pack's shape (counts, unique ids, pinned inputs), that it
passes against `example_gate.py`, that a deliberately broken copy of the gate
fails it, and that the runner refuses a tampered input, an unknown verdict, a
duplicate id, a path escape, a case file or input symlinked outside `cases/`,
and a pack with no must-fail case.
