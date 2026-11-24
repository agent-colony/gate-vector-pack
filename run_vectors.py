#!/usr/bin/env python3
"""Run one gate command against the gate test-vector pack.

A case is a JSON file in `cases/` with an attack, an input, the sha256 of that
input's exact bytes, the expected verdict and the arguments that feed the input
to the gate. The runner reads the gate command from stdin, runs it once per
case, and prints expected against got.

The gate command is a shell-like line, split with `shlex`:

    printf '%s\n' 'python3 -I example_gate.py' | \
        python3 -I run_vectors.py

Each case's `args` are appended to that command. `{input}` in either place is
replaced with the case input's path. The command runs in the caller's working
directory, so relative paths behave as they would if typed.

Verdict contract:

  * exit 0 is PASS: the gate accepted the input;
  * exit 1 is HOLD: the gate refused it;
  * exit 2 is ERROR: the gate could not run the check;
  * any other non-zero exit is HOLD (a gate that refuses with another code
    still refused), and a negative exit (killed by a signal) is ERROR;
  * a line `VERDICT: PASS|HOLD|IGNORE` on the gate's output overrides the exit
    code. A gate that models instructions uses this to say IGNORE.

Every run must contain at least one HOLD case, and the summary reports how many
cases made the gate fire (a call count in the sense of `gate-must-fail`). A
pack with no must-fail case, or a gate that never fires, fails closed.

Input bytes are pinned. Before running anything the runner hashes each input
file; a changed byte is refused, so a verifier that normalises text cannot
quietly accept an edited vector. Every case file and input must resolve inside
the cases directory; a symlink that points outside it is refused, so a case
cannot redirect the gate at another file.

Exit codes: 0 every case matched and the gate fired at least once; 1 a case
mismatched or the gate never fired; 2 a usage, case-file or input-hash error.
Stdlib only; no network.

Usage:
    printf '%s\n' 'python3 -I example_gate.py' | \
        python3 -I run_vectors.py
    python3 -I run_vectors.py --cases cases
"""

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

EXPECTED = ("PASS", "HOLD", "IGNORE")
CASE_KEYS = ("id", "attack", "expected", "negative_control", "input", "sha256")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERDICT_LINE_RE = re.compile(r"^VERDICT:\s*(PASS|HOLD|IGNORE)\s*$", re.MULTILINE)


def default_cases_dir():
    return Path(__file__).resolve().parent / "cases"


def load_cases(cases_dir):
    """Return (cases, errors). Reads and hashes every case before any run."""
    cases = []
    errors = []
    seen = set()
    cases_root = Path(cases_dir).resolve()
    files = sorted(Path(cases_dir).glob("*.json"))
    if not files:
        return [], ["no case files in %s" % cases_dir]

    for path in files:
        name = path.name
        try:
            path.resolve().relative_to(cases_root)
        except (OSError, ValueError):
            errors.append(
                "%s: case file must resolve inside the cases directory" % name
            )
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append("%s: cannot read case: %s" % (name, exc))
            continue
        if not isinstance(data, dict):
            errors.append("%s: case must be a JSON object" % name)
            continue
        missing = [key for key in CASE_KEYS if key not in data]
        if missing:
            errors.append("%s: missing key(s): %s" % (name, ", ".join(missing)))
            continue

        case_id = data["id"]
        if not isinstance(case_id, str) or not case_id.strip():
            errors.append("%s: id must be a non-empty string" % name)
            continue
        if case_id in seen:
            errors.append("%s: duplicate id %r" % (name, case_id))
            continue
        seen.add(case_id)

        if not isinstance(data["attack"], str) or not data["attack"].strip():
            errors.append("%s: attack must be a non-empty string" % name)
            continue
        if data["expected"] not in EXPECTED:
            errors.append(
                "%s: expected must be one of %s, not %r"
                % (name, ", ".join(EXPECTED), data["expected"])
            )
            continue
        if not isinstance(data["negative_control"], bool):
            errors.append("%s: negative_control must be true or false" % name)
            continue

        input_value = data["input"]
        if not isinstance(input_value, str) or not input_value.strip():
            errors.append("%s: input must be a non-empty string" % name)
            continue
        input_path = Path(cases_dir) / input_value
        if Path(input_value).is_absolute() or ".." in Path(input_value).parts:
            errors.append(
                "%s: input must be a relative path inside the cases directory"
                % name
            )
            continue
        try:
            input_path = input_path.resolve()
            input_path.relative_to(cases_root)
        except (OSError, ValueError):
            errors.append(
                "%s: input %s must resolve inside the cases directory"
                % (name, input_value)
            )
            continue
        try:
            raw = input_path.read_bytes()
        except OSError as exc:
            errors.append("%s: cannot read input %s: %s" % (name, input_path, exc))
            continue

        digest = data["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.match(digest):
            errors.append("%s: sha256 must be 64 lowercase hex characters" % name)
            continue
        actual = hashlib.sha256(raw).hexdigest()
        if actual != digest:
            errors.append(
                "%s: input %s hashes to %s but the case pins %s"
                % (name, input_value, actual, digest)
            )
            continue

        args = data.get("args", [])
        if not isinstance(args, list) or not all(
            isinstance(arg, str) for arg in args
        ):
            errors.append("%s: args must be a list of strings" % name)
            continue

        cases.append(
            {
                "id": case_id,
                "attack": data["attack"],
                "expected": data["expected"],
                "negative_control": data["negative_control"],
                "input": str(input_path),
                "args": args,
            }
        )

    if not any(case["expected"] == "HOLD" for case in cases) and not errors:
        errors.append(
            "no HOLD case: a pack must contain at least one case the gate "
            "must refuse (gate-must-fail)"
        )
    return cases, errors


def classify(returncode, output):
    """Return the verdict a gate's exit code and output amount to."""
    match = VERDICT_LINE_RE.search(output)
    if match:
        return match.group(1)
    if returncode is None:
        return "ERROR"
    if returncode == 0:
        return "PASS"
    if returncode == 1:
        return "HOLD"
    if returncode == 2:
        return "ERROR"
    if returncode < 0:
        return "ERROR"
    return "HOLD"


def run_case(tokens, case, timeout):
    """Run the gate once. Return (verdict, exit_code, note)."""
    argv = []
    for token in tokens:
        argv.append(token.replace("{input}", case["input"]))
    for arg in case["args"]:
        argv.append(arg.replace("{input}", case["input"]))
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError:
        return "ERROR", None, "command not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return "ERROR", None, "timed out after %ss" % timeout
    except OSError as exc:
        return "ERROR", None, "cannot run %s: %s" % (argv[0], exc)
    output = proc.stdout or ""
    return classify(proc.returncode, output), proc.returncode, ""


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run a gate command against the vector pack."
    )
    parser.add_argument(
        "--cases",
        default=str(default_cases_dir()),
        help="case directory (default: cases/ beside this file)",
    )
    parser.add_argument(
        "--timeout", type=float, default=60.0, help="seconds per case"
    )
    args = parser.parse_args(argv)

    command = sys.stdin.read().strip()
    if not command:
        print(
            "FAIL: no gate command on stdin; pipe one line, e.g. "
            "'python3 -I example_gate.py'",
            file=sys.stderr,
        )
        return 2
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        print("FAIL: cannot parse gate command: %s" % exc, file=sys.stderr)
        return 2
    if not tokens:
        print("FAIL: gate command is empty", file=sys.stderr)
        return 2

    cases, errors = load_cases(args.cases)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print("FAIL: %d case problem(s)" % len(errors), file=sys.stderr)
        return 2

    expected_holds = sum(1 for case in cases if case["expected"] == "HOLD")
    fired = 0
    matched = 0
    mismatched = 0
    attacks = sum(1 for case in cases if not case["negative_control"])
    controls = len(cases) - attacks

    width = max(len(case["id"]) for case in cases)
    width = max(width, len("id"))
    print("%-*s  %-8s  %-8s  %-4s  %s" % (width, "id", "expected", "got", "exit", "result"))
    for case in cases:
        got, code, note = run_case(tokens, case, args.timeout)
        ok = got == case["expected"]
        if ok:
            matched += 1
        else:
            mismatched += 1
        if got == "HOLD":
            fired += 1
        print(
            "%-*s  %-8s  %-8s  %-4s  %s"
            % (
                width,
                case["id"],
                case["expected"],
                got,
                "?" if code is None else code,
                "ok" if ok else "MISMATCH" + (" (%s)" % note if note else ""),
            )
        )

    print(
        "%d cases (%d attacks, %d controls): %d invoked, %d expected HOLD, "
        "%d fired, %d matched, %d mismatched"
        % (
            len(cases),
            attacks,
            controls,
            len(cases),
            expected_holds,
            fired,
            matched,
            mismatched,
        )
    )

    if mismatched:
        print("FAIL: %d case(s) mismatched" % mismatched, file=sys.stderr)
        return 1
    if fired == 0:
        print(
            "FAIL: the gate never fired; a gate that cannot say no is not "
            "checked by this pack",
            file=sys.stderr,
        )
        return 1
    print("PASS: all cases matched; the gate fired on %d" % fired)
    return 0


if __name__ == "__main__":
    sys.exit(main())
