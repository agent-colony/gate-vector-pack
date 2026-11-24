#!/usr/bin/env python3
"""Tests for run_vectors.py and the vector pack.

Run: python3 -I test_run_vectors.py
"""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE
RUNNER = HERE / "run_vectors.py"
EXAMPLE = HERE / "example_gate.py"
CASES = HERE / "cases"

EXAMPLE_COMMAND = "%s -I %s" % (shlex.quote(sys.executable), shlex.quote(str(EXAMPLE)))


def run_runner(command, cases=CASES, timeout=60):
    """Run the vector runner with `command` on stdin. Return CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-I", str(RUNNER), "--cases", str(cases), "--timeout", str(timeout)],
        input=command + "\n",
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )


def load_case_files(cases=CASES):
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(Path(cases).glob("*.json"))]


class TestPackShape(unittest.TestCase):
    def test_at_least_eight_cases_six_attacks_two_controls(self):
        cases = load_case_files()
        self.assertGreaterEqual(len(cases), 8)
        attacks = [c for c in cases if not c["negative_control"]]
        controls = [c for c in cases if c["negative_control"]]
        self.assertGreaterEqual(len(attacks), 6)
        self.assertGreaterEqual(len(controls), 2)

    def test_ids_are_unique(self):
        ids = [c["id"] for c in load_case_files()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_expected_verdicts_are_known(self):
        for case in load_case_files():
            self.assertIn(case["expected"], ("PASS", "HOLD", "IGNORE"), case["id"])
            if case["negative_control"]:
                self.assertEqual(case["expected"], "PASS", case["id"])

    def test_every_input_is_pinned(self):
        for case in load_case_files():
            path = CASES / case["input"]
            self.assertTrue(path.is_file(), case["id"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, case["sha256"], case["id"])

    def test_the_pack_contains_a_must_fail_case(self):
        cases = load_case_files()
        self.assertTrue(any(c["expected"] == "HOLD" for c in cases))


class TestAgainstExampleGate(unittest.TestCase):
    def test_pack_passes_against_example_gate(self):
        proc = run_runner(EXAMPLE_COMMAND)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("all cases matched", proc.stdout)
        self.assertIn("fired", proc.stdout)
        self.assertNotIn("MISMATCH", proc.stdout)

    def test_broken_copy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = EXAMPLE.read_text(encoding="utf-8")
            broken = source.replace(
                "        return 1\n    print(\"PASS\")", "        return 0\n    print(\"PASS\")"
            )
            self.assertNotEqual(source, broken, "the break did not apply")
            path = Path(tmp) / "example_gate_broken.py"
            path.write_text(broken, encoding="utf-8")
            command = "%s -I %s" % (shlex.quote(sys.executable), shlex.quote(str(path)))
            proc = run_runner(command)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("MISMATCH", proc.stdout)
            self.assertIn("mismatched", proc.stderr)

    def test_a_gate_that_always_passes_fails(self):
        command = "%s -c pass" % shlex.quote(sys.executable)
        proc = run_runner(command)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("mismatched", proc.stderr)
        self.assertIn("0 fired", proc.stdout)


class TestRunnerRefusals(unittest.TestCase):
    def test_missing_gate_command(self):
        proc = run_runner("")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no gate command", proc.stderr)

    def test_unparseable_gate_command(self):
        proc = run_runner("'unclosed")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cannot parse", proc.stderr)

    def test_empty_cases_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_runner(EXAMPLE_COMMAND, cases=Path(tmp))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("no case files", proc.stderr)

    def test_tampered_input_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / "cases"
            shutil.copytree(CASES, copied)
            target = copied / "clean-technical-post.txt"
            target.write_bytes(target.read_bytes() + b"tampered\n")
            proc = run_runner(EXAMPLE_COMMAND, cases=copied)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("hashes to", proc.stderr)

    def test_unknown_expected_verdict_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b"hello\n"
            (Path(tmp) / "input.txt").write_bytes(data)
            case = {
                "id": "bad-expected",
                "attack": "test",
                "expected": "MAYBE",
                "negative_control": False,
                "input": "input.txt",
                "sha256": hashlib.sha256(data).hexdigest(),
                "args": ["--body", "{input}"],
            }
            (Path(tmp) / "bad-expected.json").write_text(json.dumps(case))
            proc = run_runner(EXAMPLE_COMMAND, cases=Path(tmp))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("expected must be one of", proc.stderr)

    def test_duplicate_ids_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b"hello\n"
            (Path(tmp) / "input.txt").write_bytes(data)
            case = {
                "id": "same",
                "attack": "test",
                "expected": "HOLD",
                "negative_control": False,
                "input": "input.txt",
                "sha256": hashlib.sha256(data).hexdigest(),
                "args": ["--body", "{input}"],
            }
            (Path(tmp) / "a.json").write_text(json.dumps(case))
            (Path(tmp) / "b.json").write_text(json.dumps(case))
            proc = run_runner(EXAMPLE_COMMAND, cases=Path(tmp))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("duplicate id", proc.stderr)

    def test_input_path_escape_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b"hello\n"
            case = {
                "id": "escape",
                "attack": "test",
                "expected": "HOLD",
                "negative_control": False,
                "input": "../outside.txt",
                "sha256": hashlib.sha256(data).hexdigest(),
                "args": ["--body", "{input}"],
            }
            (Path(tmp) / "escape.json").write_text(json.dumps(case))
            proc = run_runner(EXAMPLE_COMMAND, cases=Path(tmp))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("relative path", proc.stderr)

    def test_pack_without_a_hold_case_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b"hello\n"
            (Path(tmp) / "input.txt").write_bytes(data)
            case = {
                "id": "only-pass",
                "attack": "test",
                "expected": "PASS",
                "negative_control": True,
                "input": "input.txt",
                "sha256": hashlib.sha256(data).hexdigest(),
                "args": ["--body", "{input}"],
            }
            (Path(tmp) / "only-pass.json").write_text(json.dumps(case))
            proc = run_runner(EXAMPLE_COMMAND, cases=Path(tmp))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("no HOLD case", proc.stderr)


if __name__ == "__main__":
    unittest.main()
