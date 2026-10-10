"""Check benchmark orchestration without launching the matcher or reading a corpus."""
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import benchmark


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="benchmark-tests-")
        self.addCleanup(temporary.cleanup)
        previous_directory = Path.cwd()
        os.chdir(temporary.name)
        self.addCleanup(os.chdir, previous_directory)
        for name in ("Legitimate", "Malicious"):
            Path("data/requests", name).mkdir(parents=True)
        Path("data/nmap-service-probes").write_text("test rules")
        Path("target/release").mkdir(parents=True)
        Path("target/release/http-matcher").write_bytes(b"test binary, never executed")

    def run_benchmark(self, worker_counts, fault=None):
        calls = []
        console = io.StringIO()

        def fake_matcher(mode, workers, limit, output):
            calls.append((mode, workers, limit))
            full = limit is None
            output.write_text("full output" if full else "sample output")
            skipped = output.with_suffix(".skipped.jsonl")
            skipped.write_text("same skipped rules")
            metrics = {
                "mode": mode,
                "workers": workers,
                "requests": 1_114_166 if full else limit,
                "bytes": 1000 if full else limit,
                "total_seconds": 12 / workers,
                "throughput_req_s": 100 * workers,
            }
            if full and workers == 8:
                if fault == "output":
                    output.write_text("different full output")
                elif fault == "bytes":
                    metrics["bytes"] += 1
                elif fault == "requests":
                    metrics["requests"] -= 1
                elif fault == "skipped":
                    skipped.write_text("different skipped rules")
            return {"metrics": metrics}

        # Matcher, digest computation and environment probes are substituted.
        # Scheduling, report saving, comparisons and console formatting are real.
        with mock.patch.object(benchmark.sys, "argv", ["benchmark.py", "10", *map(str, worker_counts)]), \
             mock.patch.object(benchmark, "run_matcher", side_effect=fake_matcher), \
             mock.patch.object(benchmark, "output_digest",
                               side_effect=lambda path, count: hashlib.sha256(path.read_bytes()).hexdigest()), \
             mock.patch.object(benchmark.subprocess, "check_output", return_value="rustc test"), \
             mock.patch.object(benchmark.platform, "platform", return_value="test platform"), \
             contextlib.redirect_stdout(console):
            benchmark.main()
        return json.loads(Path("results/benchmark.json").read_text()), calls, console.getvalue()

    def test_selected_counts_without_one_do_not_schedule_fast_one(self):
        for counts in ([2, 4, 8], [2, 8], [3, 5, 7], [8, 2, 8], [4]):
            with self.subTest(counts=counts):
                selected = sorted(set(counts))
                report, calls, console = self.run_benchmark(counts)
                self.assertEqual(calls, [("baseline", 1, 10)]
                                 + [("fast", n, 10) for n in selected]
                                 + [("fast", n, None) for n in selected])
                self.assertEqual(report["worker_counts"], selected)
                self.assertEqual(report["full_output_reference_workers"], selected[0])
                self.assertIsNone(report["full_speedup_reference_workers"])
                full_runs = [run for run in report["runs"] if run["scope"] == "full"]
                self.assertEqual(len(full_runs), len(selected))
                for run in full_runs:
                    self.assertTrue(run["every_id_once"])
                    self.assertTrue(run["equals_full_reference"])
                    self.assertEqual(run["output_reference_workers"], selected[0])
                    self.assertIsNone(run["speedup_vs_fast_one"])
                    self.assertIsNone(run["parallel_efficiency"])
                    self.assertNotIn("equals_fast_one", run)
                full_table = console.split("\nfull:")[1]
                self.assertIn("one fast worker was not selected", full_table)
                self.assertEqual(full_table.count("| — | — |"), len(selected))
                self.assertTrue(all(run["speedup_vs_baseline"] > 0
                                    for run in report["runs"]
                                    if run["scope"] == "sample" and run["metrics"]["mode"] == "fast"))

    def test_one_worker_enables_scaling_metrics(self):
        report, calls, console = self.run_benchmark([8, 1, 2])
        self.assertEqual(calls[-3:], [("fast", 1, None), ("fast", 2, None), ("fast", 8, None)])
        self.assertEqual(report["full_speedup_reference_workers"], 1)
        for run in report["runs"]:
            if run["scope"] == "full":
                self.assertTrue(run["equals_fast_one"])
                self.assertEqual(run["speedup_vs_fast_one"], run["metrics"]["workers"])
                self.assertEqual(run["parallel_efficiency"], 1)
        self.assertNotIn("unavailable", console)

    def test_full_validation_still_rejects_inconsistent_runs_without_one(self):
        errors = {
            "output": "Full fast outputs differ",
            "bytes": "Full fast outputs differ",
            "requests": "Expected the complete corpus",
            "skipped": "Skipped-pattern reports differ",
        }
        for fault, message in errors.items():
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, message):
                self.run_benchmark([2, 8], fault=fault)

    def test_nonpositive_worker_counts_are_rejected(self):
        for counts in ([0], [-2], [2, 0]):
            with self.subTest(counts=counts), self.assertRaisesRegex(ValueError, "must be positive"):
                self.run_benchmark(counts)

    def test_profile_reference_accepts_reports_without_one(self):
        two = {"scope": "full", "metrics": {"workers": 2}}
        one = {"scope": "full", "metrics": {"workers": 1}}
        sample = {"scope": "sample", "metrics": {"workers": 1}}
        self.assertIs(benchmark.full_output_reference({"runs": [sample, two]}), two)
        self.assertIs(benchmark.full_output_reference({"runs": [two, one]}), one)
        with self.assertRaisesRegex(ValueError, "no full-corpus reference"):
            benchmark.full_output_reference({"runs": [sample]})

    def test_full_reference_preserves_skipped_hash_for_both_profile_analyzers(self):
        expected_digest = hashlib.sha256(b"same skipped rules").hexdigest()
        for counts in ([2, 8], [1, 2]):
            with self.subTest(counts=counts):
                report, _, _ = self.run_benchmark(counts)
                reference = benchmark.full_output_reference(report)
                # This is the field read by the CPU and L1D profile analyzers.
                self.assertEqual(reference["skipped_report_sha256"], expected_digest)
                self.assertTrue(all(run["skipped_report_sha256"] == expected_digest
                                    for run in report["runs"]))


if __name__ == "__main__":
    unittest.main()
