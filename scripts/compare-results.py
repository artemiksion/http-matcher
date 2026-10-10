"""Validate the documented 100k baseline/fast outputs and print speedup."""

import hashlib
import json
import sys
from pathlib import Path

from benchmark import output_digest


def compare_results(baseline_output, baseline_metrics, fast_output, fast_metrics):
    baseline = json.loads(baseline_metrics.read_text())
    fast = json.loads(fast_metrics.read_text())
    if baseline["requests"] != 100000 or fast["requests"] != 100000:
        raise ValueError("Both runs must contain exactly 100000 requests")
    for field in ["bytes", "matched_requests", "supported_patterns", "skipped_patterns"]:
        if baseline[field] != fast[field]:
            raise ValueError(f"Metrics differ: {field}")
    baseline_digest = output_digest(baseline_output, 100000)
    if output_digest(fast_output, 100000) != baseline_digest:
        raise ValueError("Fast output differs from baseline")
    baseline_skipped = baseline_output.with_suffix(".skipped.jsonl")
    fast_skipped = fast_output.with_suffix(".skipped.jsonl")
    if hashlib.sha256(baseline_skipped.read_bytes()).digest() != hashlib.sha256(fast_skipped.read_bytes()).digest():
        raise ValueError("Skipped-pattern reports differ")
    if baseline["total_seconds"] <= 0 or fast["total_seconds"] <= 0:
        raise ValueError("Both run times must be positive")
    print(f"Baseline: {baseline['total_seconds']:.3f} s, {baseline['throughput_req_s']:.1f} req/s")
    print(f"Fast/{fast['workers']}: {fast['total_seconds']:.3f} s, {fast['throughput_req_s']:.1f} req/s")
    print(f"Speedup vs baseline: {baseline['total_seconds'] / fast['total_seconds']:.2f}x")
    print(f"All IDs and results agree; digest: {baseline_digest}")


def main():
    compare_results(
        Path("/tmp/http-matcher-baseline-100k.jsonl"),
        Path("/tmp/http-matcher-baseline-100k-metrics.json"),
        Path("/tmp/http-matcher-fast-100k.jsonl"),
        Path("/tmp/http-matcher-fast-100k-metrics.json"),
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"Cannot compare results: {error}")
