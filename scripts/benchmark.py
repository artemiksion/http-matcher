"""Sequential measurements with real output and one saved report."""

import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


def output_digest(path, request_count):
    fingerprints = bytearray(request_count * 32)
    seen = bytearray(request_count)
    count = 0
    with path.open() as output:
        for line in output:
            result = json.loads(line)
            request_id = result["request_id"]
            if not 0 <= request_id < request_count or seen[request_id]:
                raise ValueError(f"Duplicate or invalid request ID: {request_id}")
            seen[request_id] = 1
            canonical = json.dumps(result, sort_keys=True, separators=(",", ":"))
            start = request_id * 32
            fingerprints[start : start + 32] = hashlib.sha256(canonical.encode()).digest()
            count += 1
    if count != request_count:
        raise ValueError(f"Expected {request_count} results, received {count}")
    return hashlib.sha256(fingerprints).hexdigest()


def full_output_reference(report):
    full_runs = [run for run in report["runs"] if run["scope"] == "full"]
    if not full_runs:
        raise ValueError("The benchmark report has no full-corpus reference")
    return next((run for run in full_runs if run["metrics"]["workers"] == 1), full_runs[0])


def run_matcher(mode, workers, limit, output):
    command = [
        "target/release/http-matcher", "--mode", mode, "--workers", str(workers),
        "--input", "data/requests", "--output", str(output),
    ]
    if limit is not None:
        command.extend(["--limit", str(limit)])
    label = f"{mode}, workers={workers}, requests={limit or 'full'}"
    print(f"Running {label}", flush=True)
    start = time.perf_counter()
    process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
    try:
        while True:
            try:
                process.wait(timeout=60)
                break
            except subprocess.TimeoutExpired:
                print(f"  {label}: {time.perf_counter() - start:.0f} seconds elapsed", flush=True)
    except BaseException:
        process.terminate()
        process.wait()
        raise
    external_wall = time.perf_counter() - start
    stderr = process.stderr.read()
    process.stderr.close()
    if process.returncode:
        raise RuntimeError(f"Matcher exited with {process.returncode}: {stderr}")
    metrics = json.loads(stderr)
    if limit is not None and metrics["requests"] != limit:
        raise ValueError("The corpus contains fewer requests than the sample limit")
    print(f"  Completed: {metrics['total_seconds']:.3f} s, "
          f"{metrics['throughput_req_s']:.1f} req/s", flush=True)
    return {"command": command, "external_wall_seconds": external_wall, "metrics": metrics}


def print_table(report):
    for scope in ["sample", "full"]:
        print(f"\n{scope}: wall-clock includes preparation, matching and output flush")
        reference_label = "baseline" if scope == "sample" else "fast/1"
        if scope == "full" and 1 not in report["worker_counts"]:
            print("Speedup vs fast/1 and S(N)/N are unavailable: one fast worker was not selected.")
        print(f"| Mode | Workers | Requests | Seconds | req/s | Speedup vs {reference_label} | S(N)/N |")
        print("|---|---:|---:|---:|---:|---:|---:|")
        for run in report["runs"]:
            if run["scope"] != scope:
                continue
            metrics = run["metrics"]
            speedup = run.get("speedup_vs_baseline" if scope == "sample" else "speedup_vs_fast_one")
            efficiency = run.get("parallel_efficiency")
            print(f"| {metrics['mode']} | {metrics['workers']} | {metrics['requests']} | "
                  f"{metrics['total_seconds']:.3f} | {metrics['throughput_req_s']:.1f} | "
                  f"{f'{speedup:.2f}x' if speedup is not None else '—'} | "
                  f"{f'{efficiency:.1%}' if efficiency is not None else '—'} |")


def main():
    request_limit = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    worker_counts = [int(value) for value in sys.argv[2:]] or [1, 2, 4, 8]
    if request_limit <= 0 or any(workers <= 0 for workers in worker_counts):
        raise ValueError("The sample size and worker counts must be positive")
    worker_counts = sorted(set(worker_counts))
    has_fast_one = 1 in worker_counts
    if not all(Path("data/requests", name).is_dir() for name in ["Legitimate", "Malicious"]):
        raise ValueError("Download and extract both corpora into data/requests first")

    results = Path("results")
    results.mkdir(exist_ok=True)
    report_path = results / "benchmark.json"
    report = {
        "date": datetime.now(timezone.utc).isoformat(),
        "implementation": "rule_shards_broadcast",
        "environment": {
            "platform": platform.platform(),
            "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
            "binary_sha256": hashlib.sha256(Path("target/release/http-matcher").read_bytes()).hexdigest(),
            "patterns_sha256": hashlib.sha256(Path("data/nmap-service-probes").read_bytes()).hexdigest(),
        },
        "method": "One sequential fresh-process run per configuration, same binary and sorted input. "
                  "Real JSONL output and flush; no fsync, profiler, affinity, explicit warm-up or OS cache clearing. "
                  "Output validation is outside matcher timing. Full digests compared against the first "
                  "selected fast configuration (lowest worker count), sample digests against baseline. "
                  "Full speedup vs fast/1 and S(N)/N are calculated only when one fast worker is selected. "
                  "Speedup uses application total_seconds.",
        "sample_limit": request_limit,
        "worker_counts": worker_counts,
        "full_output_reference_workers": worker_counts[0],
        "full_speedup_reference_workers": 1 if has_fast_one else None,
        "runs": [],
    }

    def save(run):
        report["runs"].append(run)
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    with tempfile.TemporaryDirectory(prefix="benchmark-", dir=results) as temporary:
        output = Path(temporary) / "matches.jsonl"
        baseline = run_matcher("baseline", 1, request_limit, output)
        sample_digest = output_digest(output, baseline["metrics"]["requests"])
        skipped = output.with_suffix(".skipped.jsonl")
        skipped_digest = hashlib.sha256(skipped.read_bytes()).hexdigest()
        shutil.copyfile(skipped, results / "skipped-patterns.jsonl")
        baseline.update(scope="sample", output_digest=sample_digest, every_id_once=True,
                        skipped_report_sha256=skipped_digest)
        save(baseline)

        for workers in worker_counts:
            run = run_matcher("fast", workers, request_limit, output)
            if run["metrics"]["bytes"] != baseline["metrics"]["bytes"]:
                raise ValueError("Sample byte counts differ")
            digest = output_digest(output, run["metrics"]["requests"])
            if digest != sample_digest:
                raise ValueError("Fast output differs from baseline")
            if hashlib.sha256(skipped.read_bytes()).hexdigest() != skipped_digest:
                raise ValueError("Skipped-pattern reports differ")
            run.update(scope="sample", output_digest=digest, every_id_once=True,
                       equals_baseline=True, skipped_report_sha256=skipped_digest,
                       speedup_vs_baseline=baseline["metrics"]["total_seconds"] / run["metrics"]["total_seconds"])
            save(run)

        full_reference = None
        for workers in worker_counts:
            run = run_matcher("fast", workers, None, output)
            metrics = run["metrics"]
            if metrics["requests"] != 1_114_166:
                raise ValueError("Expected the complete corpus of 1114166 requests")
            digest = output_digest(output, metrics["requests"])
            if full_reference is None:
                full_reference = run
                full_digest = digest
            if digest != full_digest or metrics["bytes"] != full_reference["metrics"]["bytes"]:
                raise ValueError("Full fast outputs differ")
            run.update(scope="full", output_digest=digest, every_id_once=True,
                       equals_full_reference=True,
                       output_reference_workers=full_reference["metrics"]["workers"],
                       speedup_vs_fast_one=None, parallel_efficiency=None)
            if has_fast_one:
                speedup = full_reference["metrics"]["total_seconds"] / metrics["total_seconds"]
                run.update(equals_fast_one=True, speedup_vs_fast_one=speedup,
                           parallel_efficiency=speedup / workers)
            if hashlib.sha256(skipped.read_bytes()).hexdigest() != skipped_digest:
                raise ValueError("Skipped-pattern reports differ")
            run["skipped_report_sha256"] = skipped_digest
            save(run)

    print_table(report)
    print(f"\nSaved {report_path}; temporary per-request outputs removed.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as error:
        sys.exit(str(error))
