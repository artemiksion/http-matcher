"""Full-corpus baseline/fast comparisons and optional fast diagnostics."""

import argparse
import hashlib
import json
import platform
import signal
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ordered_digest(path, expected):
    fingerprints = bytearray(expected * 32)
    count = 0
    with Path(path).open() as output:
        for request_id, line in enumerate(output):
            result = json.loads(line)
            if request_id >= expected or result['request_id'] != request_id:
                raise ValueError('Missing, duplicated or out-of-order request ID')
            canonical = json.dumps(result, sort_keys=True, separators=(',', ':'))
            start = request_id * 32
            fingerprints[start:start + 32] = hashlib.sha256(canonical.encode()).digest()
            count += 1
    if count != expected:
        raise ValueError(f'Expected {expected} results, received {count}')
    return hashlib.sha256(fingerprints).hexdigest()


def run_matcher(mode, workers, output, diagnostic=False, binary=None, resources=False):
    command = [str(binary or 'target/release/http-matcher'), '--mode', mode, '--workers', str(workers),
               '--input', 'data/requests', '--output', str(output)]
    if diagnostic:
        command.append('--diagnostics')
    vm_before = None
    resource_path = output.with_suffix('.resources.txt')
    if resources:
        if platform.system() != 'Darwin':
            raise ValueError('--resources currently requires macOS time -l and vm_stat')
        vm_before = subprocess.check_output(['vm_stat'], text=True)
        command = ['/usr/bin/time', '-lp', '-o', str(resource_path), *command]
    print(f'Running {mode}/{workers}, full corpus, diagnostics={diagnostic}', flush=True)
    start = time.perf_counter()
    process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
    try:
        while True:
            try:
                _, stderr = process.communicate(timeout=60)
                break
            except subprocess.TimeoutExpired:
                print(f'  {time.perf_counter() - start:.0f} seconds elapsed', flush=True)
    except BaseException:
        process.terminate()
        process.communicate()
        raise
    external_wall = time.perf_counter() - start
    if process.returncode:
        raise RuntimeError(f'Matcher exited with {process.returncode}: {stderr}')
    metrics = json.loads(stderr)
    print(f"  Matching only: {metrics['prepared']['matching_seconds']:.6f} s; "
          f"output excluded: {metrics['prepared']['output_seconds']:.3f} s", flush=True)
    run = {'command': command, 'external_wall_seconds': external_wall, 'metrics': metrics}
    if resources:
        run['resources'] = {
            'time_l': resource_path.read_text(),
            'vm_stat_before': vm_before,
            'vm_stat_after': subprocess.check_output(['vm_stat'], text=True),
            'scope': 'time -l covers the full target process, including preparation and output. '
                     'VM counters are system-wide snapshots around that process, not matcher-only counters.',
        }
    return run


def worker_cpu(metrics):
    values = [worker['cpu_seconds'] for worker in metrics['prepared']['workers']]
    return sum(values) if all(value is not None for value in values) else None


def diagnostic_summary(raw, metrics):
    workers = raw['workers']
    sums = {field: sum(w['matching'][field] for w in workers)
            for field in ['prefix_seconds', 'literal_seconds', 'result_build_seconds',
                          'literal_occurrences', 'distinct_literals_per_request_sum']}
    ranked = []
    for group in raw['groups']:
        samples = [w['matching']['groups'][group['group_id']] for w in workers]
        calls = sum(sample['calls'] for sample in samples)
        if not calls:
            continue
        worst = max(samples, key=lambda sample: sample['max_call_seconds'])
        ranked.append({**group, 'calls': calls,
            'bytes': sum(sample['bytes'] for sample in samples),
            'search_seconds': sum(sample['search_seconds'] for sample in samples),
            'first_64_calls_seconds': sum(sample['first_64_calls_seconds'] for sample in samples),
            'max_call_seconds': worst['max_call_seconds'],
            'max_request_id': worst['max_request_id'],
            'max_request_bytes': worst['max_request_bytes']})
    ranked.sort(key=lambda group: group['search_seconds'], reverse=True)
    sums['group_search_seconds'] = sum(group['search_seconds'] for group in ranked)
    engines = {}
    for group in ranked:
        engines[group['engine']] = engines.get(group['engine'], 0) + group['search_seconds']
    worker_wall = sum(worker['wall_seconds'] for worker in metrics['prepared']['workers'])
    stages = {key: sums[key] for key in
              ['literal_seconds', 'prefix_seconds', 'group_search_seconds', 'result_build_seconds']}
    stages['other_bookkeeping_and_diagnostic_overhead'] = max(0, worker_wall - sum(stages.values()))
    cpu = worker_cpu(metrics)
    return {'workers': metrics['workers'],
        'instrumented_matching_seconds': metrics['prepared']['matching_seconds'],
        'worker_wall_seconds_sum': worker_wall, 'worker_cpu_seconds_sum': cpu,
        'average_active_cores': cpu / metrics['prepared']['matching_seconds'] if cpu is not None else None,
        'timed_wall_seconds_sum': sums,
        'stage_seconds_sum': stages,
        'stage_fraction_of_worker_wall': {key: value / worker_wall if worker_wall else 0
                                           for key, value in stages.items()},
        'engine_search_seconds_sum': engines, 'group_count': len(raw['groups']),
        'called_group_count': len(ranked), 'top_groups': ranked[:20],
        'interpretation': 'Elapsed per-operation sums include descheduling and diagnostic overhead. '
           'Stage percentages refer to the sum of worker lifetimes, not CPU time. '
           'Across multiple workers the sums are not a wall-clock decomposition. '
           'Only ordinary runs measure throughput.'}


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--workers', type=int, nargs='+', default=[8])
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--diagnostics', action='store_true')
    parser.add_argument('--report-dir', type=Path, default=Path('results'),
                        help='Directory for benchmark and diagnostic reports; baseline stays in results')
    parser.add_argument('--resources', action='store_true',
                        help='Collect full-process resource usage and system VM snapshots on macOS')
    parser.add_argument('--baseline', action='store_true', help='Rerun the slow naive baseline')
    parser.add_argument('--compare-binary', type=Path, help='Interleave the previous fast binary with current fast')
    args = parser.parse_args()
    if args.compare_binary:
        args.compare_binary = args.compare_binary.resolve(strict=True)
    if args.repetitions < 1 or any(worker < 1 for worker in args.workers):
        parser.error('Worker counts and repetitions must be positive')
    baseline_path = Path('results/baseline.json')
    baseline_record = json.loads(baseline_path.read_text())
    reference = baseline_record['run']
    args.report_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.report_dir / 'benchmark.json'
    previous = json.loads(report_path.read_text()) if report_path.exists() else None
    sources = {str(path): sha(path) for path in [Path('Cargo.toml'), Path('Cargo.lock'),
               Path('rust-toolchain.toml'), *Path('src').rglob('*.rs'),
               *Path('scripts').glob('*.py'), Path('README.md'), *Path('docs').glob('*.md')]}
    pattern_sha = sha('data/nmap-service-probes')
    if pattern_sha != baseline_record['environment']['patterns_sha256']:
        raise ValueError('Patterns differ from the verified baseline')
    prior = previous.get('previous_fast_measurements') if previous else None
    if not prior and previous and previous.get('status') == 'complete':
        prior = {key: previous[key] for key in ['date', 'environment', 'runs', 'full_summary']}
    report = {'date': datetime.now(timezone.utc).isoformat(), 'status': 'running',
        'implementation': 'complete_grouped_replicas_dynamic_byte_limited_batches_literal_DFA_direct_flagged_offsets_four_chains',
        'environment': {'platform': platform.platform(),
            'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
            'binary_sha256': sha('target/release/http-matcher'), 'patterns_sha256': pattern_sha},
        'method': 'Sequential full-corpus fresh processes. Primary metric: prepared.matching_seconds. '
            'Includes batch claims, all per-request filters, signature checks, complete service priority/'
            'deduplication and storing results in memory. Excludes file reading, JSON decoding, normalization, '
            'compilation, worker startup/destruction, postprocessing, JSON serialization, writes and flush. '
            'First-use search cache work is included. Every request is processed once in total. '
            'No affinity, explicit warm-up, cache reset or fsync. Actual outputs are checked outside application '
            'timing. Diagnostics perturb performance and are kept out of ordinary summaries. '
            'Baseline is historical unless --baseline is explicitly selected.',
        'source_sha256': sources, 'baseline_reference': str(baseline_path),
        'baseline_report_sha256': sha(baseline_path), 'baseline_historical': not args.baseline,
        'reference_output_digest': reference['output_digest'], 'runs': [],
        'diagnostics': [], 'previous_fast_measurements': prior}
    if args.compare_binary:
        report['comparison_binary'] = {'path': str(args.compare_binary),
            'sha256': sha(args.compare_binary),
            'method': 'Previous/current full-corpus runs are interleaved at each worker count. '
                'Their order reverses on even repetitions. Timing and output checks are identical.'}

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    def checked_run(output, mode, workers, repetition, diagnostic=False, binary=None, variant='current_fast'):
        report['current_run'] = {'mode': mode, 'workers': workers,
                                  'repetition': repetition, 'diagnostics': diagnostic, 'variant': variant}
        save()
        print(f'Variant: {variant}', flush=True)
        run = run_matcher(mode, workers, output, diagnostic, binary, args.resources)
        metrics = run['metrics']
        for field in ['requests', 'bytes', 'matched_requests', 'supported_patterns', 'skipped_patterns']:
            if metrics[field] != reference['metrics'][field]:
                raise ValueError(f'Corpus/result metric differs: {field}')
        prepared = metrics['prepared']
        for field in ['requests', 'bytes', 'batches']:
            expected = prepared['batches'] if field == 'batches' else metrics[field]
            if sum(worker[field] for worker in prepared['workers']) != expected:
                raise ValueError(f'Worker accounting differs: {field}')
        digest = ordered_digest(output, metrics['requests'])
        if digest != reference['output_digest']:
            raise ValueError('Ordered full output differs from baseline')
        skipped_sha = sha(output.with_suffix('.skipped.jsonl'))
        if skipped_sha != reference['skipped_report_sha256']:
            raise ValueError('Skipped rules differ from baseline')
        run.update(repetition=repetition, scope='full', diagnostic=diagnostic,
                   variant=variant,
                   output_digest=digest, equals_baseline=True, every_id_once_in_order=True,
                   skipped_report_sha256=skipped_sha)
        report['runs'].append(run)
        if diagnostic:
            directory = args.report_dir / 'diagnostics'
            directory.mkdir(exist_ok=True)
            destination = directory / f'workers-{workers}.json'
            destination.write_bytes(Path(metrics['diagnostics_path']).read_bytes())
            summary = diagnostic_summary(json.loads(destination.read_text()), metrics)
            report['diagnostics'].append({'path': str(destination), 'summary': summary})
            print('  Stages:', json.dumps(summary['stage_seconds_sum']), flush=True)
        save()
        return run

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'Interrupted by signal {signum}')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    save()
    try:
        with tempfile.TemporaryDirectory(prefix='http-matcher-benchmark-') as temporary:
            output = Path(temporary) / 'matches.jsonl'
            if args.baseline:
                current = checked_run(output, 'baseline', 1, 1)
                baseline_record = {'date': datetime.now(timezone.utc).isoformat(), 'status': 'complete',
                    'historical': False, 'environment': report['environment'],
                    'method': report['method'], 'source_sha256': sources, 'run': current}
                baseline_path.write_text(json.dumps(baseline_record, indent=2) + '\n')
                reference = current
                report['baseline_report_sha256'] = sha(baseline_path)
            for repetition in range(1, args.repetitions + 1):
                for workers in sorted(set(args.workers)):
                    variants = [('current_fast', None)]
                    if args.compare_binary:
                        variants.insert(0, ('previous_fast', args.compare_binary))
                        if repetition % 2 == 0:
                            variants.reverse()
                    for variant, binary in variants:
                        checked_run(output, 'fast', workers, repetition, binary=binary, variant=variant)
            if args.diagnostics:
                for workers in sorted({1, *args.workers}):
                    checked_run(output, 'fast', workers, 1, diagnostic=True)
        baseline_seconds = reference['metrics']['prepared']['matching_seconds']
        summary = []
        for workers in sorted(set(args.workers)):
            runs = [run['metrics'] for run in report['runs'] if not run['diagnostic']
                    and run['variant'] == 'current_fast' and run['metrics']['mode'] == 'fast'
                    and run['metrics']['workers'] == workers]
            times = [run['prepared']['matching_seconds'] for run in runs]
            median = statistics.median(times)
            cpus = [worker_cpu(run) for run in runs]
            summary.append({'mode': 'fast', 'workers': workers, 'repetitions': len(times),
                'median_matching_seconds': median, 'min_matching_seconds': min(times),
                'max_matching_seconds': max(times), 'matching_throughput_req_s': reference['metrics']['requests'] / median,
                'speedup_vs_baseline': baseline_seconds / median,
                'median_worker_cpu_seconds_sum': statistics.median(cpus) if all(cpu is not None for cpu in cpus) else None})
        if args.compare_binary:
            comparisons = []
            for current in summary:
                controls = [run['metrics'] for run in report['runs'] if not run['diagnostic']
                    and run['variant'] == 'previous_fast' and run['metrics']['workers'] == current['workers']]
                times = [run['prepared']['matching_seconds'] for run in controls]
                cpus = [worker_cpu(run) for run in controls]
                median = statistics.median(times)
                comparisons.append({'workers': current['workers'], 'repetitions': len(times),
                    'previous_median_matching_seconds': median,
                    'previous_min_matching_seconds': min(times), 'previous_max_matching_seconds': max(times),
                    'previous_median_worker_cpu_seconds_sum': statistics.median(cpus)
                        if all(cpu is not None for cpu in cpus) else None,
                    'current_median_matching_seconds': current['median_matching_seconds'],
                    'speedup_vs_previous_fast': median / current['median_matching_seconds']})
            report['comparison_vs_previous_fast'] = comparisons
        if {path: sha(path) for path in sources} != sources:
            raise ValueError('Measured sources/docs changed during execution')
        if sha('target/release/http-matcher') != report['environment']['binary_sha256']:
            raise ValueError('Measured binary changed during execution')
        if sha(baseline_path) != report['baseline_report_sha256']:
            raise ValueError('Baseline report changed during execution')
        if args.compare_binary and sha(args.compare_binary) != report['comparison_binary']['sha256']:
            raise ValueError('Comparison binary changed during execution')
        report.update(status='complete', completed_at=datetime.now(timezone.utc).isoformat(),
                      full_summary=summary, baseline_matching_seconds=baseline_seconds,
                      all_outputs_equal_baseline=True, measured_sources_unchanged=True)
        report.pop('current_run', None)
        save()
        if args.diagnostics:
            (args.report_dir / 'profile.json').write_text(json.dumps({
                'date': report['completed_at'], 'status': 'complete', 'environment': report['environment'],
                'source_sha256': sources, 'ordinary_summary': summary,
                'diagnostics': report['diagnostics']}, indent=2) + '\n')
        print('SUMMARY', json.dumps(summary), flush=True)
    except BaseException as error:
        report.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else 'failed', error=str(error))
        save()
        raise


if __name__ == '__main__':
    main()
