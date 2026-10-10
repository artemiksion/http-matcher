"""Summarize exported Instruments tables without assuming XML reference IDs."""
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

from benchmark import full_output_reference, output_digest


def rows(path):
    cache = {}
    columns = []
    schema = None

    def value(element):
        if 'ref' in element.attrib:
            return cache[element.attrib['ref']]
        children = [value(child) for child in element]
        tag = element.tag
        if tag == 'thread':
            result = (children[0], element.get('fmt', ''))
        elif tag == 'process':
            result = (children[0], element.get('fmt', ''))
        elif tag == 'frame':
            result = element.get('name', element.get('addr', '?'))
        elif tag == 'tagged-backtrace':
            result = tuple(children)
        elif tag == 'uint64-array':
            result = tuple(int(v) for v in (element.text or '').split())
        else:
            text = element.text or ''
            try:
                result = int(text)
            except ValueError:
                result = text
        if 'id' in element.attrib:
            cache[element.attrib['id']] = result
        return result

    for event, element in ET.iterparse(path, events=('end',)):
        if element.tag == 'schema':
            schema = element.get('name')
            columns = [col.findtext('mnemonic') for col in element.findall('col')]
        elif element.tag == 'row':
            yield schema, dict(zip(columns, (value(child) for child in element)))
            element.clear()


def analyze(directory, workers):
    metrics = json.loads((directory / f'processing-{workers}-process.log').read_text())
    samples = []
    roles = {}
    first_worker = None
    for schema, row in rows(directory / f'processing-{workers}-stacks.xml'):
        assert schema == 'time-profile', schema
        if 'http-matcher' not in row['process'][1]:
            continue
        thread = row['thread'][0]
        stack = row['stack'] if isinstance(row['stack'], tuple) else ()
        if any('process_batches' in frame for frame in stack):
            roles[thread] = 'worker'
            first_worker = min(first_worker or row['time'], row['time'])
        elif any('read_batches' in frame for frame in stack):
            roles[thread] = 'reader'
        elif 'Main Thread' in row['thread'][1]:
            roles[thread] = 'writer'
        samples.append((row['time'], thread, row['thread-state'], row['weight'], stack))
    assert first_worker is not None, 'No resolved worker stacks'
    assert sum(role == 'worker' for role in roles.values()) == workers, roles
    start = first_worker + 5_000_000_000
    sample_weights = Counter()
    category_weights = Counter()
    leaves = Counter()
    worker_thread_weights = Counter()
    for timestamp, thread, state, weight, stack in samples:
        if timestamp < start or state != 'Running':
            continue
        role = roles.get(thread, 'other')
        sample_weights[role] += weight
        if role == 'worker':
            worker_thread_weights[thread] += weight
            leaves[stack[0] if stack else '?'] += weight
            if any('regex_automata' in f or 'regex::' in f for f in stack):
                category_weights['regex'] += weight
            if any('cache_next_state' in f or 'util::determinize' in f for f in stack):
                category_weights['transition_build'] += weight
            if any('hybrid' in f and ('::clear::' in f or '::reset::' in f) for f in stack):
                category_weights['cache_clear_or_reset'] += weight

    durations = Counter()
    per_thread = Counter()
    by_core = defaultdict(lambda: Counter())
    sums = defaultdict(lambda: [0.0] * 4)
    end = start
    full_duration = 0
    for schema, row in rows(directory / f'processing-{workers}-counters.xml'):
        assert schema == 'CounterMetricByThread', schema
        if 'http-matcher' not in row['process'][1]:
            continue
        timestamp = row['timestamp']
        finish = timestamp + row['duration']
        full_duration += row['duration']
        end = max(end, finish)
        duration = max(0, finish - max(start, timestamp))
        if not duration:
            continue
        thread = row['thread'][0]
        role = roles.get(thread, 'other')
        core_type = 'efficiency' if row['core'] < 4 else 'performance'
        ratios = row['value']
        assert len(ratios) == 4, ratios
        assert all(0 <= v <= 10000 for v in ratios), ratios
        durations[role] += duration
        per_thread[thread] += duration
        by_core[role][core_type] += duration
        for key in [role, f'{role}/{core_type}', 'process']:
            for i, ratio in enumerate(ratios):
                sums[key][i] += duration * ratio / 10000

    names = ['executing', 'execution_latency_without_sme', 'memory_miss', 'memory_miss_executing']
    total = sum(durations.values())
    window = (end - start) / 1e9
    def ratios(key, duration):
        return dict(zip(names, (v / duration for v in sums[key]))) if duration else None
    denominator = sample_weights['worker']
    report = {
        'workers': workers,
        'metrics_under_profiler': metrics,
        'steady_window_trace_seconds': {'start': start / 1e9, 'end': end / 1e9, 'duration': window},
        'window_method': 'Exclude first 5 seconds after earliest resolved process_batches stack, not trace launch overhead. Clip counter intervals at window start; include remaining full-corpus work.',
        'active_cpu_seconds_process_full': full_duration / 1e9,
        'average_active_cores_process_full': full_duration / 1e9 / metrics['total_seconds'],
        'active_cpu_seconds_by_role_steady': {k: v / 1e9 for k, v in durations.items()},
        'average_active_cores_by_role_steady': {k: v / 1e9 / window for k, v in durations.items()},
        'average_active_cores_process_steady': total / 1e9 / window,
        'machine_cpu_fraction_steady': total / 1e9 / window / 8,
        'cpu_fraction_by_role_steady': {k: v / total for k, v in durations.items()},
        'worker_thread_active_seconds_steady': {str(t): v / 1e9 for t, v in per_thread.items() if roles.get(t) == 'worker'},
        'worker_efficiency_core_active_fraction': by_core['worker']['efficiency'] / durations['worker'],
        'worker_instruction_processing_ratios': ratios('worker', durations['worker']),
        'process_instruction_processing_ratios': ratios('process', total),
        'worker_ratios_by_core_type': {c: ratios(f'worker/{c}', v) for c, v in by_core['worker'].items()},
        'sampled_running_fractions_by_role': {k: v / sum(sample_weights.values()) for k, v in sample_weights.items()},
        'worker_inclusive_fractions': {k: v / denominator for k, v in category_weights.items()},
        'worker_top_leaf_functions': [{'name': f, 'fraction': v / denominator} for f, v in leaves.most_common(8)],
        'thread_roles': {str(t): role for t, role in roles.items()},
        'ratio_denominator': 'Instruction-processing cycles with a non-empty instruction window. Time-weighted interval ratios, quantized to 1/10000 by Instruments. Not wall-time percentages or cache miss rate per memory access.',
        'cpu_occupancy_method': 'Sum target process CounterMetricByThread active interval durations, divided by the analysis wall-time window; 1.0 active core = 100% of one core. Sampling approximation, not whole-machine activity.',
        'stack_method': 'Inclusive fractions of Running time-profile sample weights. Never use absolute sample weights as measured CPU seconds; initial 2-worker trace reported requested 5ms versus configured 1ms sampling warning. Constant weight scaling cancels in fractions.',
    }
    benchmark = json.loads(Path('results/benchmark.json').read_text())
    reference = full_output_reference(benchmark)
    for field in ['requests', 'bytes', 'matched_requests', 'supported_patterns', 'skipped_patterns']:
        assert metrics[field] == reference['metrics'][field], field
    output = directory / f'processing-{workers}-output.jsonl'
    digest = output_digest(output, metrics['requests'])
    assert digest == reference['output_digest'], 'Profile output differs from unprofiled reference'
    skipped_digest = hashlib.sha256(output.with_suffix('.skipped.jsonl').read_bytes()).hexdigest()
    assert skipped_digest == reference['skipped_report_sha256'], 'Skipped rules changed'
    report.update(output_digest=digest, every_id_once=True, equals_unprofiled_reference=True,
                  reference_workers=reference['metrics']['workers'],
                  skipped_report_sha256=skipped_digest)
    if reference['metrics']['workers'] == 1:
        report['equals_current_fast_one'] = True
    return report


if __name__ == '__main__':
    directory = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('results/profile-rule-shards')
    workers = int(sys.argv[1])
    report = analyze(directory, workers)
    summary_path = directory / 'summary.json'
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {'runs': {}}
    summary['runs'][str(workers)] = report
    summary['status'] = 'running'
    summary_path.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(report, indent=2))
