"""Sum Instruments L1D Cache Metrics without interpreting micro-ops as accesses."""
import hashlib
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from benchmark import full_output_reference, output_digest

module_spec = importlib.util.spec_from_file_location('profile_tables', Path(__file__).with_name('analyze-profile.py'))
profile_tables = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(profile_tables)

directory = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('results/profile-rule-shards')
workers = int(sys.argv[1])
metrics = json.loads((directory / f'l1d-{workers}-process.log').read_text())
totals = Counter()
by_core = defaultdict(Counter)
threads = set()
row_count = 0
for schema, row in profile_tables.rows(directory / f'l1d-{workers}-metrics.xml'):
    assert schema == 'MetricTableForThread', schema
    if 'http-matcher' not in row['process'][1]:
        continue
    assert row['core'] in ['Performance', 'Efficiency'], row['core']
    metric = row['metric-name']
    # The non-zero-uint64 engineering type represents zero with a sentinel.
    amount = row['sum'] if row['sum'] != '' else 0
    assert isinstance(amount, int) and amount >= 0, row
    totals[metric] += amount
    by_core[row['core']][metric] += amount
    threads.add(row['thread'][0])
    row_count += 1

required = ['ld_uop_spec', 'st_uop_spec', 'l1d_miss_ld_spec', 'l1d_miss_st_spec', 'l1d_writeback', 'cycle']
assert all(totals[k] > 0 for k in required), totals
assert len(threads) == workers + 2, threads
def ratios(counts):
    return {'load_miss_events_per_1000_load_micro_ops': 1000 * counts['l1d_miss_ld_spec'] / counts['ld_uop_spec'],
            'store_miss_events_per_1000_store_micro_ops': 1000 * counts['l1d_miss_st_spec'] / counts['st_uop_spec']}

reference_report = json.loads(Path('results/benchmark.json').read_text())
reference = full_output_reference(reference_report)
for field in ['requests', 'bytes', 'matched_requests', 'supported_patterns', 'skipped_patterns']:
    assert metrics[field] == reference['metrics'][field], field
output = directory / f'l1d-{workers}-output.jsonl'
digest = output_digest(output, metrics['requests'])
assert digest == reference['output_digest']
skipped_digest = hashlib.sha256(output.with_suffix('.skipped.jsonl').read_bytes()).hexdigest()
assert skipped_digest == reference['skipped_report_sha256']
report = {'workers': workers, 'metrics_under_profiler': metrics, 'counts': dict(totals),
          'ratios': ratios(totals), 'counts_by_core_type': {k: dict(v) for k, v in by_core.items()},
          'ratios_by_core_type': {k: ratios(v) for k, v in by_core.items()},
          'exported_metric_rows': row_count, 'target_thread_count': len(threads),
          'scope': 'Full launched target process, including startup, reader, all regex workers and writer; user-mode (EL0), speculative load/store micro-ops and speculative L1D misses. Separate fresh-process run from instruction-processing profiles. No first-five-second exclusion for these counters.',
          'method': 'Sum non-overlapping per-thread MetricTableForThread sum values, separately for Performance and Efficiency core intervals. Ratios compare speculative miss events with speculative load/store micro-ops; micro-ops are not necessarily one-to-one with cache accesses. Do not subtract the ratios from 100% to report an exact cache hit rate.',
          'output_digest': digest, 'every_id_once': True, 'equals_unprofiled_reference': True,
          'reference_workers': reference['metrics']['workers'],
          'skipped_report_sha256': skipped_digest}
if reference['metrics']['workers'] == 1:
    report['equals_current_fast_one'] = True
summary_path = directory / 'summary.json'
summary = json.loads(summary_path.read_text()) if summary_path.exists() else {'runs': {}}
summary.setdefault('l1d_cache_metrics_runs', {})[str(workers)] = report
summary['status'] = 'running'
summary_path.write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(report, indent=2))
