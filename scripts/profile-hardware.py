"""Record and summarize macOS CPU counters for full-corpus matcher workers."""

import argparse
import ctypes as C
import json
import re
import shlex
import signal
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from benchmark import ordered_digest, sha


def recording_options(mode):
    profiler = {'contextSwitchSampling': False, 'highFrequencySampling': False,
                'recordKernelStacks': mode == 'kernel', 'recordWaitingThreads': False}
    options = {'Time Profiler': profiler, 'Points of Interest': {'excludeOSLogs': False}}
    if mode != 'kernel':
        counting, analysis, label = {
            'bottlenecks': ('bottlenecks', 'bottleneck', 'CPU Bottlenecks'),
            'processing': ('processing', 'bottleneck', 'Instruction Processing Bottlenecks'),
            'l1d': ('l1d_metrics', 'metrics', 'L1D Cache Metrics'),
        }[mode]
        options['CPU Counters'] = {
            'allEventsAndFormulas': [], 'configurationType': {'guided': {}},
            'countingLevel': 'EL0', 'pmiEventAliasOrMnemonic': '', 'pmiThreshold': 1000000,
            'processBucketSize': 10, 'sampleByTime': True,
            'selectedCountingMode': {'analysisMode': analysis, 'countingMode': counting},
            'selectedCountingModeDisplayName': label, 'useDebuggingInformation': False,
            'useHighFrequencyForGuidedMode': False, 'useHighFrequencyForManualMode': False,
        }
    return options


def rows(path):
    cache, columns, schema = {}, [], None

    def value(element):
        if 'ref' in element.attrib:
            return cache[element.attrib['ref']]
        children = [value(child) for child in element]
        if element.tag in ('thread', 'process'):
            result = (children[0], element.get('fmt', ''))
        elif element.tag == 'frame':
            result = element.get('name', element.get('addr', '?'))
        elif element.tag == 'tagged-backtrace':
            result = tuple(children)
        elif element.tag == 'uint64-array':
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

    for _, element in ET.iterparse(path, events=('end',)):
        if element.tag == 'schema':
            schema = element.get('name')
            columns = [col.findtext('mnemonic') for col in element.findall('col')]
        elif element.tag == 'row':
            yield schema, dict(zip(columns, (value(child) for child in element)))
            element.clear()


class TaskInfo(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in (
        'virtual_size', 'resident_size', 'total_user', 'total_system',
        'threads_user', 'threads_system')] + [(name, C.c_int32) for name in (
        'policy', 'faults', 'pageins', 'cow_faults', 'messages_sent', 'messages_received',
        'syscalls_mach', 'syscalls_unix', 'csw', 'threadnum', 'numrunning', 'priority')]


class VmPrefix(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in ('free', 'active', 'inactive', 'wired')]
    _fields_ += [(name, C.c_uint64) for name in (
        'zero_fill', 'reactivations', 'pageins', 'pageouts', 'faults', 'cow_faults',
        'lookups', 'hits', 'purges')]
    _fields_ += [(name, C.c_uint32) for name in ('purgeable', 'speculative')]
    _fields_ += [(name, C.c_uint64) for name in (
        'decompressions', 'compressions', 'swapins', 'swapouts')]
    _fields_ += [(name, C.c_uint32) for name in (
        'compressor_pages', 'throttled', 'external', 'internal')]
    _fields_ += [('uncompressed_in_compressor', C.c_uint64), ('swapped', C.c_uint64)]


class Monitor:
    """Read-only process/VM samples, outside the target, every 10 ms."""
    def __init__(self, binary):
        self.binary, self.pid, self.samples = str(binary), None, []
        self.proc = C.CDLL('/usr/lib/libproc.dylib')
        self.system = C.CDLL('/usr/lib/libSystem.B.dylib')
        self.proc.proc_listpids.argtypes = [C.c_uint32, C.c_uint32, C.c_void_p, C.c_int]
        self.proc.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
        self.proc.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
        self.system.mach_host_self.restype = C.c_uint32
        self.system.host_statistics64.argtypes = [C.c_uint32, C.c_int, C.c_void_p,
                                                  C.POINTER(C.c_uint32)]
        self.host = self.system.mach_host_self()

    def sample(self):
        if self.pid is None:
            pids = (C.c_int * 8192)()
            count = self.proc.proc_listpids(1, 0, pids, C.sizeof(pids)) // C.sizeof(C.c_int)
            for pid in pids[:count]:
                path = C.create_string_buffer(4096)
                if self.proc.proc_pidpath(pid, path, len(path)) > 0:
                    if path.value.decode(errors='replace') == self.binary:
                        self.pid = pid
                        break
        if self.pid is None:
            return
        task = TaskInfo()
        if self.proc.proc_pidinfo(self.pid, 4, 0, C.byref(task), C.sizeof(task)) != C.sizeof(task):
            return
        # Allocate for the latest VM revision, not just the prefix decoded here.
        buffer = (C.c_uint32 * 256)()
        count = C.c_uint32(len(buffer))
        if self.system.host_statistics64(self.host, 4, buffer, C.byref(count)) != 0:
            raise RuntimeError('host_statistics64 failed')
        vm = C.cast(buffer, C.POINTER(VmPrefix)).contents
        self.samples.append({'monotonic_ns': time.monotonic_ns(),
            'task': {name: getattr(task, name) for name, _ in task._fields_},
            'vm': {name: getattr(vm, name) for name, _ in vm._fields_}})


def execute(command, log, monitor=None):
    with log.open('w') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        start = time.monotonic()
        try:
            while process.poll() is None:
                if monitor:
                    monitor.sample()
                if time.monotonic() - start > 180:
                    raise TimeoutError('Instruments command exceeded 180 seconds')
                time.sleep(.01 if monitor else .1)
        except BaseException:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
    if process.returncode:
        raise RuntimeError(f'Command exited {process.returncode}: {log.read_text()}')


def vm_summary(path, metrics):
    if not path.exists():
        return {'available': False}
    raw = json.loads(path.read_text())
    samples = raw['samples']
    positions = [i for i, sample in enumerate(samples) if sample['task']['threadnum'] > 1]
    if not positions:
        return {'available': False, 'reason': 'No worker lifetime observed'}
    first, last = max(0, positions[0] - 1), min(len(samples) - 1, positions[-1] + 1)
    a, b = samples[first], samples[last]
    window = samples[first:last + 1]
    timebase = (C.c_uint32 * 2)()
    system = C.CDLL('/usr/lib/libSystem.B.dylib')
    if system.mach_timebase_info(C.byref(timebase)) != 0:
        raise RuntimeError('mach_timebase_info failed')
    seconds_per_tick = timebase[0] / timebase[1] / 1e9
    return {'available': True, 'pid': raw['pid'], 'samples': len(window),
        'observed_thread_count_max': max(s['task']['threadnum'] for s in window),
        'approximate_worker_lifetime_seconds': (b['monotonic_ns']-a['monotonic_ns'])/1e9,
        'exact_matching_seconds': metrics['prepared']['matching_seconds'],
        'target_deltas': {key: b['task'][key]-a['task'][key] for key in (
            'faults', 'pageins', 'cow_faults', 'total_user', 'total_system', 'csw')},
        'mach_timebase': {'numer': timebase[0], 'denom': timebase[1]},
        'target_cpu_seconds_approximate': {
            'user': (b['task']['total_user']-a['task']['total_user'])*seconds_per_tick,
            'system': (b['task']['total_system']-a['task']['total_system'])*seconds_per_tick},
        'system_vm_deltas': {key: b['vm'][key]-a['vm'][key] for key in (
            'compressions', 'decompressions', 'swapins', 'swapouts', 'pageins', 'pageouts')},
        'resident_bytes_range': [min(s['task']['resident_size'] for s in window),
                                 max(s['task']['resident_size'] for s in window)],
        'scope': 'External 10ms samples. Window brackets all non-main thread lifetimes, '
                 'including short setup/destruction. VM deltas are system-wide; task faults/pageins '
                 'belong to the target. This is an approximation, not the exact barrier interval.'}


def analyze(directory, mode, workers):
    name = f'{mode}-{workers}'
    metrics = json.loads((directory / f'{name}-metrics.json').read_text())
    toc = ET.parse(directory / f'{name}-toc.xml')
    pid = int(toc.find('.//target/process').get('pid'))
    stacks = [row for _, row in rows(directory / f'{name}-stacks.xml') if row['process'][0] == pid]
    first_by_thread = {}
    for row in stacks:
        first_by_thread.setdefault(row['thread'][0], row['time'])
    # Launching through sh/exec produces short-lived launcher threads in the same
    # PID's trace. Identify Rust workers by computation stacks, not earliest TID.
    tids = {row['thread'][0] for row in stacks if any(
        'matching_rules' in frame or 'ResultBuilder' in frame for frame in row['stack'])}
    mains = {row['thread'][0] for row in stacks if any(
        'http_matcher::main::' in frame for frame in row['stack'])}
    if len(mains) != 1:
        raise ValueError(f'Cannot identify the target main thread: {mains}')
    main = mains.pop()
    if len(tids) != workers:
        raise ValueError(f'Expected {workers} worker threads, found {len(tids)}: {first_by_thread}')
    worker_stacks = [row for row in stacks if row['thread'][0] in tids and row['thread-state'] == 'Running']
    if not any(any('http_matcher' in frame for frame in row['stack']) for row in worker_stacks):
        raise ValueError('Worker stacks lack resolved matcher symbols')
    # Restrict time-series counters to the sampled computation window; do not discard
    # a fixed warm-up interval because the complete fast/8 match can take only ~1 second.
    compute = [row for row in worker_stacks if any(
        'matching_rules' in frame or 'ResultBuilder' in frame for frame in row['stack'])]
    start = min(row['time'] for row in compute)
    end = max(row['time'] for row in compute) + 1_000_000
    selected = [row for row in worker_stacks if start <= row['time'] < end]
    leaves, inclusive = Counter(), Counter()
    total_weight = sum(row['weight'] for row in selected)
    for row in selected:
        stack = row['stack']
        leaves[stack[0] if stack else '?'] += row['weight']
        for label, tokens in {
            'literal_search': ('::literals::', 'LiteralDfa::select', 'LiteralCandidates::select'),
            'regex': ('regex_automata', 'regex::'),
            'result_builder': ('ResultBuilder::build',),
            'allocator': ('malloc', 'free', 'alloc::alloc'),
            'vm_fault_or_compressor': ('vm_fault', 'vm_compressor', 'vm_page_', 'decompress'),
        }.items():
            if any(token in frame for frame in stack for token in tokens):
                inclusive[label] += row['weight']
    report = {'mode': mode, 'workers': workers, 'pid': pid, 'metrics_under_profiler': metrics,
        'worker_thread_ids': sorted(tids), 'main_thread_id': main,
        'sampled_computation_window_seconds': {'start': start/1e9, 'end': end/1e9},
        'running_worker_samples': len(selected),
        'worker_top_leaf_functions': [{'name': k, 'fraction': v/total_weight} for k, v in leaves.most_common(12)],
        'worker_inclusive_sample_fractions': {k: v/total_weight for k, v in inclusive.items()},
        'vm': vm_summary(directory/f'{name}-vm.json', metrics)}
    if report['vm']['available'] and report['vm']['pid'] != pid:
        raise ValueError('VM monitor observed a different process than the trace target')
    if mode == 'kernel':
        report['unresolved_kernel_sample_fraction'] = sum(row['weight'] for row in selected
            if any(frame.startswith('0xffff') for frame in row['stack'])) / total_weight
        report['kernel_symbol_limit'] = (
            'Kernel addresses are recorded but lack resolved function names; '
            'do not assign these samples to a specific VM/compressor routine.')
    legends = [table.get('swift-table', '') for table in toc.findall('.//table')
               if 'metricLegend:' in table.get('swift-table', '')]
    if legends:
        report['native_metric_legend'] = legends[0].split('metricLegend:', 1)[1].split('analysisModeName:', 1)[0]
    if mode == 'kernel':
        report['counter_scope'] = 'Time Profiler with kernel stacks; worker samples within computation window.'
    elif mode == 'l1d':
        totals, by_core = Counter(), defaultdict(Counter)
        for _, row in rows(directory / f'{name}-metrics-table.xml'):
            if row['process'][0] == pid and row['thread'][0] in tids:
                count = row['sum'] if row['sum'] != '' else 0
                totals[row['metric-name']] += count
                by_core[row['core']][row['metric-name']] += count
        def ratios(counts):
            return {'load_miss_events_per_1000_load_micro_ops':
                        1000 * counts['l1d_miss_ld_spec'] / counts['ld_uop_spec'],
                    'store_miss_events_per_1000_store_micro_ops':
                        1000 * counts['l1d_miss_st_spec'] / counts['st_uop_spec']}
        report.update(worker_counts=dict(totals), worker_counts_by_core_type={k: dict(v) for k,v in by_core.items()},
                      worker_ratios=ratios(totals), worker_ratios_by_core_type={k: ratios(v) for k,v in by_core.items()},
                      counter_scope='Whole worker thread lifetimes; main-thread preparation/output excluded. '
                      'Speculative micro-ops are not one-to-one cache accesses; these are not exact cache hit rates.')
    else:
        # CounterMetricByThread stores values in plot order, which differs from
        # metricLegend order. Decode the trace's mapping instead of assuming it.
        native = legends[0]
        index_mapping = dict((int(a), int(b)) for a,b in re.findall(
            r'(\d+):\s*(\d+)', native.split('areaGraphSepcIndexTometricIndex:', 1)[1].split(']', 1)[0]))
        labels = dict((int(i), label.strip()) for i,label in re.findall(
            r'index (\d+):\s*([^\n\\"]+)', report['native_metric_legend'].replace(r'\n', '\n')))
        aliases = {'Useful': 'useful', 'Instruction Processing Bottleneck': 'instruction_processing',
            'Instruction Delivery Bottleneck': 'instruction_delivery', 'Discarded Bottleneck': 'discarded',
            'Executing': 'executing', 'Execution Latency': 'execution_latency',
            'Critical L1D Cache Miss': 'critical_l1d_miss',
            'Critical L1D Cache Miss While Executing': 'critical_l1d_miss_while_executing'}
        names = [None]*4
        for legend_index, array_index in index_mapping.items():
            names[array_index] = aliases[labels[legend_index]]
        assert all(names) and len(set(names)) == 4, (index_mapping, labels)
        report['metric_array_order'] = names
        duration, sums = Counter(), defaultdict(lambda: [0.0]*4)
        for _, row in rows(directory / f'{name}-counters.xml'):
            if row['process'][0] != pid or row['thread'][0] not in tids:
                continue
            overlap = max(0, min(end, row['timestamp']+row['duration'])-max(start, row['timestamp']))
            if not overlap:
                continue
            assert len(row['value']) == 4 and all(0 <= x <= 10000 for x in row['value']), row
            core_type = 'Efficiency' if row['core'] < 4 else 'Performance'
            for key in ('all', core_type):
                duration[key] += overlap
                for i, number in enumerate(row['value']):
                    sums[key][i] += overlap * number/10000
        report.update(worker_instruction_ratios={key: dict(zip(names, (x/duration[key] for x in values)))
                                                for key,values in sums.items()},
                      worker_active_seconds_by_core_type={key: value/1e9 for key,value in duration.items()},
                      counter_scope='User-mode, worker-only time-series intervals clipped to sampled computation. '
                      'Ratios are duration-weighted Instruments bottleneck fractions, not wall-time percentages. '
                      'Core mapping confirmed by trace CPUInfo: cores 0-3 Efficiency, 4-7 Super/Performance.')
    return report


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--workers', type=int, nargs='+', default=[1, 2, 4, 8])
    parser.add_argument('--modes', nargs='+', choices=['bottlenecks', 'processing', 'l1d', 'kernel'],
                        default=['bottlenecks', 'processing', 'l1d'])
    parser.add_argument('--report-dir', type=Path, default=Path('results/profile-scaling'))
    parser.add_argument('--analyze-only', action='store_true')
    args = parser.parse_args()
    if any(worker < 1 for worker in args.workers):
        parser.error('Worker counts must be positive')
    root = args.report_dir.resolve()
    directory, traces = root/'hardware', root/'traces'
    directory.mkdir(parents=True, exist_ok=True)
    traces.mkdir(exist_ok=True)
    binary = Path('target/release/http-matcher').resolve()
    binary_hash = sha(binary)
    reference = json.loads(Path('results/baseline.json').read_text())['run']
    summary_path = root/'hardware-summary.json'
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {'runs': {}}
    sources = {str(path): sha(path) for path in Path('src').rglob('*.rs')}
    if any(traces.glob('*.trace')):
        if summary.get('binary_sha256') != binary_hash or summary.get('source_sha256') != sources:
            raise ValueError('Saved traces belong to a different binary/source snapshot. '
                             'Use a new --report-dir to record the changed matcher.')
    summary.update(status='running', binary_sha256=binary_hash,
        build_command='cargo rustc --release --locked --offline --bin http-matcher -- -C debuginfo=1',
        source_sha256=sources)
    summary_path.write_text(json.dumps(summary, indent=2)+'\n')
    for mode in args.modes:
        options_path = root/f'recording-options-{mode}.json'
        if not options_path.exists():
            options_path.write_text(json.dumps(recording_options(mode), indent=2)+'\n')
        for workers in args.workers:
            name = f'{mode}-{workers}'
            print(f'Hardware profile {name}', flush=True)
            trace, metrics_path = traces/f'{name}.trace', directory/f'{name}-metrics.json'
            output = directory/f'{name}-output.jsonl'
            if args.analyze_only and not metrics_path.exists():
                print('  No recording for this optional case; skipping.', flush=True)
                continue
            if not args.analyze_only:
                if not trace.exists():
                    command = [str(binary), '--mode', 'fast', '--workers', str(workers),
                               '--input', str(Path('data/requests').resolve()), '--output', str(output)]
                    launcher = 'exec '+shlex.join(command)+' 2> '+shlex.quote(str(metrics_path))
                    record = ['xcrun', 'xctrace', 'record', '--template',
                              'Time Profiler' if mode == 'kernel' else 'CPU Counters',
                              '--recording-options', str(root/f'recording-options-{mode}.json'),
                              '--output', str(trace), '--time-limit', '120s', '--no-prompt',
                              '--launch', '--', '/bin/sh', '-c', launcher]
                    monitor = Monitor(binary)
                    execute(record, directory/f'{name}-record.log', monitor)
                    (directory/f'{name}-vm.json').write_text(json.dumps({'pid': monitor.pid,
                        'sample_interval_seconds': .01, 'samples': monitor.samples})+'\n')
                    (directory/f'{name}-command.json').write_text(json.dumps(record, indent=2)+'\n')
                exports = [('toc', None), ('stacks', 'time-profile')]
                if mode == 'l1d':
                    exports += [('metrics-table', 'MetricTableForThread')]
                elif mode != 'kernel':
                    exports += [('counters', 'CounterMetricByThread')]
                for suffix, schema in exports:
                    destination = directory/f'{name}-{suffix}.xml'
                    if destination.exists() and destination.stat().st_size:
                        continue
                    command = ['xcrun', 'xctrace', 'export', '--input', str(trace), '--output', str(destination)]
                    command += ['--xpath', f'/trace-toc/run[@number="1"]/data/table[@schema="{schema}"]'] if schema else ['--toc']
                    execute(command, directory/f'{name}-export-{suffix}.log')
            report = analyze(directory, mode, workers)
            for field in ('requests', 'bytes', 'matched_requests', 'supported_patterns', 'skipped_patterns'):
                assert report['metrics_under_profiler'][field] == reference['metrics'][field], field
            digest = ordered_digest(output, reference['metrics']['requests'])
            assert digest == reference['output_digest'], 'Profile output differs from baseline'
            assert sha(output.with_suffix('.skipped.jsonl')) == reference['skipped_report_sha256']
            assert sha(binary) == binary_hash, 'Profiled binary changed'
            assert all(sha(path) == value for path,value in summary['source_sha256'].items()), 'Matcher sources changed'
            report.update(output_digest=digest, equals_baseline=True)
            summary['runs'][name] = report
            summary_path.write_text(json.dumps(summary, indent=2)+'\n')
            print('  Ratios:', json.dumps(report.get('worker_instruction_ratios', report.get('worker_ratios'))), flush=True)
            print('  Hot:', report['worker_top_leaf_functions'][:3], flush=True)
    summary.update(status='complete', completed_at=datetime.now(timezone.utc).isoformat())
    summary_path.write_text(json.dumps(summary, indent=2)+'\n')


if __name__ == '__main__':
    main()
