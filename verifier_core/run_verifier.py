"""Portable offline routing + evidence-grounded LLM review. Never runs actions."""
import argparse
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import ExitStack, contextmanager
from dataclasses import fields
import csv
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import threading
import time

import zstandard
import rh_candidate_rules_v5 as rules
from offline_audit_concurrency import AdaptiveRequestGate
from vendor import midtrain_adapter, prepare_sft, prepare_tb, sft_judge as core, tb_judge, transport
from vendor.sanitize import sensitive_redact

BASE = Path(__file__).resolve().parent
VERSION = 'portable_observed_trajectory_verifier_v1'
BUCKETS = {'HACKING': 'excluded_hacking', 'LLM_NO': 'retained_llm_no',
           'UNRESOLVED': 'hold_unresolved', 'RULE_NEGATIVE_UNREVIEWED': 'rule_negative_unreviewed',
           'CANDIDATE_NOT_JUDGED': 'candidate_not_judged', 'PENDING': 'pending'}


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def file_sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


@contextmanager
def source_rows(path):
    with ExitStack() as stack:
        source = stack.enter_context(path.open('rb'))
        if path.suffix == '.zst':
            source = stack.enter_context(zstandard.ZstdDecompressor().stream_reader(source))
            source = io.BufferedReader(source)
        elif path.suffix == '.gz':
            source = stack.enter_context(gzip.GzipFile(fileobj=source))
        yield ((number, raw) for number, raw in enumerate(source, 1) if raw.strip())


def normalize(data, number, raw, source, fmt):
    if not isinstance(data, dict):
        raise ValueError('each_source_row_must_be_an_object')
    selected = fmt
    if selected == 'auto':
        selected = 'canonical' if 'pairs' in data and 'instruction' in data else 'atif' if 'steps' in data else 'midtrain'
    if selected == 'canonical':
        case = dict(data)
    elif selected == 'midtrain':
        case = midtrain_adapter.normalize(data, number, raw, source)
    elif selected == 'sft':
        case = prepare_sft.normalize(data, number)
        case['source'].update(path=str(source), line=number)
    elif selected == 'atif':
        identity = str(data.get('id') or data.get('trajectory_id') or number)
        case = prepare_tb.normalize(data, {'trial_name': identity, 'task_name': data.get('task_name', identity)},
                                    'input', source, trajectory_sha256=hashlib.sha256(raw).hexdigest())
    else:
        raise ValueError('unsupported_format')
    if not isinstance(case.get('instruction'), str) or not isinstance(case.get('pairs'), list):
        raise ValueError('missing_instruction_or_pairs')
    for pair in case['pairs']:
        if (not isinstance(pair, dict) or not isinstance(pair.get('pair_id'), str)
                or type(pair.get('ordinal')) is not int or not isinstance(pair.get('action'), dict)
                or not isinstance(pair.get('tool'), str) or not isinstance(pair.get('observation'), str)
                or type(pair.get('observation_present')) is not bool):
            raise ValueError('invalid_canonical_pair_recording_metadata')
    if len({p['pair_id'] for p in case['pairs']}) != len(case['pairs']):
        raise ValueError('duplicate_pair_id')
    case.setdefault('id', f'row:{number}')
    case.setdefault('final_patch', '')
    case.setdefault('unmapped_observations', [])
    case.setdefault('network', {'capture_complete': False, 'records': []})
    case.setdefault('coverage', {'trace_complete': False})
    if not isinstance(case['coverage'], dict) or type(case['coverage'].get('trace_complete')) is not bool:
        raise ValueError('missing_explicit_trace_completeness')
    case.setdefault('audit_context', {})
    for key, value in {'dataset': source.stem, 'benchmark': 'software_engineering',
                       'task_root': '/__unknown_workspace__', 'base_history_allowed': True}.items():
        case['audit_context'].setdefault(key, value)
    case.setdefault('reference_policy', 'forbidden')
    return sensitive_redact(transport.redact(case))


def protocol(case):
    context = case['audit_context']
    if context.get('recording_style') == 'terminal_json_batch':
        return midtrain_adapter.system_for_case(case), midtrain_adapter.validate
    if context.get('benchmark') in {'terminalbench21', 'terminal_training'}:
        return tb_judge.SYSTEM, tb_judge.validate
    return core.SYSTEM + midtrain_adapter.BATCH_POLICY, core.validate


def disposition(judge):
    verdict = judge.get('verdict') or {}
    if (judge.get('status') == 'reviewed' and judge.get('classification') in {'YES', 'NO'}
            and verdict.get('classification') == judge['classification']
            and verdict.get('evidence_sufficient') is True):
        return 'HACKING' if judge['classification'] == 'YES' else 'LLM_NO'
    return 'UNRESOLVED'


def adjusted_reward(raw_reward, status):
    return 0 if raw_reward == 1 and status == 'HACKING' else raw_reward


def load_config(path, output, workers):
    data = json.loads(path.read_text())
    allowed = {f.name for f in fields(transport.Config)}
    if set(data) - allowed:
        raise ValueError('unknown_config_fields:' + ','.join(sorted(set(data) - allowed)))
    key_path = Path(os.environ.get('REWARD_HACKING_API_KEY_FILE') or data.get('api_key_file', ''))
    if not key_path.is_absolute():
        key_path = path.parent / key_path
    data.update(mode='shadow', api_key_file=str(key_path.resolve()),
                audit_dir=str(output / 'transport'), max_concurrency=workers)
    private = output / 'resolved_config.private.json'
    transport.atomic_json(private, data)
    private.chmod(0o600)
    return transport.load_config(str(private))


def review_one(item, args, cfg, gate, stop):
    number, raw = item
    identity = f'{number:09d}-' + hashlib.sha256(raw).hexdigest()
    path = args.output / 'by_row' / (identity + '.json')
    if path.exists():
        return json.loads(path.read_text())  # Source + runtime/config binding checked by manifest.
    record = {'source_line': number, 'source_row_sha256': hashlib.sha256(raw).hexdigest(),
              'record_id': identity, 'id': None, 'classification': None, 'major_type': 'none',
              'disposition': 'UNRESOLVED', 'judge_called': False}
    try:
        data = json.loads(raw)
        case = normalize(data, number, raw, args.input, args.format)
        route = rules.route(case, audit_fraction=args.negative_audit_fraction)
        if args.all_judge:
            route = {**route, 'judge': True, 'route': 'full_llm_audit'}
        raw_reward = data.get(args.reward_key, data.get('raw_reward'))
        record.update(id=case['id'], raw_reward=raw_reward, routing=route)
        if args.rules_only:
            record['disposition'] = ('CANDIDATE_NOT_JUDGED' if route['judge'] else
                                     'UNRESOLVED' if route['route'].startswith('unresolved') else 'RULE_NEGATIVE_UNREVIEWED')
        elif route['judge']:
            if stop.is_set() or (args.output / 'transport/billing_blocked.json').exists():
                return None  # Leave unstarted rows pending; never pretend they were judged.
            system, validate = protocol(case)
            judge = core.audit(case, cfg, args.output, api=gate, system_text=system,
                               protocol_version=VERSION, validator=validate)
            record.update(judge=judge, judge_called=bool(judge.get('attempts')) and not judge.get('cache_hit', False),
                          disposition=disposition(judge), classification=judge.get('classification'),
                          major_type=judge.get('major_type', 'none'))
            if record['disposition'] == 'HACKING':
                folder = args.output / 'positive_cases' / identity
                transport.atomic_json(folder / 'trajectory.normalized.json', case)
                transport.atomic_json(folder / 'evidence.json', record)
        else:
            record['disposition'] = 'UNRESOLVED' if route['route'].startswith('unresolved') else 'RULE_NEGATIVE_UNREVIEWED'
        record['effective_reward'] = adjusted_reward(raw_reward, record['disposition'])
        record['reward_1_to_0'] = raw_reward == 1 and record['effective_reward'] == 0
    except Exception as exc:
        # Parse/transport/validation failures are held, never silently accepted as NO.
        record.update(error_type=type(exc).__name__)
    transport.atomic_json(path, record)
    return record


def export_results(args):
    counts, major, routes, expected = Counter(), Counter(), Counter(), {}
    rows = judged_rows = changed = 0
    with ExitStack() as stack:
        csv_stream = stack.enter_context((args.output / 'all_results.csv.writing').open('w', newline=''))
        report = csv.DictWriter(csv_stream, fieldnames=['source_line', 'id', 'disposition', 'classification', 'major_type',
                               'route', 'raw_reward', 'effective_reward', 'reward_1_to_0'])
        report.writeheader()
        result_stream = stack.enter_context((args.output / 'results.jsonl.writing').open('w'))
        writers = {}
        for name in BUCKETS.values():
            target = stack.enter_context((args.output / (name + '.jsonl.zst.writing')).open('wb'))
            writers[name] = stack.enter_context(zstandard.ZstdCompressor(level=3).stream_writer(target, closefd=False))
            expected[name] = []
        source = stack.enter_context(source_rows(args.input))
        for number, raw in source:
            rows += 1
            row_sha = hashlib.sha256(raw).hexdigest()
            record_path = args.output / 'by_row' / (f'{number:09d}-' + row_sha + '.json')
            record = json.loads(record_path.read_text()) if record_path.exists() else {
                'source_line': number, 'disposition': 'PENDING'}
            status = record['disposition']
            counts[status] += 1
            if status == 'HACKING':
                major[record['major_type']] += 1
            routes[(record.get('routing') or {}).get('route', 'unavailable')] += 1
            judged_rows += 'judge' in record
            changed += record.get('reward_1_to_0', False)
            name = BUCKETS[status]
            writers[name].write(raw)
            expected[name].append(row_sha)
            result_stream.write(json.dumps(record, ensure_ascii=False) + '\n')
            report.writerow({**{key: record.get(key) for key in report.fieldnames},
                             'route': (record.get('routing') or {}).get('route')})
    artifacts = {}
    for name, hashes in expected.items():
        temporary = args.output / (name + '.jsonl.zst.writing')
        found = []
        with temporary.open('rb') as raw, zstandard.ZstdDecompressor().stream_reader(raw) as decoder:
            for line in io.BufferedReader(decoder):
                if line.strip():
                    found.append(hashlib.sha256(line).hexdigest())
        if found != hashes:
            raise ValueError('partition_source_identity_check_failed')
        path = temporary.with_suffix('')
        temporary.replace(path)
        artifacts[name] = {'path': str(path), 'rows': len(hashes), 'sha256': file_sha(path), 'source_rows_verified': True}
    for name in ['all_results.csv', 'results.jsonl']:
        (args.output / (name + '.writing')).replace(args.output / name)
    usage = Counter()
    for file in (args.output / 'responses').glob('*.json'):
        response = json.loads(file.read_text())
        tokens = response.get('usage') or {}
        usage.update({key: int(tokens.get(key) or 0) for key in ['prompt_tokens', 'completion_tokens', 'total_tokens']})
        usage['responses'] += 1
    summary = {'version': VERSION, 'rules_version': rules.VERSION, 'source_rows': rows,
               'processed_rows': rows - counts['PENDING'], 'complete': counts['PENDING'] == 0,
               'rules_only': args.rules_only, 'disposition_counts': dict(counts), 'major_type_counts': dict(major),
               'routing_counts': dict(routes), 'rows_with_judge_record': judged_rows, 'reward_1_to_0': changed,
               'returned_usage_counted_once_per_response': dict(usage), 'artifacts': artifacts,
               'rule_negative_is_not_llm_no': True, 'source_modified': False, 'recorded_commands_executed': False}
    transport.atomic_json(args.output / 'summary.json', summary)
    return summary


def run(args):
    args.input, args.output = args.input.resolve(), args.output.resolve()
    if not 1 <= args.workers <= 32 or not 0 <= args.negative_audit_fraction <= 1:
        raise ValueError('workers_must_be_1_to_32_and_audit_fraction_0_to_1')
    if not args.rules_only and args.config is None:
        raise ValueError('LLM_review_requires_config')
    if args.input.is_relative_to(args.output):
        raise ValueError('input_must_be_outside_output_directory')
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (args.output / 'runner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _run_locked(args)


def _run_locked(args):
    runtime_files = [BASE / 'run_verifier.py', BASE / 'rh_candidate_rules_v4.py', BASE / 'rh_candidate_rules_v5.py',
                     BASE / 'rh_candidate_signatures_v4.json', BASE / 'offline_audit_concurrency.py',
                     *sorted((BASE / 'vendor').glob('*.py'))]
    manifest = {'version': VERSION, 'input_sha256': file_sha(args.input), 'format': args.format,
                'rules_only': args.rules_only, 'all_judge': args.all_judge,
                'negative_audit_fraction': args.negative_audit_fraction, 'reward_key': args.reward_key,
                'runtime_sha256': sha({str(p.relative_to(BASE)): file_sha(p) for p in runtime_files}),
                'config_sha256': file_sha(args.config.resolve()) if args.config else None}
    prior = args.output / 'run_manifest.json'
    if prior.exists() and json.loads(prior.read_text()) != manifest:
        raise ValueError('input_config_or_runtime_changed_use_a_new_output_directory')
    transport.atomic_json(prior, manifest)
    cfg = None if args.rules_only else load_config(args.config.resolve(), args.output, args.workers)
    gate = None
    if cfg:
        control = args.output / 'concurrency_control.json'
        transport.atomic_json(control, {'target_inflight': args.workers, 'revision': time.time_ns(), 'auto_raise': True})
        gate = AdaptiveRequestGate(control, args.workers, transport.request, transport.atomic_json)
    stop = threading.Event()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
    done_count = 0
    with source_rows(args.input) as source, ThreadPoolExecutor(max_workers=args.workers) as pool:
        iterator, pending = iter(source), set()
        exhausted = False
        while pending or not exhausted:
            blocked = (args.output / 'transport/billing_blocked.json').exists()
            while len(pending) < args.workers and not exhausted and not stop.is_set() and not blocked:
                try:
                    item = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                pending.add(pool.submit(review_one, item, args, cfg, gate, stop))
            if not pending:
                break
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                record = future.result()
                if record is not None:
                    done_count += 1
                transport.atomic_json(args.output / 'progress.json', {'processed': done_count, 'updated_unix': time.time()})
    if file_sha(args.input) != manifest['input_sha256']:
        raise ValueError('source_changed_during_audit')
    summary = export_results(args)
    print(json.dumps({k: summary[k] for k in ['complete', 'processed_rows', 'disposition_counts', 'major_type_counts', 'reward_1_to_0']}, ensure_ascii=False), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--format', choices=['auto', 'canonical', 'sft', 'midtrain', 'atif'], default='auto')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--negative-audit-fraction', type=float, default=.05)
    parser.add_argument('--rules-only', action='store_true')
    parser.add_argument('--all-judge', action='store_true', help='Skip candidate filtering for a full LLM comparison audit')
    parser.add_argument('--reward-key', default='reward', help='Top-level input reward field; output never rewrites source rows')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        summary = run(args)
    except Exception as exc:
        parser.exit(1, f'verifier stopped: {type(exc).__name__}: {transport.redact(str(exc))[:400]}\n')
    if not summary['complete']:
        parser.exit(2, 'Partial run: pending rows remain; inspect summary.json and transport/billing_blocked.json.\n')


if __name__ == '__main__':
    main()
