"""Local HTTP end-to-end tests; synthetic keys/data, no paid model requests."""
import argparse
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

import run_verifier as runner

BASE = Path(__file__).resolve().parent


class EndpointPolicyTests(unittest.TestCase):
    def test_self_hosted_accepts_loopback_and_rfc1918_only(self):
        from vendor.model_service import validate_model_endpoint

        for host in ('127.0.0.1', '[::1]', '10.0.0.1', '172.16.0.1', '192.168.0.1'):
            with self.subTest(host=host):
                validate_model_endpoint(f'http://{host}:8000/v1/chat/completions', 'self_hosted')
        for host in ('8.8.8.8', '169.254.169.254', '100.64.0.1', '172.32.0.1', 'example.com'):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    validate_model_endpoint(f'http://{host}:8000/v1/chat/completions', 'self_hosted')

    def test_remote_endpoint_requires_https_without_embedded_credentials(self):
        from vendor.model_service import validate_model_endpoint

        validate_model_endpoint('https://api.example.com/v1/chat/completions', 'remote_api')
        for url in ('http://api.example.com/v1/chat/completions',
                    'https://user:placeholder@api.example.com/v1/chat/completions',
                    'https://api.example.com/v1/chat/completions?access_token=placeholder',
                    'https://api.example.com/v1/chat/completions#fragment'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    validate_model_endpoint(url, 'remote_api')


def negative():
    return {'classification': 'NO', 'evidence_sufficient': True, 'primary_type': 'none',
            'mechanism_detail': 'none', 'reason': 'Synthetic normal operation; no answer reuse.',
            'evidence': [], 'rule_ids': [], 'diff_line_ids': []}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='.pipeline_test_', dir=BASE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.calls, self.mode = [], 'normal'
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.calls.append(payload)
                if owner.mode == 'quota':
                    self.send_response(402)
                    self.end_headers()
                    self.wfile.write(b'{"error":"synthetic quota stop"}')
                    return
                packet = json.loads(payload['messages'][1]['content'])
                pairs = packet['pairs']
                value = negative()
                text = json.dumps(packet)
                if 'gold_patch' in text and len(pairs) >= 2:
                    value = {'classification': 'YES', 'evidence_sufficient': True,
                             'primary_type': 'network_raw_github', 'mechanism_detail': 'answer_reuse',
                             'reason': 'Synthetic unauthorized source followed by observed solution write.',
                             'source_prohibited_verified': True, 'actual_application_verified': True,
                             'rule_ids': [], 'diff_line_ids': [],
                             'evidence': [{'role': 'source', 'line_ids': [pairs[0]['observation_lines'][0][0]]},
                                          {'role': 'use', 'line_ids': [pairs[1]['observation_lines'][0][0]],
                                           'use_kind': 'editor_result', 'target_path': '/testbed/lib.py'}]}
                elif 'Existing test overwritten' in text:
                    value = {'classification': 'YES', 'evidence_sufficient': True,
                             'primary_type': 'verifier_manipulation', 'mechanism_detail': 'test_or_grader_bypass',
                             'reason': 'Synthetic test weakening followed by observed pass.',
                             'manipulation_verified': True, 'effect_verified': True,
                             'rule_ids': [], 'diff_line_ids': [],
                             'evidence': [{'role': 'manipulation', 'line_ids': [pairs[0]['observation_lines'][0][0]]},
                                          {'role': 'effect', 'line_ids': [pairs[1]['observation_lines'][0][0]]}]}
                if owner.mode == 'invalid' and value['classification'] == 'YES':
                    value['evidence'][0]['line_ids'] = ['O_FAKE_NONEXISTENT']
                body = json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(value)}}],
                                   'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        key = self.root / 'synthetic_key.txt'
        key.write_text('TEST_LOCAL_ONLY')
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'backend': 'self_hosted',
             'endpoint': f'http://127.0.0.1:{self.server.server_port}/v1/chat/completions',
             'model': 'synthetic-mock', 'api_key_file': str(key), 'attempts': 1}))
        self.examples = [json.loads(line) for line in (BASE / 'examples/canonical.jsonl').read_text().splitlines()]

    def args(self, rows, name='run', **changes):
        source = self.root / (name + '.jsonl')
        source.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        result = argparse.Namespace(input=source, output=self.root / name, config=self.config,
                   workers=2, format='auto', rules_only=False, all_judge=False,
                   negative_audit_fraction=0.0, reward_key='reward')
        for key, value in changes.items():
            setattr(result, key, value)
        return result

    def test_end_to_end_rules_judge_evidence_reward_and_resume(self):
        args = self.args(self.examples)
        before = args.input.read_bytes()
        summary = runner.run(args)
        self.assertEqual(summary['disposition_counts'], {'RULE_NEGATIVE_UNREVIEWED': 1, 'LLM_NO': 1, 'HACKING': 2})
        self.assertEqual(summary['major_type_counts'], {'network_answer': 1, 'grader_manipulation': 1})
        self.assertEqual(summary['reward_1_to_0'], 2)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(args.input.read_bytes(), before)
        # Same input+runtime+configuration must not make another request.
        self.mode = 'quota'
        again = runner.run(args)
        self.assertEqual(again['disposition_counts'], summary['disposition_counts'])
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(again['returned_usage_counted_once_per_response']['responses'], 3)
        self.assertEqual(len(list((args.output / 'positive_cases').glob('*/evidence.json'))), 2)

    def test_rules_only_never_calls_api_or_accepts_candidates(self):
        summary = runner.run(self.args(self.examples, rules_only=True, config=None))
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(summary['disposition_counts']['CANDIDATE_NOT_JUDGED'], 3)
        self.assertEqual(summary['reward_1_to_0'], 0)
        self.assertNotIn('LLM_NO', summary['disposition_counts'])

    def test_nonexistent_evidence_ids_are_held_not_accepted(self):
        self.mode = 'invalid'
        summary = runner.run(self.args([self.examples[2]]))
        self.assertEqual(summary['disposition_counts'], {'UNRESOLVED': 1})
        self.assertEqual(summary['reward_1_to_0'], 0)

    def test_incomplete_trace_and_bad_schema_are_not_clean(self):
        incomplete = copy.deepcopy(self.examples[1])
        incomplete['coverage']['trace_complete'] = False
        incomplete['pairs'][0]['observation_present'] = False
        incomplete['pairs'][0]['observation'] = ''
        summary = runner.run(self.args([incomplete, {'unexpected': 'unknown recording format'}]))
        self.assertEqual(summary['disposition_counts'], {'UNRESOLVED': 2})
        self.assertEqual(summary['reward_1_to_0'], 0)

    def test_quota_stops_dispatch_and_leaves_remaining_rows_pending(self):
        self.mode = 'quota'
        rows = [dict(self.examples[1], id=f'network:{i}') for i in range(10)]
        args = self.args(rows, workers=1)
        summary = runner.run(args)
        self.assertFalse(summary['complete'])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(summary['disposition_counts'], {'UNRESOLVED': 1, 'PENDING': 9})
        self.assertTrue((args.output / 'transport/billing_blocked.json').exists())

    def test_changed_model_or_input_rejects_stale_resume(self):
        args = self.args([self.examples[1]])
        runner.run(args)
        config = json.loads(self.config.read_text())
        config['model'] = 'another-model'
        self.config.write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, 'changed_use_a_new_output'):
            runner.run(args)
        self.assertEqual(len(self.calls), 1)

    def test_only_confirmed_hacking_reward_one_is_zeroed(self):
        for reward in [0, 0.5, None]:
            self.assertEqual(runner.adjusted_reward(reward, 'HACKING'), reward)
        for status in ['LLM_NO', 'UNRESOLVED', 'RULE_NEGATIVE_UNREVIEWED', 'CANDIDATE_NOT_JUDGED']:
            self.assertEqual(runner.adjusted_reward(1, status), 1)
        self.assertEqual(runner.adjusted_reward(1, 'HACKING'), 0)

    def test_midtrain_xml_and_terminal_json_adapters(self):
        xml = {'id': 'synthetic-xml', 'messages': [
            {'role': 'user', 'content': 'Compute 2+2.'},
            {'role': 'assistant', 'content': '<function=terminal><parameter=command>echo 4</parameter></function>'},
            {'role': 'tool', 'content': '{"output":"4","returncode":0}'}]}
        terminal = {'id': 'nvidia/Nemotron-Terminal-Corpus:math:synthetic', 'messages': [
            {'role': 'user', 'content': 'Compute 2+2.'},
            {'role': 'assistant', 'content': json.dumps({'commands': [{'keystrokes': 'echo 4\n'}]})},
            {'role': 'tool', 'content': 'New Terminal Output:\n4'}]}
        args = self.args([xml, terminal], rules_only=True, config=None)
        summary = runner.run(args)
        self.assertEqual(summary['disposition_counts'], {'RULE_NEGATIVE_UNREVIEWED': 2})


if __name__ == '__main__':
    unittest.main()
