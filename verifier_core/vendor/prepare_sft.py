from collections import Counter, defaultdict


import hashlib


import json


from pathlib import Path


import re


CALL = re.compile(r'<tool_call>\s*<function=([\w.:-]+)>(.*?)</function>\s*</tool_call>', re.S)


PARAM = re.compile(r'<parameter=([\w.:-]+)>(.*?)</parameter>', re.S)


def content(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return '\n'.join(x.get('text', '') for x in value if isinstance(x, dict) and x.get('type') == 'text')
    return json.dumps(value, ensure_ascii=False)


def unwrap_parameter(text):
    # The source serializer adds one newline on each side, not whitespace trim.
    if text.startswith('\n'): text = text[1:]
    if text.endswith('\n'): text = text[:-1]
    return text


def calls(message):
    found = [];errors = []
    structured = message.get('tool_calls') or []
    if structured:
        for j, call in enumerate(structured):
            function = call.get('function', call)
            arguments = function.get('arguments', {})
            if isinstance(arguments, str):
                try: arguments = json.loads(arguments)
                except ValueError: errors.append('invalid_arguments_json');arguments = {'unparsed_arguments': arguments}
            if not isinstance(arguments, dict):
                errors.append('nonobject_arguments');arguments = {'unparsed_arguments': arguments}
            found.append({'id': call.get('id'), 'name': function.get('name', 'unknown'), 'arguments': arguments})
        return found, errors
    text = content(message.get('content', ''))
    for match in CALL.finditer(text):
        params = {m[1]: unwrap_parameter(m[2]) for m in PARAM.finditer(match[2])}
        residue = PARAM.sub('', match[2]).strip()
        if residue: errors.append('unparsed_xml_call_body')
        found.append({'id': None, 'name': match[1], 'arguments': params})
    if text.count('<tool_call>') != len(found): errors.append('unparsed_xml_call')
    if not found and not errors:
        plain = re.sub(r'^\s*<think>.*?</think>\s*', '', text, count=1, flags=re.S).strip()
        try: value = json.loads(plain)
        except ValueError: value = None
        # Some strict360 messages store a bare bash argument object. Require
        # the whole non-thinking message, not a JSON example inside prose.
        if (isinstance(value, dict) and isinstance(value.get('command'), str)
                and set(value) <= {'command', 'timeout', 'description'}):
            found.append({'id': None, 'name': 'bash', 'arguments': value,
                          'format': 'bare_command_object_tool_name_inferred'})
    return found, errors


def normalized_action(call):
    name = call['name'].lower();a = dict(call['arguments'])
    if name in {'bash', 'terminal', 'execute_bash', 'run'}:
        return 'terminal', {**a, 'command': a.get('command', a.get('cmd', a.get('bash', ''))), 'original_tool': call['name']}
    if name in {'write', 'write_file'}:
        return 'write_file', {'command': 'write', 'path': a.get('path', a.get('file_path', a.get('filename'))),
                              'content': a.get('content', a.get('file_text', a.get('text', ''))), 'original_tool': call['name']}
    if name in {'edit', 'edit_file'}:
        edits = a.get('edits')
        if isinstance(edits, str):
            try: edits = json.loads(edits)
            except ValueError: pass
        return 'edit_file', {'command': 'edit', 'path': a.get('path', a.get('file_path')), 'edits': edits,
                            'old_str': a.get('old_str', a.get('old_string', a.get('oldText'))),
                            'new_str': a.get('new_str', a.get('new_string', a.get('newText'))), 'original_tool': call['name']}
    if name in {'read', 'read_file'}:
        return 'file_editor', {'command': 'view', 'path': a.get('path', a.get('file_path')), 'original_tool': call['name']}
    return name, a


def decoded_returns(text):
    decoder = json.JSONDecoder();position = 0;values = []
    while position < len(text):
        while position < len(text) and text[position].isspace(): position += 1
        if position == len(text): break
        try: value, end = decoder.raw_decode(text, position)
        except ValueError: values = [];break
        if not isinstance(value, dict) or not any(k in value for k in ['output', 'stdout', 'is_error', 'returncode']):
            values = [];break
        values.append(value);position = end
    if values: return values
    matches = list(re.finditer(r'<returncode>(-?\d+)</returncode>\s*<output>(.*?)</output>', text, re.S))
    if matches and not text[:matches[0].start()].strip():
        gaps = [text[a.end():b.start()] for a, b in zip(matches, matches[1:])]
        if not any(gap.strip() for gap in gaps):
            values = [{'returncode': int(m[1]), 'output': m[2]} for m in matches]
            footer = text[matches[-1].end():].strip()
            if footer and not footer.startswith('Your previous response reached'):
                return [{'output': text}]
            if footer: values[-1]['controller_feedback'] = footer
            return values
    return [{'output': text}]


def observation(value):
    output = value.get('output', value.get('stdout', value.get('content', '')))
    text = content(output)
    if value.get('stderr'): text += '\n[stderr]\n' + content(value['stderr'])
    code = value.get('returncode', value.get('exit_code'))
    if isinstance(code, str) and re.fullmatch(r'-?\d+', code): code = int(code)
    error = value.get('is_error') is True or isinstance(code, int) and code != 0
    return text, error, code


def terminal_submit(pair):
    command = (pair['action'].get('command') or '').strip()
    command = re.sub(r'^cd\s+[\w./-]+\s*&&\s*', '', command)
    return pair['tool'] == 'terminal' and bool(re.fullmatch(
        r'echo\s+COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT(?:\s*&&\s*cat\s+[\w./-]+)?', command))


def patch_from_pair(pair):
    if pair['tool'] != 'terminal' or pair.get('observation_is_error'): return ''
    command = pair['action'].get('command', '').strip()
    command = re.sub(r'^cd\s+[\w./-]+\s*&&\s*', '', command)
    if not re.match(r'^git\s+(?:(?:--no-pager|-C\s+[\w./-]+)\s+)*diff\b', command): return ''
    if '--no-index' in command or any(x in command for x in ['git fetch', 'git show', 'curl ', 'wget ']): return ''
    lines = pair['observation'].splitlines();start = next((i for i, line in enumerate(lines) if line.startswith('diff --git ')), None)
    if start is None: return ''
    result = []
    for line in lines[start:]:
        if line.startswith('[stderr]'): break
        if (not line or line[0] in ' +-\\' or line.startswith(('diff --git ', 'index ', '@@ ', 'new file mode ',
                'deleted file mode ', 'old mode ', 'new mode ', 'similarity index ', 'rename from ', 'rename to ', 'Binary files '))):
            result.append(line)
        else: break
    return '\n'.join(result) + '\n' if any(x.startswith('+++ b/') for x in result) else ''


def normalize(row, line_number):
    messages = row.get('message', row.get('messages', []));pairs = [];pending = [];issues = []
    context = [];unmapped = [];expected_terminal = []
    for index, message in enumerate(messages):
        role = message.get('role');text = content(message.get('content', ''))
        if role in {'system', 'user'}:
            context.append(f'[Visible {role} message {index}]\n' + text)
        elif role == 'assistant':
            parsed, errors = calls(message);issues.extend({'message': index, 'error': e} for e in errors)
            for j, call in enumerate(parsed):
                tool, action = normalized_action(call)
                pair = {'pair_id': f'message:{index}:call:{j}', 'ordinal': index, 'tool': tool, 'action': action,
                        'original_call': call, 'observation': '', 'observation_present': False,
                        'observation_is_error': False, 'observation_event_indices': [], 'evidence_stream': 'sft_chat'}
                pairs.append(pair);pending.append(pair)
        elif role == 'tool':
            values = decoded_returns(text);call_id = message.get('tool_call_id')
            matched = [p for p in pending if p['original_call'].get('id') == call_id] if call_id else []
            alignment = 'explicit_tool_call_id'
            if len(matched) != 1:
                latest = max((p['ordinal'] for p in pending), default=-1)
                current = [p for p in pending if p['ordinal'] == latest]
                named = [p for p in current if len(values) == 1 and values[0].get('tool', '').lower() == p['original_call']['name'].lower()]
                if len(named) == 1:
                    matched = named;alignment = 'unique_tool_name_in_latest_call_group'
                elif len(values) == len(current) and current:
                    matched = list(current);alignment = 'positional_exact_envelope_count'
                elif len(current) == 1 and len(values) == 1:
                    matched = list(current);alignment = 'single_pending_call'
                else:
                    unmapped.append({'message': index, 'content': text});issues.append({'message': index, 'error': 'ambiguous_tool_return'})
                    continue
            if len(matched) != len(values):
                unmapped.append({'message': index, 'content': text});issues.append({'message': index, 'error': 'return_count_mismatch'})
                continue
            for pair, value in zip(matched, values):
                output, error, code = observation(value)
                pair.update(observation=output, observation_present=True, observation_is_error=error,
                            observation_event_indices=[index], tool_returncode=code, alignment=alignment,
                            observation_receipt={k: v for k, v in value.items() if k in {'is_error', 'returncode', 'exit_code', 'tool'}})
                if value.get('controller_feedback'):
                    pair['controller_feedback'] = value['controller_feedback']
                pending.remove(pair)
    missing = []
    for pair in pending:
        if terminal_submit(pair) and pair['ordinal'] >= len(messages) - 2:
            expected_terminal.append(pair['pair_id'])
        else: missing.append(pair['pair_id'])
    metadata = row.get('metadata') or {};mixture = metadata.get('sft_mixture') or {};source = mixture.get('source') or {}
    dataset = source.get('dataset', 'unknown');instruction = '\n\n'.join(context)
    benchmark = 'reverse_engineering' if 'reverse-engineering benchmark' in instruction else 'software_engineering'
    task_root = '/testbed' if dataset == 'strict360' else '/app' if dataset == 'deepswe11' else '/__unknown_workspace__'
    explicit_root = re.search(r'\bWork only in\s+(/[^\s.`]+)', instruction)
    if explicit_root:
        task_root = explicit_root[1]
    elif dataset == 'nonpython_mindforge':
        for pair in pairs[:4]:
            command = pair['action'].get('command', '')
            match = re.search(r'\b(?:cd|ls|git\s+-C)\s+(/(?:testbed|app|workspace))\b', command)
            if match: task_root = match[1];break
            if command.strip() == 'pwd' and re.fullmatch(r'/[\w./-]+\s*', pair['observation']):
                task_root = pair['observation'].strip();break
    patches = [(p, patch_from_pair(p)) for p in pairs];patches = [(p, text) for p, text in patches if text]
    last_patch, patch = patches[-1] if patches else (None, '')
    return {'id': row['id'], 'instruction': instruction, 'pairs': pairs, 'final_patch': patch,
            'coverage': {'trace_complete': not missing and not issues and metadata.get('truncated') is not True,
                         'missing_observations': missing, 'parse_issues': issues, 'terminal_submit_without_return': expected_terminal,
                         'terminal_finish_observed': bool(messages and messages[-1].get('role') == 'assistant'),
                         'unmapped_tool_returns': len(unmapped), 'network_capture_complete': False},
            'network': {'capture_complete': False, 'records': []},
            'audit_context': {'dataset': dataset, 'benchmark': benchmark, 'task_root': task_root,
                              'base_history_allowed': dataset != 'strict360',
                              'patch_basis': 'most_recent_observed_local_diff' if patch else 'not_available',
                              'patch_pair_id': last_patch['pair_id'] if last_patch else None,
                              'official_final_patch_available': False, 'original_reward_available': False},
            'source': {'path': str(SOURCE), 'line': line_number, 'original_id': source.get('original_id'),
                       'source_dataset': dataset, 'source_row_sha256': source.get('row_sha256')},
            'unmapped_observations': unmapped}


SOURCE = Path("<provided-input>")
