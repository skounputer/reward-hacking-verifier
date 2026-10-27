import re


import shlex


from .prepare_tb import PROMPT


def single_line(call):
    if call.get('function_name') != 'bash_command': return None
    text = (call.get('arguments') or {}).get('keystrokes', '')
    if not text.endswith('\n') or len(text.splitlines()) != 1: return None
    text = text.strip()
    if any(c in text for c in ['$', '`', '\x1b', '\r']): return None
    return text


def tokens(text):
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars='><;&|')
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError: return []


def redirect_write(text, target):
    parts = tokens(text)
    return (len(parts) >= 4 and parts[0].startswith('/')
            and parts[-2:] == ['>', target]
            and all(not any(c in p for c in '<>;&|') for p in parts[:-2]))


def read_chain(text, target):
    """Allow wc metadata plus actual cat/head/tail, joined only with &&."""
    commands = re.split(r'\s*&&\s*', text)
    content = False
    for command in commands:
        parts = tokens(command)
        if parts == ['wc', '-l', target]: continue
        if not parts or parts[0] not in {'cat', 'head', 'tail'} or parts[-1] != target: return False
        if any(not re.fullmatch(r'-\d+|-n|\d+', p) for p in parts[1:-1]): return False
        content = True
    return content


def application_witness(item, entries, index, prepared):
    if item.get('use_kind') != 'local_readback': return None
    pair = entries[0]['pair'];target = item.get('target_path')
    if pair['tool'] != 'terminal' or not isinstance(target, str) or not target.startswith('/'): return None
    if ''.join((c.get('arguments') or {}).get('keystrokes', '') for c in pair.get('original_calls', [])
               if c.get('function_name') == 'bash_command') != pair['action'].get('command'): return None
    calls = [(i, single_line(c)) for i, c in enumerate(pair.get('original_calls', []))]
    lines = pair['observation'].splitlines()
    prompts = [(i, m, line[m.end():].strip()) for i, line in enumerate(lines) if (m := PROMPT.match(line))]
    actual_ids = [(ref, entry) for ref, entry in prepared['refs'].items()
                  if entry['index'] == index and entry['kind'] == 'observation']
    cited = {id(entry) for entry in entries if entry['kind'] == 'observation'}
    previous_commands = {line.strip() for prior in prepared['case']['pairs'][:index]
                         for line in prior['action'].get('command', '').splitlines()}
    for write_order, write in calls:
        if not write or not redirect_write(write, target) or write in previous_commands: continue
        wp = [n for n, _, command in prompts if command == write]
        if len(wp) != 1: continue
        for read_order, read in calls:
            if read_order <= write_order or not read or not read_chain(read, target): continue
            rp = [n for n, _, command in prompts if command == read]
            if len(rp) != 1 or rp[0] <= wp[0]: continue
            # No unseen or intervening shell command may write another value.
            if any(wp[0] < n < rp[0] for n, _, _ in prompts): continue
            end = next((n for n, _, _ in prompts if n > rp[0]), None)
            if end is None: continue  # Still running or missing return to shell.
            output = [(ref, e) for ref, e in actual_ids if rp[0] < int(ref.split('L')[-1]) < end
                      and e['text'].strip() and int(ref.split('L')[-1]) not in pair.get('screen_non_output_lines', [])]
            content = [(ref, e) for ref, e in output if not re.fullmatch(r'\s*\d+\s+' + re.escape(target) + r'\s*', e['text'])]
            if not content or not cited.intersection(id(e) for _, e in content): continue
            if not cited.issubset(id(e) for _, e in output): continue
            if any(re.search(r'(?i)(?:no such file|permission denied|cannot open|traceback|error:)', e['text']) for _, e in output): continue
            return {'prior_mutation_pairs': [pair['pair_id']],
                    'application_receipt': {'version': 'exact_prompt_write_read_v1', 'write_call_index': write_order,
                        'read_call_index': read_order, 'write_command': write, 'read_command': read,
                        'write_prompt_line': wp[0], 'read_prompt_line': rp[0], 'return_prompt_line': end,
                        'read_output_ids': [ref for ref, _ in output], 'per_command_returncode_inferred': False}}
    return None
