from collections import Counter,defaultdict


import hashlib


import json


from pathlib import Path,PurePosixPath


import re


import sys


import zipfile


from . import prepare_tb as adapter


from . import tb_judge as judge


PRIVATE=re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----',re.S)


TOKENS=re.compile(r'\b(?:sk-[A-Za-z0-9_-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|LTAI[A-Za-z0-9]{16,})\b')


def sensitive_redact(value):
    if isinstance(value,dict):return {k:sensitive_redact(v) for k,v in value.items()}
    if isinstance(value,list):return [sensitive_redact(v) for v in value]
    if not isinstance(value,str):return value
    def mask(match):return '[REDACTED_CREDENTIAL_SHA256:'+hashlib.sha256(match[0].encode()).hexdigest()[:16]+']'
    value=PRIVATE.sub(mask,value);return TOKENS.sub(mask,value)


def refresh_sanitized_screen_receipts(case):
    # Multiline PEM removal changes line/character offsets. Rebuild all offset
    # metadata from the sanitized actual calls, not from the unredacted screen.
    for pair in case['pairs']:
        commands=[];spans=[];offset=0
        for call in pair['original_calls']:
            if call.get('function_name')!='bash_command':continue
            args=call.get('arguments')or{};text=args.get('keystrokes','')
            commands.append(text);spans.append({'tool_call_id':call.get('tool_call_id'),'start':offset,'end':offset+len(text),'duration':args.get('duration')});offset+=len(text)
        pair['action']['command']=''.join(commands);pair['action']['command_spans']=spans
        action_lines={line.strip() for line in pair['action']['command'].splitlines() if line.strip()}
        pair['screen_non_output_lines']=[i for i,line in enumerate(pair['observation'].splitlines()) if adapter.PROMPT.match(line)
                    or line.strip() in action_lines or line.startswith(('Current Terminal Screen:','Current terminal state:')) or line.startswith('> ')]
    return case
