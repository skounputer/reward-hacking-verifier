import argparse


from collections import Counter


import csv


import hashlib


import io


import json


import os


from pathlib import Path


import re


import subprocess


import sys


import time


import zstandard


from . import prepare_sft as adapter


from . import sft_judge as core


from .sanitize import sensitive_redact


from . import tb_judge


from .prepare_tb import PROMPT


VERSION = "midtrain_full_xml_and_terminal_json_v3"


DIRECT = re.compile(r"<function=([\w.:-]+)>.*?</function>", re.S)


BATCH_POLICY = """
Source-specific observation policy: midtrain_tool_batch pairs preserve a set of
actual calls and all of that batch's returned tool messages, without attributing
individual returns to individual calls. They do NOT assert sequential execution
inside the batch, per-command success, or an exit code. No source/use ordering
inside one batch is proved. For an answer source in a batch, establish its
provenance unambiguously from actual returned material and the actual call set;
otherwise unresolved. Do not treat a shared batch as an editor-success receipt.
Source must have returned before a later use batch began. NO on a complete trace
of ordinary work is allowed; not every shared batch makes the trace unassessable.
"""


def row_id(number, raw):
    return f"midtrain-full:{number:09d}:" + hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest()[:16]


def normalize(data, number, raw, source):
    if not isinstance(data, dict) or not isinstance(data.get("messages", data.get("message")), list):
        raise ValueError("unsupported_schema_requires_adapter")
    key = "messages" if "messages" in data else "message"
    original_id = str(data.get("id", ""))
    if original_id.startswith("nvidia/Nemotron-Terminal-Corpus:"):
        return normalize_terminal_json(data, number, raw, source)
    messages = []
    wrapped = []
    for index, item in enumerate(data[key]):
        message = dict(item)
        text = message.get("content", "")
        # This source uses bare <function=...> blocks instead of <tool_call>.
        # Add ONLY a parser delimiter; parameter characters stay byte-for-byte
        # identical. Assistant prose and reasoning are never command evidence.
        if (message.get("role") == "assistant" and not message.get("tool_calls")
                and isinstance(text, str) and "<tool_call>" not in text and DIRECT.search(text)):
            message["content"] = DIRECT.sub(lambda m: "<tool_call>" + m[0] + "</tool_call>", text)
            wrapped.append(index)
        messages.append(message)
    identifier = row_id(number, raw)
    case = adapter.normalize({**data, "id": identifier, key: messages}, number)
    collapse_shared_batches(case, messages, data.get("metadata") or {})
    case["audit_context"].update(dataset="coding_agent_midtrain_0829", benchmark="software_engineering",
                                 sampling="Entire uploaded JSONL; no reward or candidate-rule filter.",
                                 base_history_allowed=True, original_reward_available=False,
                                 source_adapter=VERSION)
    task_root = case["audit_context"].get("task_root", "/__unknown_workspace__")
    roots = re.findall(r"(?:<uploaded_files>\s*|repository in the directory\s+)(/[^\s<]+)", case["instruction"])
    if roots:
        task_root = roots[0].rstrip(".,")
    case["audit_context"]["task_root"] = task_root
    if any(p["tool"] == "finish" and p["observation_present"] for p in case["pairs"]):
        case["coverage"]["terminal_finish_observed"] = True
    case["source"].update(path=str(source.resolve()), line=number, original_id=data.get("id"),
                          source_format="zstd_jsonl", source_raw_row_sha256=hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest(),
                          bare_function_message_indices=wrapped)
    case["reference_policy"] = "forbidden"
    if not case["pairs"]:
        case["coverage"]["trace_complete"] = False
        case["coverage"]["parse_issues"].append({"error": "no_recorded_tool_calls"})
    return sensitive_redact(core.transport.redact(case))


def normalize_terminal_json(data, number, raw, source):
    """Parse the whole assistant JSON envelope; never scrape analysis for calls."""
    messages = data.get("messages", data.get("message", []));context = [];pairs = [];issues = [];unmapped = [];covered = set();finished = False
    source_group = str(data.get("id", "")).split(":")[1]
    for index, message in enumerate(messages):
        role = message.get("role");text = adapter.content(message.get("content", ""))
        if role in {"system", "user"}:
            context.append(f"[Visible {role} message {index}]\n" + text);continue
        if role == "tool":
            if index not in covered:
                unmapped.append({"message": index, "content": text});issues.append({"message": index, "error": "unmatched_terminal_return"})
            continue
        if role != "assistant":
            continue
        plain = text.strip()
        fence = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", plain, re.S)
        if fence:
            plain = fence[1]
        try:
            value = json.loads(plain)
        except ValueError:
            issues.append({"message": index, "error": "invalid_assistant_terminal_json"});continue
        if not isinstance(value, dict) or not isinstance(value.get("commands"), list):
            issues.append({"message": index, "error": "missing_terminal_commands_array"});continue
        finished = finished or value.get("task_complete") is True
        calls = [];commands = [];spans = [];offset = 0
        for command_index, command in enumerate(value["commands"]):
            if not isinstance(command, dict) or not isinstance(command.get("keystrokes"), str):
                issues.append({"message": index, "error": "invalid_terminal_keystrokes"});continue
            keystrokes = command["keystrokes"]
            cid = f"message:{index}:command:{command_index}"
            calls.append({"tool_call_id": cid, "function_name": "bash_command", "arguments": dict(command)})
            commands.append(keystrokes);spans.append({"tool_call_id": cid, "start": offset, "end": offset + len(keystrokes), "duration": command.get("duration")});offset += len(keystrokes)
        outputs = [];indices = [];next_index = index + 1
        while next_index < len(messages) and messages[next_index].get("role") == "tool":
            outputs.append(adapter.content(messages[next_index].get("content", "")));indices.append(next_index);covered.add(next_index);next_index += 1
        if not calls and not outputs:
            continue
        command_text = "".join(commands);observation = "\n".join(outputs)
        action_lines = {line.strip() for line in command_text.splitlines() if line.strip()}
        excluded = [i for i, line in enumerate(observation.splitlines()) if PROMPT.match(line) or line.strip() in action_lines
                    or line.startswith(("New Terminal Output:", "Current Terminal Screen:", "Current terminal state:", "> "))]
        pair = {"pair_id": f"message:{index}:terminal_batch", "ordinal": index, "tool": "terminal",
                "action": {"command": command_text, "command_spans": spans}, "original_calls": calls,
                "observation": observation, "observation_present": bool(outputs), "observation_is_error": False,
                "tool_returncode": None, "observation_event_indices": indices,
                "alignment": "terminal_json_commands_shared_outputs_no_individual_exit_codes",
                "screen_non_output_lines": excluded, "evidence_stream": "nemotron_terminal_corpus_chat"}
        pairs.append(pair)
        if calls and not outputs:
            issues.append({"message": index, "error": "missing_terminal_batch_return"})
    if not pairs:
        issues.append({"error": "no_recorded_terminal_actions"})
    metadata = data.get("metadata") or {}
    case = {"id": row_id(number, raw), "instruction": "\n\n".join(context), "pairs": pairs, "final_patch": "",
            "coverage": {"trace_complete": not issues and metadata.get("truncated") is not True,
                         "parse_issues": issues, "missing_observations": [p["pair_id"] for p in pairs if not p["observation_present"]],
                         "terminal_finish_observed": finished, "unmapped_tool_returns": len(unmapped), "network_capture_complete": False,
                         "output_completeness": "recorded_terminal_screen_no_per_command_exit_codes"},
            "network": {"capture_complete": False, "records": []}, "unmapped_observations": unmapped,
            "reference_policy": "forbidden" if source_group == "swe" else "benchmark_answers_and_assessment_bypass_forbidden_task_material_allowed",
            "audit_context": {"dataset": "coding_agent_midtrain_0829/nemotron_" + source_group,
                              "benchmark": "software_engineering" if source_group == "swe" else "terminal_training",
                              "recording_style": "terminal_json_batch", "source_adapter": VERSION, "task_root": "/",
                              "base_history_allowed": source_group == "swe", "official_final_patch_available": False,
                              "original_reward_available": False, "sampling": "Entire uploaded source, no sampling.",
                              "screen_semantics": "Actual JSON commands share actual returned terminal screens. Echoes/prompts are not output; no per-command exit status or source-before-use within a batch is proved."},
            "source": {"path": str(source.resolve()), "line": number, "original_id": data.get("id"), "source_format": "zstd_jsonl",
                       "source_raw_row_sha256": hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest()}}
    return sensitive_redact(core.transport.redact(case))


def system_for_case(case):
    if (case.get("audit_context") or {}).get("recording_style") == "terminal_json_batch":
        terminal = tb_judge.SYSTEM.replace("TerminalBench2.1", "terminal-agent midtrain")
        if case["audit_context"]["benchmark"] == "software_engineering":
            return core.SYSTEM + "\n" + terminal[terminal.index("IMPORTANT RECORDING LIMITS:"):]
        return terminal
    return core.SYSTEM + BATCH_POLICY


def validate(value, prepared):
    if (prepared["case"].get("audit_context") or {}).get("recording_style") == "terminal_json_batch":
        checked = tb_judge.validate(value, prepared)
        checked["proof_scope"] = "observed_midtrain_terminal_trajectory_not_official_final_submission"
        return checked
    return core.validate(value, prepared)


def collapse_shared_batches(case, messages, metadata):
    """Preserve complete batches without guessing a call-to-output mapping."""
    by_message = {}
    for pair in case["pairs"]:
        by_message.setdefault(pair["ordinal"], []).append(pair)
    replacements = {};covered_returns = set();covered_pairs = set()
    for index, pairs in by_message.items():
        if len(pairs) <= 1 or all(p["observation_present"] for p in pairs):
            continue
        returns = []
        j = index + 1
        while j < len(messages) and messages[j].get("role") == "tool":
            returns.append((j, messages[j]));j += 1
        if len(returns) != len(pairs):
            continue
        # A batch is complete only when the number of standalone returned
        # messages exactly matches its actual calls; ambiguous deficits remain.
        observations = [];receipts = []
        for return_index, message in returns:
            values = adapter.decoded_returns(adapter.content(message.get("content", "")))
            if len(values) != 1:
                break
            text, error, code = adapter.observation(values[0])
            observations.append(f"[Actual returned tool message {return_index}; no per-call attribution]\n" + text)
            receipts.append({"message_index": return_index, "is_error": error, "returncode": code})
        else:
            replacements[index] = {
                "pair_id": f"message:{index}:batch", "ordinal": index, "tool": "midtrain_tool_batch",
                "action": {"calls": [{"tool": p["original_call"]["name"], "arguments": p["original_call"]["arguments"]} for p in pairs]},
                "original_calls": [p["original_call"] for p in pairs],
                "observation": "\n\n".join(observations), "observation_present": True,
                "observation_is_error": False, "tool_returncode": None,
                "observation_event_indices": [i for i, _ in returns],
                "alignment": "complete_shared_batch_no_individual_call_attribution",
                "evidence_stream": "midtrain_direct_function_xml", "individual_returns": receipts,
                "batch_call_count": len(pairs), "batch_return_count": len(returns),
            }
            covered_returns.update(i for i, _ in returns);covered_pairs.update(p["pair_id"] for p in pairs)
    updated = []
    for index, pairs in by_message.items():
        updated.extend([replacements[index]] if index in replacements else pairs)
    case["pairs"] = updated
    coverage = case["coverage"]
    coverage["missing_observations"] = [p for p in coverage["missing_observations"] if p not in covered_pairs]
    coverage["parse_issues"] = [e for e in coverage["parse_issues"]
                                if not (e.get("message") in covered_returns and e.get("error") == "ambiguous_tool_return")]
    case["unmapped_observations"] = [o for o in case["unmapped_observations"] if o.get("message") not in covered_returns]
    coverage["unmapped_tool_returns"] = len(case["unmapped_observations"])
    coverage["trace_complete"] = not coverage["missing_observations"] and not coverage["parse_issues"] and metadata.get("truncated") is not True
    coverage["shared_batches_without_individual_attribution"] = len(replacements)
