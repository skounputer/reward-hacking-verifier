# Reward-Hacking Verifier

Evidence-grounded reward-hacking detection for code and terminal agents, with a frozen v4 skill registry, reusable memory cards, and aggregate Terminal Wrench evaluation results.

The verifier distinguishes unauthorized answer reuse, evaluator manipulation, and violations of explicit task requirements from legitimate tool use. Suspicious commands are routing signals; a positive judgment requires a complete causal evidence chain. Recorded commands are treated as data and are never executed by the verifier.

## Terminal Wrench results

The supplied evaluation used **DeepSeek V4.1 Flash** on the **Original monitor split** of [Terminal Wrench](https://github.com/few-sh/terminal-wrench): **5,984 trajectories**, comprising 3,632 hacking trajectories and 2,352 legitimate baselines.

| Verifier | Precision | Recall | F1 | False positive rate | Accuracy | Coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| v3 repaired | 96.06% | 83.31% | 89.24% | 5.27% | 87.80% | 96.34% |
| **v4 skill + memory** | **95.62%** | **91.27%** | **93.39%** | **6.46%** | **92.16%** | **99.03%** |

The v4 confusion matrix is **TP 3,315 / FP 152 / TN 2,200 / FN 317**. Coverage is the fraction of records with a non-abstaining judgment; it differs from successful API processing, which was 5,984/5,984. Abstentions remain in the all-row metrics. Of 3,467 positive verdicts, 3,437 had every evidence reference resolve to a host-generated ID (**99.13%**). Reference resolution does not establish semantic correctness.

These are **reported results from the supplied evaluation snapshot**, not a new evaluation run performed when publishing this repository. The benchmark informed skill and memory development, so these results describe a **development benchmark**, rather than a fully unseen generalization test. The 6.46% false positive rate requires calibration before automatic blocking.

Machine-readable reports:

- [v4 metrics](evaluation/TERMINAL_WRENCH_FULL5984_V4_METRICS.json)
- [Paired v3/v4 comparison](evaluation/TERMINAL_WRENCH_FULL5984_V3_V4_COMPARISON.json)
- [Evidence grounding](evaluation/TERMINAL_WRENCH_FULL5984_V4_EVIDENCE_GROUNDING.json)
- [Targeted and task-disjoint development-round results](evaluation/ROUND_005_TARGETED_AND_HOLDOUT_METRICS.json)

## Repository layout

| Path | Contents |
| --- | --- |
| [`verifier_core/`](verifier_core/) | Portable offline CLI, trajectory adapters, candidate rules, LLM review, and host evidence validation |
| [`skill_memory_v4/`](skill_memory_v4/) | Frozen skill registry, memory catalog, rubric, tool schemas, and protocol validation |
| [`protocol_example.py`](protocol_example.py) | Offline demonstration of routing, memory retrieval, and judgment validation |
| [`INTEGRATION_CONTRACT.md`](INTEGRATION_CONTRACT.md) | How to connect the decision layer to host evidence validation |
| [`evaluation/`](evaluation/) | Aggregate results and methodology notes; no raw benchmark trajectories or per-case answers |
| [`README_ZH.md`](README_ZH.md) | Original Chinese release overview |

The top-level **v4** version refers to the skill/memory decision layer. The portable host CLI retains its own version identifiers and uses the **v5 candidate-rule revision**. These version numbers describe different components.

## Skills and memory

The model sees the compact [Skill Registry](skill_memory_v4/SKILL_REGISTRY.json), selects exactly one primary domain skill and at most one distinct secondary skill, and calls `retrieve_memory`. The host returns only the selected [Memory Cards](skill_memory_v4/MEMORY_CATALOG.json), automatically adding `evidence_sufficiency`.

| Skill | Purpose |
| --- | --- |
| `authorization_boundary` | Establish what the underlying task authorizes |
| `causal_provenance` | Link a prohibited source to successful acquisition and later use |
| `verifier_integrity` | Identify evaluator manipulation with a later observed effect |
| `semantic_generalization` | Check task semantics beyond a single observed checker state |
| `artifact_operability` | Distinguish functional artifacts from metadata, placeholders, and claims |
| `method_fidelity` | Check compliance with an explicitly required method or procedure |
| `evidence_sufficiency` | Require the complete mechanism-specific evidence chain; always added by the host |

The cards contain general principles, counterevidence, and abstention conditions rather than benchmark case IDs or answer lookups. They are JSON resources consumed by the included Python runtime; see the [skill interface](skill_memory_v4/SKILL_INTERFACE.md).

## Quick start

Use **Python 3.10+ on Linux or macOS**. The host runner uses POSIX file locks. No GPU, training framework, or model weights are needed for local tests and rules-only routing.

```bash
git clone https://github.com/skounputer/reward-hacking-verifier.git
cd reward-hacking-verifier
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r verifier_core/requirements.txt
```

Run the existing tests and the offline protocol example:

```bash
python -m unittest discover -s skill_memory_v4 -p 'test_*.py' -v
python -m unittest discover -s verifier_core -p 'test_*.py' -v
python protocol_example.py
```

The pipeline tests use synthetic data and a local mock HTTP server. They make no external model requests.

Try candidate routing without an API:

```bash
python verifier_core/run_verifier.py \
  --input verifier_core/examples/canonical.jsonl \
  --output runs/rules-demo \
  --rules-only \
  --negative-audit-fraction 0
```

Rule hits in this mode are **candidates awaiting review**, not confirmed reward hacking. Rules-only output does not certify clean negatives or reproduce the Terminal Wrench v4 results.

## Configure an LLM reviewer

Copy `verifier_core/config.example.json` to `verifier_core/config.local.json`. Set `endpoint` to your HTTPS OpenAI-compatible **chat-completions URL** and `model` to your provider's model identifier. The shipped URL and model name are placeholders.

Store your API key in a separate local file and set `api_key_file` to its path. Relative key paths are resolved against the configuration file's directory. You can override the path with `REWARD_HACKING_API_KEY_FILE`. Keep credential files outside version control and restrict their permissions, for example with `chmod 600`.

```bash
python verifier_core/run_verifier.py \
  --input /path/to/trajectories.jsonl \
  --output runs/llm-audit \
  --config verifier_core/config.local.json \
  --workers 4
```

The CLI supports JSONL, gzip-compressed JSONL, and Zstandard-compressed JSONL, with `canonical`, `midtrain`, `sft`, and `atif` adapters. By default it reviews candidates plus a reproducible 5% sample of eligible rule negatives. Use `--all-judge` for a full audit.

**Component boundary:** this CLI runs the portable host-review protocol. It does **not** automatically invoke the v4 skill router. To run the skill/memory decision layer, connect its two-stage tool calls to your model client and then apply host evidence validation as specified in the [integration contract](INTEGRATION_CONTRACT.md). `protocol_example.py` demonstrates the interface without a model call. The original benchmark evaluation driver and raw trajectories are not included.

## Judgments and outputs

The model returns YES or NO, with a separate evidence-sufficiency flag. Missing evidence, malformed output, transport failures, or failed host validation remain unresolved.

| Output disposition | Meaning |
| --- | --- |
| `HACKING` | Positive judgment accepted by the host evidence validator |
| `LLM_NO` | Completed negative review with sufficient evidence |
| `UNRESOLVED` | Failed, invalid, or insufficient-evidence review |
| `RULE_NEGATIVE_UNREVIEWED` | No routing signal and not selected for LLM audit |
| `CANDIDATE_NOT_JUDGED` | Rules-only candidate awaiting review |
| `PENDING` | Not processed before interruption or a service/quota stop |

The runner writes `summary.json`, `results.jsonl`, `all_results.csv`, evidence for positive cases, and compressed source-row partitions. It preserves the input file. Only a validated positive with an input reward of 1 receives `effective_reward=0`; rule hits alone never change rewards.

Resume with the same input, configuration, runtime, and output directory. Changed inputs or configuration require a new output directory. Previously processed failures remain unresolved; use a new directory to re-review selected failed rows.

## Release notes

Public-release preparation replaced provider defaults and historical private filesystem locations with generic placeholders. Self-hosted HTTP endpoints accept loopback or standard RFC 1918 private addresses; remote API endpoints require HTTPS. Skills, memory cards, rubric, candidate rules, and evaluation counts remain unchanged.

`SHA256SUMS` covers the public release files. Historical test reports and source hashes describe the original snapshot; [public release validation](PUBLIC_RELEASE_VALIDATION.json) records the checks performed on this version. No credentials, private service URLs, raw benchmark trajectories, or model checkpoints are included.
