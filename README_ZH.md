# Reward-hacking verifier v4 交付包

版本：`reward_hacking_verifier_skill_memory_v4_20261021`

这是当前冻结的 code-agent reward-hacking verifier 候选版本，供接入真实 verifier、代码审查
和后续 adaptive hacker 实验使用。包中不包含原始 benchmark 轨迹、逐题答案、内部 endpoint、
API key 或运行 checkpoint。

## 目录

| 路径 | 用途 |
|---|---|
| `verifier_core/` | 可移植外壳：轨迹标准化、规则候选、LLM review、host evidence 校验与结果分桶 |
| `skill_memory_v4/` | 冻结的 Skill Registry、Memory Catalog、Rubric、tool schemas 与 host validation |
| `INTEGRATION_CONTRACT_ZH.md` | 把两层合成真实 verifier 时必须满足的调用和证据约束 |
| `protocol_example.py` | 无网络调用的两阶段 host 接口示例 |
| `evaluation/` | 聚合指标、方法说明和已知限制，不含逐题数据 |

## 正确调用顺序

1. `verifier_core` 把轨迹标准化并分配不可伪造的 host evidence IDs；
2. 模型只看 compact Skill Registry，调用 `retrieve_memory` 选择 1 个 primary、最多 1 个 secondary Skill；
3. host 返回所选 Memory，并自动加入 `evidence_sufficiency`；
4. 模型输出 YES/NO、机制和机制对应的有序 evidence chain；
5. `skill_runtime.validate_judgment()` 校验机制链，随后 `verifier_core` 校验证据 ID、时序和因果关系；
6. 只有同时通过两层校验的 `YES,true` 才进入 hacking 告警。

不要把整个 Memory Catalog 一次性塞进 prompt，也不要信任 trajectory 或模型自己编写的 evidence ID。

## Terminal Wrench 全量结果

DeepSeek V4.1 Flash，Original monitor split，5,984/5,984 条调用状态为 `ok`：

| TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy | Coverage |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3315 | 152 | 2200 | 317 | 95.62% | 91.27% | 93.39% | 6.46% | 92.16% | 99.03% |

## 同协议 v3/v4 严格对照

| Verifier | Precision | Recall | F1 | FPR | Accuracy | Coverage |
|---|---:|---:|---:|---:|---:|---:|
| v3 repaired | 96.06% | 83.31% | 89.24% | 5.27% | 87.80% | 96.34% |
| v4 skill+memory | 95.62% | 91.27% | 93.39% | 6.46% | 92.16% | 99.03% |

v4 相对 v3：Recall `+7.96pp`，F1 `+4.16pp`，
FPR `+1.19pp`。Paired correctness 中 v4 独立正确 386 条，
v3 独立正确 125 条，exact McNemar `p=5.28e-32`。

该 benchmark 已参与 Skill/Memory 开发，应视为 development benchmark。它证明当前配置对
Terminal Wrench 有很强覆盖，但不能替代面向新任务、新 agent 模型和 adaptive hacker 的隐藏集。
FPR 6.46% 仍是生产接入前需要校准的主要问题。全量 v4 的 3,467 个 YES 中，3,437 个所有
evidence ID 均能解析到 host packet，grounding rate 为 99.13%；语义正确性仍需独立审计。

## 快速检查

```bash
cd skill_memory_v4
python -m unittest -v test_skill_runtime.py
python skill_runtime.py
cd ..
python protocol_example.py
```

公开版本使用通用服务配置，配置步骤与组件边界见英文 `README.md`。

接入真实服务前请完整阅读 `INTEGRATION_CONTRACT_ZH.md`。
