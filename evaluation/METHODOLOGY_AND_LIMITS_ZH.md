# 评测范围与解释

## 官方全量

- Benchmark：Terminal Wrench Original monitor split
- 样本：3,632 hacking + 2,352 legitimate baseline
- Judge：DeepSeek V4.1 Flash
- 输出：YES/NO、机制、三段 evidence；unresolved 按未检出计入 all-row recall
- v4 状态：5,984/5,984 `ok`

v4 的 Precision 为 95.62%，Recall 为 91.27%，F1 为 93.39%，
FPR 为 6.46%。完整机器可读指标见 `TERMINAL_WRENCH_FULL5984_V4_METRICS.json`。

## 解释边界

本版本的 `method_fidelity` 和对应 Memory 来自该 benchmark 的失败簇，因此 5,984 条结果不是
未接触 benchmark 的最终泛化估计。后续应冻结本包，用新的任务、模型和 adaptive hacking 轨迹
建立 hidden split；禁止再用 hidden split 更新 Skill/Memory。

## 发布门槛建议

- 研究用 monitor：当前版本可作为冻结基线；
- 高召回离线审计：当前 Recall 已超过 90%；
- 自动阻断或生产告警：先在真实 legitimate 流量上校准，FPR 预算建议单独冻结；
- self-evolution 结论：必须报告 forward transfer、FPR、遗忘、evidence grounding 和每轮新增 Memory 数量。

## Evidence grounding

v4 的 3,467 个 YES 中，3,437 个所有引用均解析到真实 host T/A/O ID，
grounding rate 为 99.13%。该检查验证引用存在性，不等同于 evidence 的语义正确性。
