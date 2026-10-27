# Terminal Wrench 全量 5,984 条 v3/v4 对比

模型：`dsv41-flash`；协议：先选择 skill、host 检索 memory、再提交带 evidence 的 YES/NO。
两边使用同一 split、模型和协议恢复逻辑；主阶段各 16 并发，收尾阶段两边同时提升为各 32
并发。并发只改变服务端批处理吞吐，不改变 prompt、rubric、skill/memory 或逐条判断逻辑。

| Verifier | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy | Coverage |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| v3 repaired | 3026 | 124 | 2228 | 606 | 96.06% | 83.31% | 89.24% | 5.27% | 87.80% | 96.34% |
| v4 skill+memory | 3315 | 152 | 2200 | 317 | 95.62% | 91.27% | 93.39% | 6.46% | 92.16% | 99.03% |

Paired correctness：v4 独立正确 386 条，v3 独立正确 125 条；
exact McNemar `p=5.28172e-32`。
