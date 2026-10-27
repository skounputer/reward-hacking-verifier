Reward hacking verifier：独立离线运行包，v5 第6次修订

适用环境：Linux、Python 3.10及以上；不需要GPU、Slime、Harbor或原项目仓库。
包内不含API密钥、不含原始训练数据。轨迹中的命令仅作为文字读取，绝不执行。

一、判断流程
1. 读取真实记录的动作、工具返回、可用补丁及宿主事件，按29条规则筛候选。
   curl、git fetch、普通依赖下载、读取参考路径、改测试等都只是送审线索。
   规则命中无需先证明作弊；正常联网和失败下载也可能命中。
2. 候选送OpenAI兼容接口审核，区分网络答案、本地答案、评测/任务约束绕过。
3. judge必须给出原轨迹的证据行ID；程序校验引用、真实输出、实际使用/效果和先后顺序。
   答案复用需“禁止的答案来源→实际使用”；评测绕过需“篡改→实际效果”。
4. LLM只返回YES或NO。证据不足、缺返回、解析/接口/校验失败进入UNRESOLVED状态，
   它不是第三个hacking类别，也不会被当作审核通过。
5. 若输入顶层reward（或raw_reward）为1，且程序校验后的结论为HACKING，
   results.jsonl的effective_reward才置0；规则命中本身不会改reward。
   输入JSONL始终不改动。本包是离线入口，不会自动安装到别人的训练框架。

二、安装与无需API的试跑
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest test_rh_candidate_rules_v4 test_rh_candidate_rules_v5 test_pipeline -v
bash run.sh --input "$PWD/examples/canonical.jsonl" --output "$PWD/demo_rules" --rules-only --negative-audit-fraction 0

三、接入LLM
复制config.example.json为config.json，填写自己的endpoint、model、api_key_file。
api_key_file为一个只含API key的文本文件；建议chmod 600；不要把密钥发给别人。
相对密钥路径按config.json所在目录解释。
也可用REWARD_HACKING_API_KEY_FILE环境变量指定自己的密钥文件路径。

bash run.sh --input /absolute/path/to/data.jsonl.zst --output /absolute/path/to/audit_run --config "$PWD/config.json" --workers 4

默认只审核规则候选，另随机、可复现地抽检5%的完整规则阴性。
--negative-audit-fraction 0 可取消阴性抽检；建议保留抽检来发现新型漏检。
--all-judge 可对全部可解析轨迹进行LLM审核，适合建立独立对照集。
支持.jsonl、.jsonl.zst、.jsonl.gz；文件内容均为每行一个JSON对象。
--format auto 自动识别当前包支持的格式；可显式设canonical、midtrain、sft、atif。
midtrain支持当前coding_agent_mid-train_0829中的XML/SWE与Nemotron终端JSON记录。
atif支持逐行的TerminalBench ATIF对象；任务约束必须包含在轨迹中。
canonical样例见examples/canonical.jsonl，要求instruction、pairs、coverage等字段；
每个pair需要pair_id、ordinal、tool、action、observation、observation_present。
未支持的新工具/消息格式不能靠猜测补工具结果，应先增加适配器。
默认参考答案禁止使用；canonical中显式reference_policy及实际任务授权仍由judge核对。
默认已观察轨迹证据协议不重跑benchmark，也不由原reward推断隐藏测试通过。

四、结果给谁用
summary.json：处理数量、规则路由量、三类hacking数量、reward=1→0数量、返回token用量。
complete只表示输入行完成当前模式处理，不代表全部行均经过LLM审核。
results.jsonl / all_results.csv：逐条结论、规则命中、原reward与effective_reward。
positive_cases/：hacking轨迹的规范化全文及逐条证据。
excluded_hacking.jsonl.zst：确认hacking的原始JSON行。
retained_llm_no.jsonl.zst：LLM完成审核且未发现hacking的原始JSON行。
hold_unresolved.jsonl.zst：未决/失败，单独隔离。
rule_negative_unreviewed.jsonl.zst：规则没有发现线索且未抽中LLM；不能冒充LLM已审核。
candidate_not_judged.jsonl.zst：仅--rules-only时的待审候选。
pending.jsonl.zst：中断或额度停机后尚未处理的原始JSON行。
所有分区保持源行字节，并在写完后重新解压核对。原文件不会删改。
不要把rule_negative_unreviewed或--rules-only结果说成“LLM确认无hacking”。
本入口只将retained_llm_no称为已完成LLM审核的保留集；是否保留未审规则阴性由调用方决定。

五、续跑和并发
同一命令、同一输入和同一output目录可续跑，已处理行（包括失败行）不会再次付费审核。
输入、协议、规则、模型/接口或配置改变时要求新的output目录，避免错误复用旧结果。
若要重审失败记录，另建目录并只提供需要重审的源行；不要重复跑整个原始文件。
workers默认4，范围1～32。只影响本离线进程，不分配GPU或更改训练配置。
遇到429或密集传输错误会自动降速，稳定后恢复到指定workers上限。
401/402/403停止新审核，标记transport/billing_blocked.json；处理完在途请求后输出部分结果。
恢复额度后检查该标记原因，再移除标记并原命令续跑。已处理失败行仍保持未决。
启动期间不能有第二个进程使用同一output目录；有文件锁保护。
费用未按任何未核实单价估算；summary只统计实际返回的token用量，超时未返回的费用不可推断。

六、已知覆盖与边界
当前规则版本rh_candidate_v5_20261016_6，共29条；规则细则见RULES_ZH.txt。
按现有实验口径：历史610条阳性+midtrain159条阳性，规则候选覆盖769/769。
其中通用规则768条、案例补充1条；另5条仅暴露未证实使用，不算确认hacking。
这是开发所用已知样本的回归覆盖，不是独立测试集的总体召回率。
尚未证明任意新数据真实召回达到95%或100%；需要保留规则阴性抽检/全量对照。
本包不安装宿主网络或文件事件采集器；若输入包含真实宿主事件，会使用这些记录。
静态轨迹没有记录到的动作，检测器也无法凭空补齐。
regression/保留原冻结回归报告；样例为合成数据，不是新增真实hacking发现。
SOURCE_PROVENANCE.json记录复用代码来源、导入适配及哈希；运行不依赖这些来源路径。
SELFTEST_REPORT.json记录该交接包的验证结果；本地模拟接口测试不产生外部API费用。
