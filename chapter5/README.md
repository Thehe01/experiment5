# 第五章：漏洞与攻击技术关联预测

用户已于 2026-10-10 确认全部推荐方案并要求开始。规范见 [spec.md](spec.md)，可执行预算见 [config.json](config.json)，文件绑定见 [registration.json](registration.json)。当前独立分支为 `codex/chapter5-v1-20261010`。

主任务是已有节点之间缺失 `exploited_by` 边的排序。使用六类实体、五类关系，保留来源确认事实、规则对齐和未核验预测的区别。完整扫描固定 Enterprise ATT&CK 19.2 提交，明确 CVE/直接利用的官方过程记录进入来源确认集合，歧义、否定和利用后活动另存 pending；继承第四章 Train/Dev 冻结标签。NVD 提供 CWE 和 vulnerable CPE；原始配置逻辑、版本范围与引用检索状态均保存。来源确认不等同于独立人工 IAA。

按 CVE 分组，目标比例 70/15/15，新的 Test 排除仓库记录中已曝光的 CVE。采集完成后依据预设上下文资格条件划分与冻结；稀有技术保留 Train 覆盖，无法形成有效划分则报告失败。所有技术（含子技术）进入完整冻结候选域。留出目标边及其逆向副本不会进入训练邻接或重构损失，战术与阶段只由技术定义/固定规则产生。

| 实验臂 | 选择与重复 |
|---|---|
| Frequency、CWE Frequency | 只统计训练目标边；CWE 无已知训练支持时退回全局频率 |
| DistMult | 8 个开发配置，固定开发种子；选优后 5 个种子 |
| R-GCN + DistMult | 2 层、4 bases，8 个开发配置；选优后 5 个种子 |
| 三个 R-GCN 消融 | 分别移除产品、CWE、战术与阶段；复用主 R-GCN 参数，各 5 个种子 |
| C4 预测图补充 | 21 篇旧 Dev 的真实 ProTeGi_Full 预测替换 C4 Gold 边；共享官方扩充。DistMult/R-GCN 各 5 种子，复用主参数 |

两个学习主模型共享三元组、类型约束负采样和加权重构目标。目标关系系数 1；每个上下文关系系数 1/4，消融删除对应项，不改变目标系数。负采样不碰撞已知正例，目标负例的 CVE 头只来自 Train。主指标为 filtered macro-CVE MRR，另存 Hits@1/3/10、分技术指标、逐边名次及固定种子均值/标准差。并列采用平均名次。所有主/补充运行完成后统一评价 Test；不要求 R-GCN 必须优于基线。

实际运行入口：[CPU 工作流](https://github.com/Thehe01/experiment4/actions/workflows/chapter5-cpu-v1.yml)。工作流固定 CPU Torch 2.9.1、Python 3.12.14 和依赖版本，先验收再采集；有界请求与原子检查点支持续跑。全量来源、账本、图、字典、split、模型、当前/最佳状态、优化器和随机状态保存到 Actions artifact，并在 `chapter5/runs/chapter5-v1-20261010/` 保存校验分片和可读结果。新增模型 API 调用为 0；不启动第四章推理。

```bash
python -m pip install -r chapter5/requirements-cpu.txt
python -m unittest discover -s chapter5 -t . -p 'test_*.py' -v
python -m chapter5.verify
python -m chapter5.campaign --out /absolute/path/chapter5-state
```

独立 GitHub runner 在采集前持久预占。正常失败可从归档续跑；输入、代码、运行库或检查点摘要改变时拒绝恢复。runner 突然丢失且未留下封存证据时，保持 uncertain 阻断，不回退成零预算新运行。

最终 `models/result.json` 保存已冻结 Test 的结果与描述性 CVE bootstrap 区间，`models/ranks/` 支持复算。`models/unverified_candidates.json` 仅是候选预测，状态 `UNVERIFIED`，原始排序分数不表示事实置信度。小样本、稀有类、引用失败和 C4 预测覆盖均在结果中单列。

这是第五章独立关系恢复实验。第四章原有正式 Test/IAA 缺口、冻结结果、activation 分支及 main 保持原状。
