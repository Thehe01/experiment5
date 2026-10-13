# C3 离线准备 v1：新最终 Test 与真实人类 IAA

状态：`offline_preparation_complete_materials_missing`。仅提供材料框架，不是新Test冻结、人工IAA完成或正式运行登记。模型预算0，formal/Test门禁关闭，C4最终Dev结果v1原字节保持。

## 已有依据

沿用仓库[标注协议](../../ANNOTATION_GUIDELINE.md)和[模式契约](../../scripts/schema.py)：`chapter3-no-capec-v1`、`4.6-mcpu-mention-fact-dual-layer-v1`、`chapter3-boundary-sync-v2`。文本层只标Configuration、Vulnerability、Weakness、AttackTechnique和affects、instantiates、exploited_by。AttackTactic/KillChainPhase及映射关系不加入文本Gold。任何新政策应独立版本登记，不能静默更新旧协议或旧结果。

旧63 Train / 21 Dev / 21 Test均已参与开发；105篇不能重新命名为新最终Test。

## 文件与用途

| 文件 | 需要填写的材料 | 当前是否完成真实材料 |
|---|---|---|
| [known_exposure_index.json](known_exposure_index.json) | 已知旧数据/来源索引，供排除历史暴露 | 只有元数据索引，不是新候选审计 |
| [source_selection.template.json](templates/source_selection.template.json) | 新来源、选样规则、样本量及理由、覆盖计划、去重/分组、IAA范围、冻结与后续登记 | 未填写；候选/入选均0 |
| [annotation_A.template.json](templates/annotation_A.template.json) | 第一名真实人类的逐文档独立标注 | 未填写 |
| [annotation_B.template.json](templates/annotation_B.template.json) | 第二名真实人类在同一原文上的独立标注 | 未填写 |
| [independent_human_evidence.template.json](templates/independent_human_evidence.template.json) | 实际匿名标注者ID、提交时间/原始文件哈希、独立访问证据 | 未填写 |
| [adjudication.template.json](templates/adjudication.template.json) | IAA计算后，对真实分歧逐条裁决和隔离记录 | 未填写 |
| [iaa_report.template.json](templates/iaa_report.template.json) | 裁决前原始版本的分层/分类型一致性统计 | 未计算；null不代表0或100% |

复制模板到新的独立候选/标注工作目录再填写，保留本次模板和所有独立原始提交；不要写入旧`data/annotations/gold/`或旧split/登记。模板不包含真实来源、标签、人工身份或人审声明，不能通过改状态字段变成已完成证据。

## 新来源选样标准

1. 先确定研究总体、资料语言/体裁/时间范围、来源采样方式、文档数及精度/覆盖理由。样本数不照搬旧Dev21篇，也不根据模型预测挑选“容易提升”的材料；本准备稿不凭空承诺统计功效。
2. 独立策展人在推理前固定来源和排除规则。优先可保存原始字节、来源链接及出版/获取时间的可靠公开资料；完整记录失败、候选与排除理由，不能只保留有利结果。
3. 比对[已知暴露索引](known_exposure_index.json)中的105篇、21条补充/参考资源记录和130条仓库来源文件元数据；继续补审历史提示、其他本地材料、镜像、译文、公告家族及版本更新。此索引未覆盖所有过去人工阅读/外部提示，不宣称全面无暴露。
4. 相同SHA、实质复制/近重复、同一公告家族重述按预先确定的分组规则隔离。相同CVE/产品需披露交集和事实重复，但不把“来源未用过”夸大为“未知CVE/产品能力”。换URL、文档ID或发布日期不能证明独立。
5. 在选择阶段用来源元数据与内容体裁制定覆盖计划；两名盲标后报告四类实体和三类直接关系的实际数量，稀有关系不足需如实报告。不得看到模型结果后补样或用模板挑战替代正式总体样本。
6. 先冻结规范化/解码流程和原文SHA256，再标注。字符区间固定为0-based、右端不包含；禁止标注后改变换行/Unicode/清洗方式而沿用旧偏移。
7. 在任何待评价推理前冻结来源、标签协议、文本/Gold哈希、样本/分组、隔离项、评分、提示/runtime、分析口径及新执行预算。预算与正式执行登记目前为空；原C4剩余额度不自动转为正式Test预算。
8. “新未见Test”限定项目开发历史与实际核验范围；基础模型预训练是否见过公开资料通常未知，需要在结果中保留该限制。

## 两名真实人类的独立流程

1. 预先声明IAA标注是整个新最终Test还是固定代表性子集，写明选样与覆盖理由。子集IAA不能写成全量IAA。标注前固定一致性口径、解释标准及任何拟用准入阈值；本稿不设置未经论证的数值门槛。
2. 两人使用相同原文、协议快照及官方规范化依据，独立工作；不查看待评模型预测、旧最终Gold或对方标签，不交流本批具体答案。标注者已有相关暴露需如实记录。实际匿名ID不同，并保存独立工作/访问与提交凭据；不保存账号凭据或私人联系方式。
3. 文本提及保留全部合法重复位置；Configuration按MCPU与直接affects作用域处理。规范化只核验原文明示身份，不能根据NVD配置反造文本关系。CPE的part/vendor/product、官方证据快照和哈希单列留存；组件/父族有多个互不等价候选时进入复核区。
4. 两份原始提交先各自封存哈希和时间；补正结构错误必须保留原提交及修订原因，不能覆盖成一份假“原始独立标注”。在任何裁决前计算IAA并封存报告及其输入绑定。
5. IAA后再裁决：记录A/B意见、原文证据、最终决定、协议依据和裁决者匿名ID；原标注不可改写。未决身份/边界/CPE统一按冻结隔离规则处理，不依据模型错例或评分选择。正式Gold不留未解决硬错误和复核候选。
6. 人工复裁完成、两份AI标注或复制最终Gold，均不能代替裁决前真实双人独立IAA。模板当前所有完成声明为false/未知，不属于人审证据。

## IAA报告口径草案

以下以同一文档内A/B的独立集合为单位。最终计算/准入方案仍需在实际标注前补齐并冻结；本次没有实现新的IAA程序，也没有运行formal Gold完整性脚本去打开旧Test标签。

- 严格实体键：`(doc_id, start, end, type)`，不比较两人本地实体ID。
- 严格关系键：`(doc_id, head_span_type, relation_type, tail_span_type)`；本地端点ID先解析为各自实体跨度/类型。证据字符串和证据偏移的分歧另列，不能被端点F1掩盖。
- 规范化事实键：`(doc_id, head_type, canonical_head_id, relation_type, tail_type, canonical_tail_id)`；使用冻结[评分器](../../scripts/eval_metrics.py)的canonical规范化，文档内确定性去重，不新增别名归并。
- 双人对称集合F1为`2 × |A ∩ B| / (|A| + |B|)`；跨文档先累计各集合计数/交集再算micro，类型和文档支持量单列。不要把F1写成基于真负例的Kappa，也不把A或B当作裁决后Gold。
- Configuration同时报告span+精确CPE的联合一致性，以及共同span/type上的规范化一致率；后者是条件一致率，不是Gold准确率或整体召回。
- 空支持、规范化缺失与候选区的处理需提前明确并单列计数；共同缺失ID不能被当作正确事实。当前评分器全空集合F1为0，这只是约定，不能解释成标注完全不一致或把空支持当100%一致。
- 报告实体mention、关系mention、规范化fact、分类型原始计数与分歧分布。若只有部分材料、协议/原文哈希不一致或不独立，报告不可计算/范围受限，不能填造IAA。

## 交给后续执行者的材料清单

- 新Test候选来源原始字节与链接、出版/获取时间、解码后文本及哈希；来源/暴露/重复审计与所有选择/排除记录。
- 选样规则、样本量及理由、覆盖计划、固定IAA范围与计算/解释口径。
- 两名真实标注者的独立原始文件、实际匿名ID、提交时间/哈希与独立性凭据。
- 裁决前IAA报告、真实分歧与裁决记录、最终Gold与官方CPE证据、冻结哈希。
- 新的正式评价登记、确切提示/代码/runtime/窗口/评分绑定、有界预算及适用运行授权；已有授权不重复询问，缺登记不自行运行。

## 当前阻塞与下一步

未收到新候选来源和真实双人标注，未开展候选来源审计、未冻结新Test、未计算IAA，未建立新的可执行formal登记。#3保持开放，#5正式结论依赖#3。下一步提交新候选来源与实际人工独立标注安排，先完成来源/选样/IAA口径冻结；不恢复旧C4模型作业。

本次验收见[回执](../../results/convergence_c3_v1/offline_preparation/verification.json)；所有旧冻结文件由远端tree对比保持原GitblobSHA，activation不移动，main不合并。
