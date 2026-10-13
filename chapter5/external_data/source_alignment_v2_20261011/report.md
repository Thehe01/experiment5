# 来源口径统一 v2：2026-10-11

**可由现成来源核验的口径统一已完成。** 原有880个开发CVE的31父技术标签全部从固定CTID源记录重建成功；619个重合CVE的统一视图采用这些标签，73条原始集合差异都有逐项处理依据。保留12个CVE的20个论文额外标签为UNKNOWN，它们的真实适用性还没有完整裁决。因此，结果是**统一项目表示与隔离争议**，不是宣布全部标签差异都已证实为错误。

## 处理结果

| 项目 | 结果 |
|---|---:|
| 原开发CVE的CTID来源重建 | 880/880吻合；原标签修改0 |
| 重合CVE规范化视图 | 619；规范化后与原项目标签差异0 |
| 原始差异CVE及逐项来源记录 | 73；原差异原样保留 |
| 论文额外标签 | 20个CVE-技术对，涉及12个CVE，保存UNKNOWN |
| 多标签版本CVE | CVE-2011-4106、CVE-2014-6271；按CTID来源统一，保留各原版本 |
| 外部跨域来源冲突 | 2条隔离；858外部候选→856 |
| 新版本总CVE数 | 1736：原880＋外部856 |
| 有范围正例CVE/标签边 | 1706 / 3166 |
| 每折候选监督 Train / Dev | 1556 / 150；固定31类，Train最少17正例 |

旧数据仍有30个仅背景CVE；这些样本保持背景角色。三个Dev划分和固定主要类23保持原定义。

## 统一规则与来源证据

1. 使用CTID原始CSV固定提交191e87005a51be1e28983b0fa64adcb367e9aa30，以及Mappings Explorer固定提交a85e55af3c9fa55359a98621745b9b039a088bec中的KEV07.28.2025、ATT&CK16.1记录。原始字节、Git对象和Apache许可证完整保存在 [ctid-source-inputs.zip](ctid-source-inputs.zip)。完整SHA及来源位置见 [协议](protocol.json)和输出manifest。
2. 只在原880开发CVE和858登记外部CVE的范围内抽取标签证据，折叠到已有31个Enterprise父技术ID。CTID阶段字段、原技术ID、CSV行/KEV对象下标、来源提交和参考链接均保留。原数据集合必须与源重建逐条相同，出现意外差异就停止生成。
3. 作者CSV的同CVE视图以CTID标签为项目规范表示。CTID有而论文未记的标签从源记录恢复；论文额外但该CTID记录未支持的标签保存UNKNOWN。UNKNOWN不加入正例，也不视为已确认负例；后续训练要读取输出negative-exclusions.json。真实标注遗漏或范围差异尚不能由来源优先级证明。
4. 未与CTID同域记录重合的856条外部样本保留原作者标签，明确标记“外部人工整理来源，未由本轮CTID重新裁决”。这次没有为它们生成AI新标签，不能称为全部语义已验证。

73条原始差异中共有79次“原标签有、作者变体缺失”的标签出现，其中22次只由后来的KEV源补充支持，其余有原CTID CSV支持。这里是**变体级标签出现次数**，不是不同CVE数。一个原CSV单元格为TT1565；按上游使用的技术ID提取形式取得T1565，保留原字面值与定位。这解释了来源解析差异，不修改原CSV。

例如CVE-2008-2992，论文记录T1203；CTID旧CSV有T1203，KEV记录有T1204.002，统一父标签为T1203/T1204。CVE-2021-21166的CTID记录为JavaScript利用与客户端执行，对应T1059/T1203；作者另记T1110/T1189，这两个标签保留待核验。Google原始分析与CTID的浏览器/JavaScript说明相符，本轮未据网页内容新造技术标签。

## 两条Mobile来源样本的隔离

| CVE | CTID源技术 | 论文Enterprise标签 | 新版本处理 |
|---|---|---|---|
| CVE-2017-0493 | T1461、T1533 | T1005 | 待跨域证据，隔离 |
| CVE-2019-7287 | T1404 | T1068 | 待跨域证据，隔离 |

MITRE官方资料确认上述三个源ID属于Mobile域。见 [domain-evidence.json](domain-evidence.json)。仅凭相近技术名称没有建立Mobile→Enterprise对应关系。程序只对这三个已核验Mobile ID使用跨域隔离，其他超出31类范围的CTID技术会停止并要求另行核验，避免把普通Enterprise范围外技术错判为Mobile。隔离条目的作者标签、NVD背景及原始CTID证据都保留。

## 数据包与复现

[来源统一数据包](source-aligned-candidates-v2.zip)内含：
- outputs/records.jsonl：1736条规范记录；850＋856条有目标标签；
- outputs/author-aligned-overlap.jsonl：619条规范化视图及原变体/出处；
- outputs/resolutions.jsonl：73条处理依据；
- outputs/unknown-author-labels.jsonl和negative-exclusions.json：20个待核验标签对；
- outputs/quarantine.jsonl：2条跨域隔离记录；
- outputs/folds.json、summary.json、manifest.json：原角色边界、候选覆盖与哈希；
- verification.json：独立复核回执。

代码、协议、原始来源包和[复现说明](README.md)单列保存。新版本尚未接入已登记训练引擎；目前冻结引擎没有上述UNKNOWN排除处理，不能直接用新版本继续旧run。下一次科学训练需支持这个排除表并独立登记，不能通过只换输入包绕过旧绑定。

## 验收与限制

- 新行为测试9项通过，接入前处理19项回归通过，原扩展图数据10项回归通过，共38项本轮最终检查。TDD先出现8项未实现失败；新增域边界回归先出现1项行为断言失败，再通过修复。见 [checks.json](checks.json)和保存日志。
- 独立逐项检查确认CTID源重建880项吻合、原CWE/CPE保持、73个证据定位可以回到原记录、619规范视图一致、UNKNOWN表与原作者差集相符、原Train/Dev和155保护ID边界保持。9份输出两次生成字节一致；篡改CTID包和覆盖已有输出均被拒绝。见 [verification.json](verification.json)。
- 原完成比较36模型单位、23冻结源文件及登记绑定重新通过；原分数和未晋级判定不变。见 [original-completion-verification.json](original-completion-verification.json)。本轮不重放模型检查点或评分。
- 619个重合CVE在原扩容时就没有重复加入新Train；统一它们并不代表已测得性能改善。2条跨域隔离改变候选输入，但没有重训或估计新的MRR。
- 原来源的技术/年份/产品分布差异仍然存在；数据分布本身不能靠复制标签消除。92条NVD CWE多源分歧仍待核验，本轮未改其CWE/CPE或刷新元数据。
- 本轮科学训练、模型推断/API、保留组标签比较与评分0，没有真人独立标注/IAA或最终盲测结论。20个UNKNOWN的真实语义仍需原始证据/人工裁决；本版本已经确保它们不会被自动认定为正例或确认负例。

来源资料：[CTID原映射](https://github.com/center-for-threat-informed-defense/attack_to_cve/blob/191e87005a51be1e28983b0fa64adcb367e9aa30/Att%26ckToCveMappings.csv)、[CTID KEV固定记录](https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/a85e55af3c9fa55359a98621745b9b039a088bec/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json)、[CIRCL来源说明](https://huggingface.co/datasets/CIRCL/vulnerability-attack-techniques)、[Google CVE-2021-21166分析](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-21166.html)。直接Git网页读取失败的资料已通过GitHub连接器取得固定字节，未使用变化网页替换旧实验输入。

