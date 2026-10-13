# HANDOFF — 第五章 v3 实验下降原因诊断

交接日期：2026-10-12，UTC+8。核对时间约11:48。范围仅为当前会话的第五章 v3 诊断、证据归档与状态同步。

## Goal and next-session focus

- 目标：解释v3扩容比较为何下降，保留可信负结果与可复现证据，给出下一项可检验候选。
- 下一会话的具体任务：先核对持久化状态，再完成能够恢复的诊断摘要及证据归档、同步开发分支的EXPERIMENT_PLAN。
- **关键现状：诊断计算与独立复核此前完成，但新的诊断文件和缓存未确认上传成功；工作区维护已清理这些未提交文件。此交接保留了对话中的验证记录和数字，不等于恢复了原始诊断证据包。**
- 不重新训练原36单位；不直接重新执行原144次诊断forward；不自动启动建议的9单位新模型候选。

## Repository/artifacts

仓库：[Thehe01/experiment4](https://github.com/Thehe01/experiment4)。以下分支HEAD在本次交接重新读取确认：

|对象|分支或提交|
|---|---|
|当前开发分支|codex/chapter5-public-dev-20261011|
|开发HEAD/完成复核|68e4d2fd09ece4a70c70b0c550e8ff144c03d29d|
|v3科学源提交|4f379b612b3d6cce5f8237b8103e866909ca7988|
|v3启动提交|244e217428e23c9bd019084171de40c49999c389|
|v3完成activation HEAD|a247a950412c517d4c80ff5bab7e46fece8b929e|
|v3 activation分支|codex/chapter5-resolved-activation-20261011|
|旧expanded activation分支HEAD|50905f65a09ec91f8ccedf099b71443e2d22c6f6|
|main HEAD|c71cfbdfcdb41dcd0fb59820619c14d87dadd7d4|

先读实际HEAD的AGENTS.md、EXPERIMENT_PLAN.md，处理新变化时重新核对，不能依赖这份快照直接覆盖分支。

已经持久保存、可以从GitHub恢复的材料：

- [v3科学规范](https://github.com/Thehe01/experiment4/blob/4f379b612b3d6cce5f8237b8103e866909ca7988/chapter5/resolved_dev/spec.md)。
- [v3配置](https://github.com/Thehe01/experiment4/blob/4f379b612b3d6cce5f8237b8103e866909ca7988/chapter5/resolved_dev/config.json)、同目录registration.json与data/paired-parent-v3.zip。
- [完成运行38152196348](https://github.com/Thehe01/experiment4/actions/runs/38152196348)，attempt1，completed/success，slot1完成全部36单位，slot2/3正常跳过。
- [完成复核报告](https://github.com/Thehe01/experiment4/blob/68e4d2fd09ece4a70c70b0c550e8ff144c03d29d/chapter5/resolved_dev/completion-review/README.md)。同目录verification.json、verify_completion.py、remote-tree.json、run.json与执行摘录。
- a247a950提交的chapter5/resolved_dev/runs/chapter5-resolved-dev-v3-20261011/：原comparison.json、report.md、status.json、session.json、manifest.json及51个state.part-*。
- 运行artifact ID：11707257200；名称chapter5-resolved-dev-slot-1-38152196348；原ZIP212,090,493字节，SHA256为15f7f7705188877b68edb2cdd754a92f0e1619427dd827df78701bfc7b6bb6b4。此前下载检查含298个成员、36个checkpoint.pt。
- artifact曾显示有效至2027-01-09。应重新查询是否仍可下载；Git永久分片是后备，不依赖artifact长期保留。

不可当成当前存在文件的历史本地路径：

- /workspace/scratch/740249c3d03b/chapter5_integrated/source/chapter5/diagnostics/resolved_v3_20261012/
- /workspace/scratch/740249c3d03b/chapter5_integrated/v3-diagnosis-work/results/
- 上述目录的analyze.py、helpers.py、verify.py、protocol.json、report.md、summary.json、next-candidate.md、diagnostic-evidence.zip，以及144个分数缓存，均在交接时未找到。
- 不能运行这些已清理路径中的命令，或声称其文件已保存到仓库。

## Current state

### 已完成且有Git持久证据：v3科学比较

- 1724可用CVE：原开发池868（838有范围标签、30仅背景）+外部Train-only856。
- 31个ATT&CK19.2 Enterprise父技术候选；每折固定主要类23。
- base监督Train691/691/690；augmented1547/1547/1546。两条件共用Dev147/147/148，共233不同CVE、442次出现。
- DistMult/R-GCN mixed ×两条件×三次留出×三个种子=36单位；500轮上限、30轮早停；实际全部patience早停，35–343轮。

|方法|base MRR|augmented MRR|配对差|改善|
|---|---:|---:|---:|---:|
|DistMult mixed|0.3816654267922884|0.36188018877070655|-0.01978523802158186|1/9|
|R-GCN mixed|0.39173425069270706|0.3550765962354105|-0.03665765445729659|0/9|
|Neighbor vote|0.46533919504374655|0.42860628842669285|-0.0367329066170537|三折均值|

v3扩容开发门槛失败，原判定必须保留。155保留组未评分，确认训练未启动。

### 此前已执行、但新的原始文件现已丢失：离线诊断

以下数字来自本会话已经返回成功的命令结果；本次交接没有重新执行诊断。原始诊断缓存未恢复前，要将它们标为“历史执行记录”，不能声称已从当前缓存重新验证。

- 用户授权：2026-10-12 09:32:43 UTC+8，“开始诊断”；后续“继续”要求收尾归档。
- 诊断协议名称chapter5-resolved-v3-diagnosis-20261012；历史protocol.json SHA256为3436ca91769341465b1937fc1cfd2864fb0da8e89bddd6fa976784d5dedb21f5。
- 用冻结权重执行144个forward：36原回放+36换CWE+36换CPE+36联合换背景；没有新训练、模型API、新标注或元数据刷新。
- 36原模型最佳检查点及11,868条原真关联排名完整复现；完整指标最大误差0。
- 36份简单基线独立公式复算并匹配原排名，最大指标误差1.1102230246251565e-16。
- 7项helpers行为测试先RED再GREEN；独立验证exit0，检查144个分数缓存、36单位、442条来源分解，保护ID169。
- 缓存篡改和输出覆盖均被拒绝。未重复执行未知模型调用。
- 从恢复的artifact状态按冻结pack_state代码重建原永久ZIP：212,300,186字节、51分片，ZIP及全部分片SHA256完全匹配原manifest；ZIP SHA256为2fd3c6b2bebf7ba50337f7a29383588e90adbfca7669c5811a4461ace26b0a28。
- 历史诊断代码/协议/注册binding：2f5883ad2c44d70d73a013adb061da9474b21cc8efe5424b603e536eb63b8f9a。它不是当前恢复证据，不能凭此反造旧账本。

### 已验证的诊断发现（历史计算记录）

1. **新增来源改变训练分布。** Train/Dev技术标签边归一化TV距离三折均值base0.03286463647703253，augmented0.11101243163273264，约3.38倍。各折都偏离。外部98.60%的CVE编号属于2020–2022，原838个有标签CVE为30.07%；编号年份不是发布时间或标注起源。

2. **同背景的标签分布不同。** 11种CWE在两来源各至少10个CVE。邻居分解442次出现：新增来源平均占38.57%权重，新增总权重87.22%来自CWE。对两来源均有正邻居权重的同330次出现配对，已观察Dev标签加权重合旧34.86%、新22.76%。这是部分标签的重合度，不是语义标签准确率。

|邻居覆盖分组|出现数|平均MRR差（按出现次数）|
|---|---:|---:|
|两来源都有邻居|330|-0.03717026893724435|
|只有旧邻居|32|0，完全不变|
|只有新增邻居|11|-0.04028643355268741|
|两来源都无邻居，回退全局先验|69|-0.051211309060261674|

全442次中215下降、116改善、111不变。来源票与全局先验改变都影响固定neighbor算法；不能把所有下降归为新增相似邻居。分组均值不是三折等权总体均值。

3. **扩展后模型更趋于共同技术排序。** 对每查询的31分数先去均值、除以自身population std，再量化共有平均技术分数形状的平方能量占比；不是准确率、注意力或因果贡献百分比。

|模型/条件|共同形状占比|原MRR|仅共同形状MRR|去共同形状MRR|
|---|---:|---:|---:|---:|
|DistMult base|95.25%|0.381665|0.362068|0.197309|
|DistMult augmented|99.44%|0.361880|0.356094|0.168723|
|R-GCN base|97.93%|0.391734|0.362655|0.163729|
|R-GCN augmented|99.76%|0.355077|0.348994|0.178656|

共同偏好包含有用先验，直接删掉会明显伤害MRR。高共性本身不能诊断为典型过平滑或某一个参数的错误。

4. **R-GCN仍利用背景，但扩展条件的排序敏感性减弱。** 每折只使用一个seed固定的无自身循环donor映射；同映射用于两条件及单独/联合置换。CWE实际bundle变化90.50%、CPE98.42%、联合100%。Train边、目标标签、节点索引与候选保持。

|R-GCN条件|原MRR|换CWE MRR / Top3集合变化|换CPE MRR / Top3集合变化|联合MRR / Top3集合变化|
|---|---:|---:|---:|---:|
|base|0.391734|0.356956 / 41.02%|0.380472 / 22.92%|0.348514 / 47.06%|
|augmented|0.355077|0.345160 / 19.47%|0.353490 / 1.74%|0.343976 / 20.45%|

该测试为固定权重下的传导图输入敏感性；逆边及共享节点会传播影响，不是训练因果贡献或新CVE归纳成绩。

DistMult三种置换的分数均完全不变，这是推断结构预期：无消息层，读取已学习的CVE ID向量。它不能证明训练时没利用背景，但新背景不会在固定权重推断端自动变成新查询向量。

结论边界：未发现原执行/评分错误；“分布不匹配”和“查询区分弱”有直接证据。不能唯一归因于标签错误、数据量太少或某模型参数。原Dev已用于早停与选择，不能当正式盲测。

### 尚未完成/当前阻塞：诊断归档

- 原计划上传7,454,079字节diagnostic-evidence.zip，159成员，153结果文件，其中144分数缓存。
- 该包历史SHA256：c55a29de2032a7f215a26c980c529b85c8fb729f98ea24c02c5d9fee845e81bc。
- 目标Git blob SHA：6fb79ea10485503395d7976bc271cd28a1984b00。
- 两次上传工具被用户中断，没有收到成功结果；没有执行新诊断的create_tree/create_commit/update_ref。
- 本次GET该blob返回404；开发HEAD仍为68e4d2fd09ece4a70c70b0c550e8ff144c03d29d，EXPERIMENT_PLAN仍只有v3完成复核。
- 本次Library检索未找到匹配的当前诊断包；返回的旧第五章快照是早期状态，不能替代新诊断缓存。
- 本次本地检查确认历史诊断目录、证据ZIP与results/verification.json已不在工作区。维护清理不是用户主动删除。

## Decisions and constraints

- 原科学源码、数据、注册、结果及失败判定保持字节。管理EXPERIMENT_PLAN可以更新，但不得伪造已持久化状态。
- 当前只授权诊断及归档，新训练预算仍0。原144个诊断forward已经执行完毕，不能因缓存被清理就把调用账本归零。
- 若需要重新生成丢失缓存，先制定独立恢复协议，明确累计已用144与新增额度；不能直接沿用旧144额度重复预测。若没有新增授权/额度，先完成无模型恢复、摘要与缺口记录。
- 155 reserved+12 UNKNOWN所属CVE+2跨域CVE，共169个保护ID不得进入诊断评分；UNKNOWN不晋级Gold或确认负例；没有新增独立人类IAA。
- 原数据源口径统一不等于分布匹配。旧Dev150与新Dev147/147/148不同，不跨轮MRR直接计算清洗增益。
- 不移动main、旧expanded activation或已closed的resolved activation，不自动新臂/调参/确认训练，不执行其他章节任务。
- 默认在当前开发分支提交；写入前重新读HEAD，用expected_sha/非force更新，检查变化仅为新诊断路径与管理入口。

### 下一模型候选（设计建议，未实施/未登记/未训练）

- 先固定v3 base，不同时扩容、改标签、改负采样或搜权重。
- 一个DistMult context-pool/mixed候选×三折×三个原种子=9个新训练单位。
- 目标关系的查询由当前CVE的CWE节点编码均值与CPE节点编码均值构成：两种都在时各0.5，仅一种时用存在的一种；两种都无或未见背景无法取向量时明确拒绝/覆盖路由，不凭空构造已训练表示。
- 目标评分为q(CVE)×r(target)×e(technique)；训练和Dev均使用该目标查询构造，辅助关系/loss其余保持。
- dimension64、lr0.003、dropout0.3、wd1e-5、aux1、mixed10负例（5全31+5Train见过）、500轮/30早停、2线程、原seed/runtime保持。
- 相对冻结base DistMult的9配对可建议沿用ΔMRR≥+0.02、改善≥6/9、主要类宏差≥-0.01，并报告相对更强neighbor基线的差/胜数；最终晋级规则须在新训练前固定。
- 该候选对应既有Issue #19的查询区分方向；尚未证明有效，当前交接不构成新9单位运行授权。

## Verification

此前已运行的实际命令与结果：

|命令/动作|历史结果|当前证据状态|
|---|---|---|
|Python unittest chapter5.diagnostics.resolved_v3_20261012.test_helpers|7项先RED后GREEN，GREEN exit0|日志随未提交目录清理|
|python -m chapter5.diagnostics.resolved_v3_20261012.analyze|exit0，36回放/144 forward闭合，模型最大误差0|代码与分数缓存清理；摘要见本交接|
|python -m chapter5.diagnostics.resolved_v3_20261012.verify|exit0，144缓存、36单位、442来源分解核验|原复核文件清理|
|缓存篡改/输出覆盖拒绝|两项通过，新增forward0|原negative-gates.json清理|
|冻结chapter5.archive.pack_state重新打包原state|51分片与ZIP SHA256全部匹配|原receipt清理；原manifest在Git|
|v3 completion-review/verify_completion.py|再次exit0，原36数值绑定/28科学源保持|验证器及原完成复核在Git|
|本交接重新读开发HEAD及completion-review/verification.json|HEAD68e4d2f，result passed，36单位|本次直接从Git读取|
|本交接GET目标诊断blob|404|本次直接查询|
|本交接检查历史诊断路径|不存在|本次直接检查|

已经持久化、恢复科学源后可运行的**无模型forward**完成复核：

```bash
# /path/to/repo必须是恢复后的真实源码根；/path/to/completed是从Git恢复的原完成材料。
# /path/to/evidence包含completion-review的remote-tree.json、run.json和execution-evidence.log。
ATEN_CPU_CAPABILITY=avx2 PYTHONPATH=/path/to/repo python \
  /path/to/repo/chapter5/resolved_dev/completion-review/verify_completion.py \
  --repo /path/to/repo --inputs /path/to/completed --evidence /path/to/evidence \
  --receipt /new/path/completion-verification.json
```

恢复36 checkpoint artifact时：先校验上述artifact SHA256，再检查ZIP重复名、绝对路径/..、成员数、comparison字节Git SHA、config/registration与冻结科学源一致。原comparison Git blob为ab39bcb6f32e00102bd9ef08a8d4187bc12c9ac2。

重要绑定：registration SHA256 ac19948da5d31cfede901073af08dbbc49c2b99950ff48e3f96bea334e075e5e；运行数据ZIP SHA256 693deeb60537b51f9d9e6b7a1734a6d74482ad44c310e56092deb58c8f03a16b；来源v3候选ZIP SHA256 eb7f7434b61d2abeb5741b27758ac17f1e5f145ca62057e9ded364dc44bb56ac。

原runtime：Python3.12.14、Torch2.9.1+cpu、ATEN_CPU_CAPABILITY=avx2，训练/回放线程2。不要假设新会话已经有旧venv；按仓库冻结requirements-cpu.txt恢复。

当前不能执行被清理的diagnostics/resolved_v3_20261012模块。源代码若重建，要标为恢复版本，不冒称与丢失版本字节相同。

## Risks and open questions

- 原诊断包/原始缓存不可用 → 先尝试合法持久来源恢复，找不到则明确缺口；将对话记录视为历史计算摘要，不反造原manifest或旧forward账本。
- 重新生成会重复144个已完成forward → 用独立恢复登记/新增额度，不能静默重置预算或声称只是继续未完成调用。
- 文件恢复不等于原科学状态能直接续跑 → 科学run已closed/development_complete，不能重新激活原运行。
- 来源标签语义尚无完整独立核验 → 配对标签重合仅为现有部分标签的一致性，不当准确率。
- 模型共同形状占比高 → 不能直接当过平滑/类型向量根因；去共同形状的诊断反而下降。
- 固定一个置换、Dev交叠 → 描述性敏感性，不给独立样本置信区间或训练因果结论。
- 多会话并行/分支HEAD可能推进 → 在修改前读实际HEAD、AGENTS.md和计划，用CAS保护，不覆盖其他工作。

## First action for the next agent

**读取当前开发分支HEAD的AGENTS.md、EXPERIMENT_PLAN.md和已保存完成复核，然后核查本交接所述诊断包能否从持久来源恢复；输出“已恢复/未恢复”的明确清单。**

验收：核对HEAD是否仍68e4d2f、原run36单位完整及包6fb79e是否仍不可用；本步模型forward/训练/API/保留评分全部0。随后先保存能够核验的摘要与缺口记录，再规划需要新额度的恢复，不跳到新模型训练。

## Suggested skills/tools

- handoff：维护这份接续文件。
- OpenAI Library：保存/读取交接文件、检索可能留存的附件；用工具返回的真实ID，不使用搜索result_id充当文件ID。
- GitHub连接器：读取实际分支、文件/树、run artifact。已有仓库授权不重复询问；不要假设私有repo可以匿名clone。
- systematic-debugging与verification-before-completion：在额外复核/实现前确定假设及新鲜证据。
- 若将来获得新模型实现/训练授权，再使用spec/spec-audit、TDD、executing-plans；当前不自动启动这些新训练任务。

可粘贴给下一会话的开场指令：

> @GitHub 读取Thehe01/experiment4分支codex/chapter5-public-dev-20261011最新HEAD的AGENTS.md、EXPERIMENT_PLAN.md，并阅读我附带的HANDOFF_CHAPTER5_DIAGNOSIS_20261012.md。先核对第五章v3诊断的持久化缺口，恢复能恢复的证据，保存可信摘要及状态。不要重训已完成36单位、把已执行144次诊断forward的账本清零、自动启动建议的9单位候选、打开155保留组或合并main。若完整诊断缓存已不可恢复，先做无模型恢复与缺口说明，制定独立恢复登记后再决定新增推断额度。沿用既有诊断/归档授权，不重复询问已解决问题。
