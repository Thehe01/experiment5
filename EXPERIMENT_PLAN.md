# 第五章当前状态：context-pool9单位开发候选完成、复核与归档闭合

2026-10-12：[独立恢复运行38221419470](https://github.com/Thehe01/experiment4/actions/runs/38221419470) completed/success，无模型对账及数值复核/归档门禁通过。复用已完成9单位；首次复核凭永久成功receipt对账，未重复推断，仅执行原登记余下8次。9/9 checkpoint复核分数误差0，缓存排名/指标复算最大误差0、覆盖100%。[完成验收](chapter5/context_pool_recovery_20261012/completion-review.json)、[报告](chapter5/context_pool_recovery_20261012/results/report.md)、[独立复核](chapter5/context_pool_recovery_20261012/results/verification.json)、[完成账本](chapter5/context_pool_recovery_20261012/ledger.json)、[完成记录](chapter5/context_pool_recovery_20261012/completion.json)、[逐单位原比较](chapter5/context_pool_dev/runs/comparison.json)。

固定9配对：旧base DistMult平均MRR **0.381665→候选0.404273**，Δ **+0.022608**，**7/9**改善；主要23类宏平均Δ **+0.004490**。事前登记的三项开发门槛同时满足。Neighbor vote平均MRR **0.465339**，候选平均落后 **0.061066**、**0/9**胜；不能据此宣称优于强邻居基线或正式实验成功。三折Dev及早停已参与开发，沿用传导背景协议，非独立最终Test/新CVE归纳验证，亦不作独立样本显著性或唯一因果归因。

新候选训练**9单位闭合**（55–112epoch），优化forward **869**、训练Dev评分 **878**、关联checkpoint复核 **9=首次对账1+剩余执行8**。恢复新增训练0、超出原9次复核登记额度0。历史诊断forward **288保持**，原36单位未重训。首次Git发布失败保留为[原UNKNOWN账本](chapter5/context_pool_dev/runs/ledger.json)（SHA256 `13c47c7f449b7806a011484a845812277f5b45c815698211c7a4459ee3fdf49b`），独立恢复账本9/9 done；不覆盖旧记录或把账本清零。首次成功receipt SHA256 `85ec38b544fa1a9a669e42bb04270313d0e1f4e7ad11b2e8c3e4dabadf8ed8f9` 已按checkpoint/分数绑定核验。

[完整永久ZIP](chapter5/context_pool_recovery_20261012/results/complete-evidence.zip) **40,262,873字节、79成员、9 checkpoint**，SHA256 `591a4ab92e911e63f452e23b7af34d16772e26f1340e990fd1fa7bf8daa2d69c`；[manifest](chapter5/context_pool_recovery_20261012/results/evidence-manifest.json)、[9复核receipt](chapter5/context_pool_recovery_20261012/receipts)单独永久保存。artifact11734388436（97成员）已下载核验，ZIP及全部成员哈希通过，23个下载后永久文件的Git blob逐个吻合；根会话纯缓存审计exit0，报告/verification逐字等于远端，新增模型forward0。交付采用已验证永久ZIP，不替换成时间戳不同的本地重打包。

原科学登记/参数/源码15文件与首发布a1f7fb0保持，原历史科学/36单位/诊断2489个blob保持。169保护ID（含155保留组）未评分；没有新Gold或独立人类IAA声明；main及resolved/expanded activation HEAD保持。首运行缺rg的门禁失败（训练0）和CI2发布失败均保留在下方历史及验收记录；不抹除工程问题，不把它们当科学负结果。

当前任务清单：9单位训练、原额度9次checkpoint复核、独立缓存/配对复算、完整永久归档、下载验收和管理状态同步已完成。本轮固定预算闭合；不自动开启新候选、调参、155保留组、确认训练或合并main。

以下为此前管理记录，原文保持：

# 第五章当前状态：context-pool9单位训练完成，恢复原额度剩余8次checkpoint复核

2026-10-12：[CI2运行38219304888](https://github.com/Thehe01/experiment4/actions/runs/38219304888)无模型和数值门禁通过、9/9训练完成（55–112epoch，优化forward869、训练Dev评分878），[原逐单位比较](chapter5/context_pool_dev/runs/comparison.json)已永久保存。初步候选MRR .404273 vs旧base DistMult .381665，Δ+.022608、7/9改善、主要类宏Δ+.004490，按既定算术门槛通过；仍比Neighbor vote低.061066且0/9胜。独立全部checkpoint/缓存验收尚未完成，不在此状态宣称完整实验闭合。

首次checkpoint复核实际分数误差0，保存receipt时Git push报missing necessary objects；下一次UNKNOWN保存push成功，已带上该成功receipt。[原停止账本](chapter5/context_pool_dev/runs/ledger.json)首次复核为UNKNOWN，9训练全done；[成功receipt](chapter5/context_pool_dev/runs/f0-context_pool_mixed-s20261021-replay.json)SHA25685ec38…与训练checkpoint/分数哈希一致。已下载artifact11734240004、SHA256c5ff0341…，9 checkpoint及输出receipt全部校验。该一次调用经现有永久证据对账成功，禁止再重放。

新增[独立恢复登记](chapter5/context_pool_recovery_20261012/registration.json)、[原UNKNOWN账本字节快照](chapter5/context_pool_recovery_20261012/original-stopped-ledger.json)、[对账receipt](chapter5/context_pool_recovery_20261012/reconciled-first-receipt.json)、[9单位状态inventory](chapter5/context_pool_recovery_20261012/state-inventory.json)。只承接原9次checkpoint复核中已执行1和未执行8，新增训练预算0、超出原分配的新增复核额度0；不改原科学代码/config/registration、旧账本或成功9单位，不重训。恢复publisher使用git push --no-thin并仍禁止force/merge；不能唯一断言远端缺对象的根因。

恢复无模型对账门禁已RED→GREEN，下一步复用原永久unit分片执行剩余8次复核、独立缓存/配对复算和完整归档。原诊断288次保持，155保留组、main及两个activation仍未动。

以下为原管理记录，原文保持：

# 第五章当前状态：context-pool执行修订CI2，科学9单位登记保持

2026-10-12：[首运行38218792808](https://github.com/Thehe01/experiment4/actions/runs/38218792808) completed/failure，verify在synthetic RED日志检查使用rg时exit127（runner未安装rg）；train明确skipped，实际科学训练0、没有单位账本预留。并非数值GREEN测试通过或科学负结果。原科学源码、参数、登记及launch保持字节，不改首版冻结文件。

新增[执行修订CI2](chapter5/context_pool_dev/execution_revision_ci2.json)绑定原科学registration SHA256及新独立兼容workflow，用Python stdlib检查同一RED日志，原4项数值GREEN及所有原门禁保持。继续原9单位额度，新增额度0，首版已用科学单位0；不是另开9单位实验或清零已计费状态。原诊断288次、旧36单位、155保留组和其他保护边界保持。修订发布后核对CI，门禁全部通过才开始训练，成绩仍未知。

以下为既有管理记录，原文保持：

# 第五章当前状态：v3 base context-pool候选已登记，待远端门禁后启动9单位

2026-10-12，用户15:09:11（UTC+8）「开始」授权紧邻建议的9单位新候选。[规范](chapter5/context_pool_dev/spec.md)、[计划](chapter5/context_pool_dev/plan.md)、[配置](chapter5/context_pool_dev/config.json)、[独立登记](chapter5/context_pool_dev/registration.json)、[旧配对输入](chapter5/context_pool_dev/baseline-inputs.json)、[预检/自审](chapter5/context_pool_dev/checks.json)、[launch](chapter5/context_pool_dev/launch.json)。只用冻结v3 base三图、原3个seed，目标query按CWE/CPE均值pool（双渠道各0.5，单渠道1）；不回退CVE ID或无背景零向量评分。辅助loss/原mixed采样/原参数/早停保持。

事前固定开发门槛：相对同fold/seed旧base DistMult，平均ΔMRR≥+0.02、改善≥6/9、主要23类宏Δ≥−0.01，三项同时满足；相对同折Neighbor vote差/胜数另报。原691/691/690 Train、147/147/148 Dev、31候选与23主要类不变，实际背景覆盖100%；Dev背景辅助边沿用原传导协议，不能宣称新CVE归纳效果或独立Test。

本地4项stdlib行为RED→GREEN、真实三图/9单位/169保护ID覆盖和注册校验通过，实际新训练0；本地没有Torch，四项数值测试将在远端synthetic-only参考RED与实现GREEN门禁完成。门禁成功后才启动9单位，每单位先永久reserve，checkpoint含optimizer/RNG及最佳模型，每25epoch/完成永久分片。失败/UNKNOWN停止，不盲目重训或重置预算。

预算：新训练9单位、优化epoch forward≤4500、训练期间Dev评分≤4509、独立checkpoint重放评分9，按新训练账本分项记录；旧诊断288次及所有旧账本保持，不把训练epoch forward写成0。API/元数据刷新/155保留评分/确认训练0。新候选结果尚未知，不预填提升或赢家；后续独立重放/缓存复算、门槛判定与完整9 checkpoint归档后同步状态。原36训练及旧科学/诊断文件、main和两个activation保持。

以下为已保存管理记录，原文保持：

# 第五章当前状态：独立诊断恢复v1完成并永久归档

2026-10-12（UTC+8）：[运行38205273398](https://github.com/Thehe01/experiment4/actions/runs/38205273398) completed/success，远端无模型5项测试及真实登记门禁通过，原Python3.12.14/Torch2.9.1+cpu/AVX2/2线程与科学登记检查通过。按用户「继续实验」登记的新144次forward全部完成，无UNKNOWN；**历史已用144保留，本次新增144，累计288，新额度剩余0**。原36训练单位未重训，模型API/元数据刷新/155保留评分0，9单位候选未启动。

[新完整诊断报告](chapter5/diagnostics/resolved_v3_replay_20261012/report.md)、[独立分数复核](chapter5/diagnostics/resolved_v3_replay_20261012/verification.json)、[逐行动账本](chapter5/diagnostics/resolved_v3_replay_20261012/ledger.json)、[144永久分数缓存](chapter5/diagnostics/resolved_v3_replay_20261012/scores)、[逐单位摘要](chapter5/diagnostics/resolved_v3_replay_20261012/per-unit-summary.json)、[完整ZIP](chapter5/diagnostics/resolved_v3_replay_20261012/complete-evidence.zip)、[manifest](chapter5/diagnostics/resolved_v3_replay_20261012/manifest.json)、[完成验收](chapter5/diagnostics/resolved_v3_replay_20261012/completion-review.json)。原输入36回放、11,868条排名逐条吻合，完整原指标/全部缓存评分复算最大误差0。每forward前reservation已成功push、完成缓存与哈希逐行动持久化；全部已成功缓存不再重复执行。

完整新ZIP7,562,863字节、157成员，SHA256 `46f5fcf641509f4aa9300529c573640907e3043b06903ba60f2df8a2623c713b`。远端永久证据提交8f5983fe5a5c3a992c41960f16e8b2ede3bbbc83；artifact11727043877亦已下载并校验。根会话重复纯缓存复核exit0，所有159本地新诊断文件的Git blob与永久对象一致，ZIP及全部成员哈希检查通过。交付ZIP采用已验证永久对象，不将本地重打包代替冻结ZIP。

重新取得的分数确认共同形状占比：DistMult base95.25%/augmented99.44%，R-GCN97.93%/99.76%；去共同形状MRR下降。R-GCN换CWE Top3变化41.02%→19.47%，换CPE22.92%→1.74%，联合47.06%→20.45%。DistMult三干预分数完全不变，为固定CVE ID向量推断结构预期。结合已永久恢复的来源TV及邻居分解，分布不匹配和查询区分弱仍有描述性证据；不能唯一归因于标签错误、样本太少、过平滑或某参数，也不能当训练因果贡献或独立盲测。

新donor映射是独立恢复版本，原丢失映射未知，不能仅因汇总一致就声称原诊断包/原逐forward账本字节恢复。原36单位科学比较、扩容失败判定、28源及之前无模型恢复文件全部保持；169保护ID排除，未声称新独立人类IAA。main及resolved/expanded activation的HEAD保持。

当前任务清单：新增恢复登记/授权、无模型CI、冻结检查点144forward、独立缓存验收、完整永久归档及状态同步完成。本轮预算闭合，不自动继续推断/训练/调参/9单位候选；后续研究候选需要独立科学登记和适用额度。

以下为原管理记录，原文保持：

# 第五章当前状态：独立诊断恢复v1已登记，等待远端门禁及推断

2026-10-12，用户12:13:45（UTC+8）「继续实验」后，按紧邻的诊断恢复提案登记[新规范](chapter5/diagnostics/resolved_v3_replay_20261012/spec.md)、[独立144行动与预算登记](chapter5/diagnostics/resolved_v3_replay_20261012/registration.json)、[启动绑定](chapter5/diagnostics/resolved_v3_replay_20261012/launch.json)及[本地门禁证据](chapter5/diagnostics/resolved_v3_replay_20261012/checks.json)。历史诊断已用144保留，本次最多新增144，最大累计288；本登记不授权9单位候选或新训练，训练/API/元数据刷新/155保留评分预算均0。

新工作流先运行无模型5项行为测试与实际6图/144行动登记门禁，再恢复原Python3.12.14/Torch2.9.1+cpu/AVX2/2线程及原科学登记，使用a247a950原永久51分片恢复36冻结检查点。每行动forward前成功push持久reservation，完成分数与哈希后逐行动push；失败/UNKNOWN不自动重放，成功缓存验证复用，预算不重置。新的固定donor是已归档提案映射，不冒称恢复原丢失映射。

当前仅已完成登记与本地5项RED→GREEN、真实边界离线校验（新增forward0）；发布后核对远端无模型CI、冻结runtime门禁及推断进度。后续独立检查144分数、原36排名与完整ZIP/账本并同步完成状态。未宣称此时已有144缓存或结果。原科学36单位closed及无模型恢复目录字节保持，main及两个activation分支不移动。

以下为已保存管理记录，原文保持：

# 第五章当前状态：v3无模型诊断恢复完成，完整分数缓存仍缺失

2026-10-12（UTC+8）：按本轮用户授权核对68e4d2f最新HEAD及附带交接，完成[无模型恢复摘要与缺口](chapter5/diagnostics/resolved_v3_recovery_20261012/report.md)、[独立恢复登记](chapter5/diagnostics/resolved_v3_recovery_20261012/recovery-registration.json)、[累计用量保留](chapter5/diagnostics/resolved_v3_recovery_20261012/usage-state.json)、[新鲜验证](chapter5/diagnostics/resolved_v3_recovery_20261012/verification.json)、[归档校验](chapter5/diagnostics/resolved_v3_recovery_20261012/archive-verification.json)及[定位检查](chapter5/diagnostics/resolved_v3_recovery_20261012/persistence-observations.json)。

原训练artifact仍有效，精确恢复298成员、36 checkpoint字节/receipt、36模型排名及11,868真关联排名、原账本/closed session；28冻结源及6图绑定一致。原排名汇总和36独立简单基线公式/排名复算最大误差0。冻结pack_state重建212,300,186字节ZIP及51分片，原manifest、ZIP/分片SHA256与分片Git blob全部匹配。上述不含模型forward或checkpoint反序列化；原Torch数值runtime绑定本次未复算，冻结completion verifier因Torch2.9.1+cpu缺失未运行，使用新stdlib恢复审计，未绕过原门禁。

[来源分布](chapter5/diagnostics/resolved_v3_recovery_20261012/source-distribution.json)及[442条邻居分解](chapter5/diagnostics/resolved_v3_recovery_20261012/neighbor-source-rows.json)已重建持久保存：Train/Dev标签边TV均值base .0328646365→augmented .1110124316；新增票平均占38.5701%，其中87.2176%权重来自CWE；同330出现配对部分标签票重合旧34.8572%/新22.7560%（非语义准确率）。邻居两来源均有/仅旧/仅新/皆无330/32/11/69，215降/116升/111不变。原扩容负结果与判定保持：DistMult ΔMRR−.019785（1/9），R-GCN−.036658（0/9）。

完整原诊断包blob6fb79e仍404，当前开发树无原诊断目录，检查过的文件与历史工作路径未恢复144份分数缓存、原逐forward账本/代码/协议/复核日志。共同形状与固定权重背景置换仍仅按[交接历史记录](chapter5/diagnostics/resolved_v3_recovery_20261012/source-handoff.md)引用，不称本次原始分数复验。恢复代码独立新版本，不反造旧manifest或调用条目。

历史诊断forward累计已执行144保留，本次新增forward/科学训练/模型API/元数据刷新/保留评分全部0，新增推断已授权额度0。独立登记只将最多144次新增重证据forward列为未激活提案（若未来全额分配并用完累计288）；新donor映射为独立恢复版本，原丢失映射未知。实际新增推断须单独固定额度、实现/runtime及逐行动持久化，不按旧144额度静默重跑。169保护ID继续排除，155保留组未评分，9单位候选未实施/登记/启动。

当前任务清单：持久化缺口核对、可恢复原状态/排名/基线/来源/归档、可信摘要与累计用量保留、独立恢复登记和状态同步完成；完整诊断缓存恢复与新增推断暂不开展。原36单位closed、不重训、不重新激活；main、resolved/expanded activation及所有原科学文件保持。本次审计exit0；输出覆盖/冻结配置篡改两项按预期exit1。[命令与边界](chapter5/diagnostics/resolved_v3_recovery_20261012/checks.json)。

以下为原管理记录和冻结证据，原文保持：

# 第五章当前状态：v3开发比较完成并闭合

2026-10-12（UTC+8复核）：[运行38152196348](https://github.com/Thehe01/experiment4/actions/runs/38152196348)于10月11日23:57 completed/success，36/36单位全部slot1完成，slot2/3因无continuation正常跳过。[完成复核与分析](chapter5/resolved_dev/completion-review/README.md)、[独立验证](chapter5/resolved_dev/completion-review/verification.json)、[汇总](chapter5/resolved_dev/completion-review/compact-results.json)、[命令/输入哈希](chapter5/resolved_dev/completion-review/checks.json)。永久完成提交a247a950412c517d4c80ff5bab7e46fece8b929e的原报告/comparison/session/manifest保持。

同Dev147/147/148，base Train691/691/690→augmented1547/1547/1546：DistMult MRR .381665→.361880（Δ−.019785，1/9改善），R-GCN .391734→.355077（Δ−.036658，0/9）；23主要类宏差−.016022/−.024933。最佳邻居基线 .465339→.428606，两扩展图模型均0/9胜同折扩展基线。数据扩展开发门槛未通过，固定预算本轮闭合，不自动新增臂/调参/确认训练。

36唯一执行ID、28科学源Git对象、v3配置/数据及数值绑定fresh核对通过；CVE宏MRR组重建最大误差5.55e-17、主要类宏误差0，配对/基线选择及门槛算术一致。36单位patience早停，35–343轮；51归档分片212,300,186字节，连续名称/大小/Git对象/限额验证。此次未重放全部检查点/原始排名、未重组分片复算ZIP SHA256，也未从原始分数重算全部基线；不称完成独立原始评分审计。

采用1724可用CVE，31父技术，12个UNKNOWN所属CVE及旧2跨域项仍隔离；155保留组未评分，未声称独立人类IAA。旧Dev150与新Dev不同，不直接计算跨轮清洗收益。当前结果不支持单靠这批数据继续扩容；来源/类别/年份/同背景标签分布及模型查询区分是后续诊断候选，因果贡献仍未知，#19候选未实施/登记/启动。

当前任务清单：接入、科学登记、启动、36单位运行闭合、完成复核及状态同步完成；本次新增科学训练/模型API/保留评分0。原科学结果/冻结源码/注册、main和旧expanded activation保持，新resolved activation停留于永久完成提交，不从此状态自动续跑。

以下为历史管理记录和冻结证据：

# 第五章当前状态：v3实验已启动

2026-10-11：独立v3配对开发实验已发布并进入slot1执行。[运行38152196348](https://github.com/Thehe01/experiment4/actions/runs/38152196348) in_progress/attempt1；verify的28项离线测试和登记校验success，slot1 durable reserve已success，登记campaign步骤in_progress，Git session为active/reserved。[启动观察](chapter5/resolved_dev/launch-observations/README.md)、[启动证据](chapter5/resolved_dev/launch-observations/started.json)、[activation](chapter5/resolved_dev/launch-observations/activation.json)、[远端校验摘录](chapter5/resolved_dev/launch-observations/verify-evidence.log)。实际epoch/完成科学单位数尚未公布，未知；verify的synthetic_test_only结果不算科学进度，不能写为36单位完成或改善。

科学提交4f379b612b3d6cce5f8237b8103e866909ca7988，登记SHA256 ac19948da5d31cfede901073af08dbbc49c2b99950ff48e3f96bea334e075e5e；新activation244e217428e23c9bd019084171de40c49999c389只增加launch。发布28项blob大小/Git SHA精确匹配，原科学文件及main/旧activation保持。采用1724可用CVE、31父技术，12个UNKNOWN所属CVE及旧2跨域项继续隔离；未收到恢复裁决或人类IAA证据。

同折Dev147/147/148，base监督Train691/691/690、augmented1547/1547/1546；两模型×两条件×3折×3种子=36登记单位，原模型/参数/停止门槛保持，最多3×240分钟CPU槽，后槽仅前槽closed+continuation_needed时续跑。模型API0、保留155未评分、确认训练未启动。旧Dev150不与新成绩直接算增幅。

当前任务清单：v3接入、登记、离线验收、发布、启动及观察完成；科学运行执行中，36单位结果闭合/数值与归档复核待运行完成后开展。不自动增加实验臂或参数搜索，#19候选不在本轮范围。

以下为历史管理记录和冻结证据：

# 第五章最新任务：v3配对实验

2026-10-11：用户「我已核验开始实验吧」授权，独立v3正式接入和36单位科学登记完成。[规范](chapter5/resolved_dev/spec.md)、[计划](chapter5/resolved_dev/plan.md)、[配置](chapter5/resolved_dev/config.json)、[登记](chapter5/resolved_dev/registration.json)、[接入报告](chapter5/resolved_dev/preparation-report.md)、[验证](chapter5/resolved_dev/verification.json)、[命令](chapter5/resolved_dev/checks.json)、[自审](chapter5/resolved_dev/review.md)。当前尚未activation启动。

采用1724可用CVE，原868+外部856，1694有标签、30仅背景；12个UNKNOWN所属CVE及旧2跨域CVE继续隔离。未收到新的恢复标签文件，不把核验声明转换为独立人类IAA。两条件同Dev147/147/148；base监督Train691/691/690、augmented1547/1547/1546。31父候选，23主要技术，233不同Dev/442次出现；原标签/角色保持，外部统一来源804CWE/2353CPE边。旧Dev150结果不能直接与新分数算增幅。

DistMult/R-GCN mixed×base/augmented×3折×3种子=36单位，原参数/损失/采样/评分/早停/门槛保持，最多3个240分钟CPU槽，不新增算法/参数搜索。9准入RED→GREEN、28综合测试、六图采样/保护/确定性重建、4项注册篡改拒绝、原36单位/23科学源绑定fresh通过。科学训练、模型API、reserved评分目前0；接下来独立新activation绑定本科学提交并确认verify/slot1，启动证据另作管理更新。旧原文件、main及expanded activation保持。

任务清单：接入/登记/离线验收完成；发布科学提交及新activation启动执行中；36单位完成及成绩判定尚待运行后复核。#19候选不在本轮范围。

以下为历史状态与证据：

# 第五章实验最新状态

2026-10-11：按用户“帮我消除差异”完成独立来源选择及争议隔离v3。[报告](chapter5/external_data/source_resolution_v3_20261011/report.md)、[规范](chapter5/external_data/source_resolution_v3_20261011/spec.md)、[数据准备协议](chapter5/external_data/source_resolution_v3_20261011/protocol.json)、[AI逐条意见](chapter5/external_data/source_resolution_v3_20261011/review-opinions.json)、[验收](chapter5/external_data/source_resolution_v3_20261011/verification.json)、[原绑定复核](chapter5/external_data/source_resolution_v3_20261011/original-completion-verification.json)、[命令](chapter5/external_data/source_resolution_v3_20261011/checks.json)、[交付](chapter5/external_data/source_resolution_v3_20261011/delivery.json)。107个官方CVE原始文件和15个冻结ATT&CK19.2定义保存于primary-evidence-v3.zip，Git/SHA256逐项核验。全部856外部记录按同一来源优先级选择数字CWE；92项CNA与缓存核对一致，89项候选集合改变、3项无需改变，共减少91条跨来源并集CWE边，覆盖仍775CWE/856CPE。3项CISA-only条目逐条在官方ADP容器确认。

20个UNKNOWN技术对的AI证据意见为支持潜在关联3、具体场景不足7、所核机制缺少支持10，**不晋级Gold或确认负例**。12个所属CVE暂时整体隔离，可用视图1736→1724（1694有标签、30仅背景），技术边3166→3144；原1736完整记录/原标签/角色及20个UNKNOWN保留，旧2跨域隔离不变，总隔离14。新划分仅过滤此12项：监督Train1547/1547/1546、可评分Dev147/147/148、每折背景25/5、31类Train最低17、Dev仍28类。**旧Dev150评分协议不适用新视图；不能直接比较新旧MRR宣称改善。** 原880CWE、全部技术/CPE/原角色不变。类别、年份、来源分布差异仍存在，856外部标签独立语义复核未完成。

9项v3行为、9项v2、19前处理、10图数据共47项通过；10份输出确定性复算、来源/角色/集合/支持校验、覆盖及输入篡改拒绝通过；原36单位/23科学源绑定复核exit0。原v1/v2包、科学源码/注册/结果/未晋级结论、activation/main保持。本轮训练/模型推断/实验模型API/reserved标签比较与评分0；新科学登记未创建。

当前任务：可复现来源口径与已知争议隔离完成，独立候选包为source-resolved-candidates-v3.zip。后续若重新训练，先为同一可用数据冻结新Train/Dev、评估类别与预算，适配数据引擎并科学登记；不直接续接旧run。12项恢复需独立人工语义复核及明确关联口径，完整证据已备齐。既有[Issue #19](https://github.com/Thehe01/experiment4/issues/19)查询区分候选仍未实现/登记/启动，本次不自动扩展该任务。

以下为既有实验和v2等历史记录，原证据继续保持：

# 第五章实验当前入口

2026-10-11：按用户“先消除差异”完成独立来源口径统一v2。[报告](chapter5/external_data/source_alignment_v2_20261011/report.md)、[规范](chapter5/external_data/source_alignment_v2_20261011/spec.md)、[协议](chapter5/external_data/source_alignment_v2_20261011/protocol.json)、[交付摘要](chapter5/external_data/source_alignment_v2_20261011/delivery.json)、[独立复核](chapter5/external_data/source_alignment_v2_20261011/verification.json)、[验收命令](chapter5/external_data/source_alignment_v2_20261011/checks.json)。固定CTID原CSV与KEV07.28.2025发布原字节重建全部880原开发CVE标签，原标签改变0；619重合CVE统一CTID规范视图，73原差异留逐项证据，规范视图差异0。作者12个CVE的20个额外标签保存UNKNOWN及未来负采样排除表，不认定为正例或确认负例；两个多变体编号按明确来源统一但不自动并集。新发现CVE-2017-0493/CVE-2019-7287的CTID来源只有Mobile标签，与31 Enterprise输入范围冲突，在候选v2隔离并保留原记录；外部858→856、每折候选Train1556/Dev150、总1736CVE/3166标签边。9项新行为、19前处理及10原图数据回归共38项通过，9输出确定性复算、原始证据定位/CWE-CPE/角色保护检查、两项篡改/覆盖拒绝检查通过，原36单位/23科学源绑定重新exit0。候选完整数据在source-aligned-candidates-v2.zip，CTID原始来源与许可证在ctid-source-inputs.zip。**可核验来源口径统一完成；20个UNKNOWN的完整语义裁决、92个CWE来源分歧及856条新增标签独立复核仍未完成。** 来源分布不人为拉平；原619重合项原本就未新增到Train，不能把统一口径宣称性能改善。冻结引擎尚未实现UNKNOWN排除，新科学训练/登记/模型推断/API/reserved比较及评分0；原科学结果与未晋级判定保留，activation/main保持。

当前第五章任务：来源核验、规范化视图、争议隔离、独立数据交付与验收完成；后续先明确UNKNOWN和CWE争议的证据，再考虑新协议/数据适配及既有#19查询区分候选。候选数据不直接续接旧run，尚未启动新实验。


2026-10-11：按用户“开始审计”完成31父技术扩展数据的离线来源审计。[报告](chapter5/diagnostics/expanded_data_audit_20261011/report.md)、[协议](chapter5/diagnostics/expanded_data_audit_20261011/protocol.json)、[可复现分析](chapter5/diagnostics/expanded_data_audit_20261011/results/analysis.json)、[独立验收](chapter5/diagnostics/expanded_data_audit_20261011/artifact-verification.json)、[原绑定复核](chapter5/diagnostics/expanded_data_audit_20261011/completion-binding-verification.json)。36份已登记简单基线独立公式复算最大误差1.11e-16；450次邻居来源分解（237不同CVE）匹配原下降−.026713，新增票平均占38.42%，新增票总权重87.75%来自CWE，现有Dev标签加权重合均值原35.31%/外部22.75%（非完整标签准确率）。619个重合开发CVE中73个存在变体集合差异、2个有多变体，已保存证据复核队列；未判为错误、未自动合标签。来源同有CTID方法背景，CSV无逐条标注起源/阶段，外部98.37%编号为2020–22但不等于发布时间或人工来源。训练先验及同CWE标签分布变化明显；扩展图模型Top3的前三热门技术占95.58%/96.10%，背景利用的全部因果贡献未知。主审计、独立算术/保护/确定性复算及原36单位/23源绑定检查exit0；4份结果两次字节一致、输入保持、覆盖/篡改两项拒绝exit1。审计任务完成，原未晋级结论保持；**下一待办是标签证据核验与既有#19查询区分候选的前置审查，尚未启动或登记新训练/权重搜索**。本轮新增科学训练/模型推断/API/元数据刷新/reserved标签比较及评分0；未重放模型检查点/排名、未重组归档，不合main或移动activation。

本次审计任务清单：输入/保护边界核验、来源/类别/背景分布分析、36基线复算与450来源票分解、报告与验收记录均完成。73标签证据及92个NVD CWE差异的人工裁决仍待提供，不能以本审计代替；新数据版本/模型实验另行固定协议。

2026-10-11 19:19（UTC+8）：31父技术扩展开发比较**完成并闭合：36/36单位**。[运行38134213784](https://github.com/Thehe01/experiment4/actions/runs/38134213784) completed/success；verify、slot1及永久归档成功，slot2/slot3因无需continuation正常跳过。[原运行报告](chapter5/expanded_dev/runs/chapter5-expanded-dev-v1-20261011/report.md)、[逐单位比较](chapter5/expanded_dev/runs/chapter5-expanded-dev-v1-20261011/comparison.json)、[完成复核](chapter5/expanded_dev/completion-review/verification.json)、[分析与限制](chapter5/expanded_dev/completion-review/README.md)。同Dev150、同31父候选、Train700→1558：DistMult MRR .380415→.365335（差−.015080，0/9改善），R-GCN .383998→.366259（差−.017739，2/9）；最佳邻居基线 .460084→.433371。两扩展模型均0/9胜扩展基线，数据扩展开发门槛未通过。所有36单位耐心早停（37–152轮），源/配置/数据与数值绑定及汇总算术核对通过；51分片共212,783,840字节，名称/大小/Git对象登记匹配。本次不重放全部检查点/排名、不重组分片复算SHA；新增科学训练/API0，reserved155评分0，确认训练未启动。当前结果不支持单靠此队列扩容提升，不归因为确定标签错误；来源口径/分布与背景利用留作后续诊断候选，本轮不自动新增实验。原结果/冻结输入/登记/activation/main保持。

2026-10-11：独立31父技术扩展开发实验**接入与登记完成，远端已启动并进入slot1执行**。[运行38134213784](https://github.com/Thehe01/experiment4/actions/runs/38134213784) in_progress；verify的29项离线测试及登记校验成功，slot1持久预留成功、登记campaign步骤in_progress。[启动证据](chapter5/expanded_dev/launch-observations/started.json)与[说明](chapter5/expanded_dev/launch-observations/README.md)已保存。运行日志暂未发布，实际epoch/已完成单位数未知，不能把排队/执行中当36单位完成或性能改善。858新增CVE、同Dev150、Train700→1558、31候选、36登记单位；155保留组未评分。源提交317570f，activation仅加launch.json；此管理提交不改变已启动的科学源码，不合main。后槽仅在前槽closed+continuation_needed时续跑。

2026-10-11：按用户“正式接入并开启实验”完成独立31父技术扩展开发实验准备。新增858个CVE接入独立运行包，每折同Dev150、Train由700增至1558；原Train725/Dev155中25/5项无此范围标签保留背景用途。31类扩展Train支持均至少17；Dev有正例28类，固定主要类23。DistMult mixed/R-GCN mixed × base/augmented ×3折×3种子=36单位，500轮上限/30轮早停，最多3个240分钟槽，模型API/确认实验/保留组评价0。独立数据复算、29项离线测试、六图采样输入校验、五项拒绝检查及ZIP确定性复算均通过。[准备报告](chapter5/expanded_dev/preparation-report.md)、[规范](chapter5/expanded_dev/spec.md)、[登记](chapter5/expanded_dev/registration.json)、[验收](chapter5/expanded_dev/verification.json)、[自审](chapter5/expanded_dev/review.md)。本提交为**接入与登记完成、远端训练尚未启动**；随后独立activation分支仅改launch启动，观察证据另行更新。此回顾性开发比较不认定正式盲测完成；原输入/标签/划分/登记/结果/reserved155/main保持。

2026-10-11：按用户「帮我补齐」完成独立CVE2ATT&CK官方背景补齐。[报告](chapter5/external_data/cve2attack_background_v1/report.md)、[规范](chapter5/external_data/cve2attack_background_v1/spec.md)、[复算](chapter5/external_data/cve2attack_background_v1/README.md)、[验收](chapter5/external_data/cve2attack_background_v1/verification.json)、[数据包摘要](chapter5/external_data/cve2attack_background_v1/delivery.json)。NVD官方9批/9请求取得全部860记录，858达到数字CWE或受影响CPE的原最低OR规则，保留1549条父技术关联/30类；777有CWE+CPE、81只有CPE。两条REJECTED（CVE-2019-9081、CVE-2022-27458）经固定官方CVEProject原始记录复核后隔离，不改号搬标签。92个多源CWE差异留证未裁决；3252背景边；753与旧图共享背景、105全部背景未见旧图。19项行为测试/19项前处理回归、独立逐条来源与保护集检查、5项拒绝检查、真实0网络续跑、6份确定性输出及24成员ZIP校验通过。当前背景补齐完成，数据已交付；**正式接入、角色/范围注册、新训练仍未启动**。2026现状元数据不称2022时点或前瞻输入。旧输入哈希/标签/划分/reserved155/main保持；新增科学训练0、模型API0、reserved评分0。

2026-10-11：按用户“你做接入前处理”完成 CVE2ATT&CK（2022）独立离线处理。[报告](chapter5/external_data/cve2attack_v1/report.md)、[规范](chapter5/external_data/cve2attack_v1/spec.md)、[复算说明](chapter5/external_data/cve2attack_v1/README.md)、[校验回执](chapter5/external_data/cve2attack_v1/verification.json)及[数据包摘要](chapter5/external_data/cve2attack_v1/delivery.json)已保存。固定作者四CSV共1665行/1661个不同CVE，排除原reserved99、开发池619、其余原公开源74、额外已记录曝光7，再隔离同文2，保留**860个新增文本开发候选、1552条父技术关联、30类**。31个来源列均对齐冻结活跃父技术ID；T1211更名同ID。原数据4个重复编号（3个标签冲突）及开发重合73个同范围标签差异均保留，未自动并入原Gold；reserved不做标签比较或模型评分。19项行为测试、独立逐项校验、4项篡改/覆盖拒绝检查及两次确定性生成通过。CSV缺CWE/CPE，**当前图模型新增可训练0**，已交付860项可靠背景补齐队列；补背景、正式接入、新训练/范围注册仍未启动。父技术Train支持≥10为26类，假设未来加入全部860候选的预览为34类，不据Dev/reserved选类，不代表性能增益。原冻结图/split/科学登记/结果/main保持，新增训练0、模型API0、reserved评分0。

2026-10-11：用户在现成样本调查后明确“开始”，已完成独立公开数据审计与适配。CIRCL/CTID 1207 个 CVE、2820 条专家潜在关联，排除与 v1 图/已记录曝光的169个重复后剩1038；其中3个缺少可规范化 CWE/CPE 背景保留单列，形成 **1035 个 CVE、2332 条潜在关联、174 类监督、697 全候选** 的独立扩展图。开发划分 Train/Dev/reserved_holdout=725/155/155，所有监督技术在 Train 有支持；保留组尚未评分，也不认证为从未接触的正式盲测。

2026-10-11 01:05:11（UTC+8）用户要求“进入下一阶段”，授权落实训练适配、简单基线和受控开发比较。已建立独立 [科学规范](chapter5/public_dev/spec.md)、[配置](chapter5/public_dev/config.json)、[36单位登记](chapter5/public_dev/registration.json)、[三组重复划分](chapter5/public_dev/folds.json)、[离线回执](chapter5/public_dev/verification.json)。当前为 **受控开发比较已完成：36/36单位，模型API0，155保留CVE未评分**。[运行38101314699](https://github.com/Thehe01/experiment4/actions/runs/38101314699)今天09:40（UTC+8）completed/success；verify及slot1成功，slot1提前完成全部登记单位并闭合归档，slot2/slot3按continuation_needed条件正常跳过，不代表漏跑三分之二。[完成核对](chapter5/public_dev/launch_observations/completed_run.json)记录36个唯一执行ID、closed/development_complete及50个归档分片清单；[结果报告](https://github.com/Thehe01/experiment4/blob/c9362392cc309635ab355c0ddf330736783f3501/chapter5/public_dev/runs/chapter5-public-dev-v1-20261011/report.md)已保存。最强简单基线为neighbor_vote，rgcn_mixed九单位平均Dev MRR=0.319400、相对基线差=-0.057397、改善0/9，主要技术宏MRR差=-0.145000；开发进阶门槛未通过。确认实验/保留组评价未启动，不自动新增训练单位、实验臂或调参。此次状态核对未重放全部检查点/排名字节，不替代后续独立评分复核。

2026-10-11 12:25（UTC+8）：按用户“开始”完成前两项 P0 离线诊断。[诊断报告](chapter5/diagnostics/public_dev_p0_20261011/report.md)、[范围协议](chapter5/diagnostics/public_dev_p0_20261011/protocol.json)、[复算回执](chapter5/diagnostics/public_dev_p0_20261011/results/verification.json)、[执行与来源核验](chapter5/diagnostics/public_dev_p0_20261011/execution.json)及完整证据包独立保存。全部36个最佳检查点与18份基线输出、20,934条目标排名复现，原完整指标最大误差0；固定参数对照72项、逐查询记录12,555条。恢复产物重建永久209,393,445字节ZIP及50分片清单完全一致。R-GCN mixed按查询标准化后共同技术分数形状占97.80%；联合背景置换MRR 0.319400→0.301043、Top3集合改变10.73%，邻居投票0.376797→0.193966、改变94.98%。不支持直接认定典型过平滑或热门技术向量范数膨胀；完全去掉共同分数使MRR降到0.126861，有用先验与条件区分需同时保留。[Issue #19](https://github.com/Thehe01/experiment4/issues/19)记录性能证据及唯一候选：DistMult context-pool/mixed以CPE/CWE直接构造查询，建议另行登记3折×3种子9个单位，其余损失/评分/采样/停止条件保持。候选未登记、未实现、未启动；本轮新增科学训练0、模型API0、reserved155评分0，原未晋级结论/冻结登记/activation/main保持。源码与真实检查点重放通过不等于正式泛化提升。

公开标签描述潜在利用及直接/后续影响，独立目标 potentially_associated_with；不合入 v1 exploited_by。阶段缺失、非数字 CWE、reported CPE 条件不足和重合CVEs标签差异均留有复核清单。[已完成数据准备](chapter5/public_data/report-20261011.md)的包字节保持冻结。本轮固定 DistMult/R-GCN ×均匀/混合负采样 ×3组Train725/Dev155 ×3种子=36单位，500轮上限/30轮早停；同折比较Frequency、CWE、全局选择alpha的平滑CWE及产品/CWE邻居投票。三组Dev两两重合100/100/107个CVE，不视为独立K折；完整697候选与Train174技术支持保持。最多3个240分钟CPU槽只在前槽closed+continuation_needed时续跑，未知/失败状态不自动重置。35确认/消融、10有条件补充和155保留组评价额度均为0；本轮不改变第四章formal/Test/IAA。

第五章 v1 保留已完成状态：[CPU运行38059570399](https://github.com/Thehe01/experiment4/actions/runs/38059570399)于2026-10-10 23:00（UTC+8）success，16开发调参+25主实验+10补充=51次归档；[冻结结果](https://github.com/Thehe01/experiment4/blob/d168b5b67506fee2976ba8eebf432ad42005057b/chapter5/runs/chapter5-v1-20261010/result.json)。Test MRR Frequency0.6819、DistMult0.6447、R-GCN0.6904，Test24个CVE，平均增益小。原[source/result分析](docs/chapter5/v1-analysis-and-v2-plan-20261010.md)及[机器证据](docs/chapter5/v1-analysis-evidence-20261010.json)保留。不能把不同目标的公开扩展基准分数与v1直接算增幅；原 chapter5-v1 科学输入、代码、结果、C4门禁保持字节，不移动v1分支或main。

---

# experiment4 收敛执行计划

更新：2026-10-09。计划 ID：`experiment4-convergence-20261005`。

**C4 开发比较、最终结果 v1（Dev）完整归档及状态同步已完成。运行37818651924已completed/success，六轮实体/关系优化、1152缓存窗口及21篇Dev五方法比较完成。ProTeGi_Full严格实体/关系/归一化关系F1=93.17%/58.65%/47.41%；累计Task14864/18000、Optimizer580/600，含废弃818，旧18 UNKNOWN与未知费用保留，新UNKNOWN=0、在途=0。[归档提交2494470](https://github.com/Thehe01/experiment4/commit/249447019202f6adc4849f950f2182af5715954f)持久保存42,827,903字节源ZIP的11个分片及清单；远端分片大小/Git SHA与本地一致，顺序重组SHA-256=4e5eb2f25f93f5451846844f45fc34dfbfc69f8155d9ca3d11ee4de98dd94ab9，归档不再依赖Actions artifact到期。指定源ZIP与无参数分片复算均退出0，238阶段产物哈希、315项评分一致，38个实际导入仓库Python文件与远端一致；此次模型调用0、Test打开0。[验收回执](results/convergence_c4_v1/final_result_v1/archive_parts/verification.json)、[结果说明](results/convergence_c4_v1/final_result_v1/README.md)、[交接](HANDOFF_C4_FINAL_V1.md)。#4已完成关闭；#5保持开放跟踪#3正式材料，收尾状态development_complete_formal_blocked。冻结分数/响应/账本/缓存/Gold/登记与activation源码保持原字节，不合并main。新未见最终Test与真实人类IAA仍缺，formal/Test关闭，不自动启动v2或重跑模型。**

C3 当前入口：[离线准备报告](CONVERGENCE_C3_OFFLINE_PREPARATION_V1.md)、[选样/独立标注/IAA操作说明](data/convergence_c3_v1/README.md)、[已知暴露元数据索引](data/convergence_c3_v1/known_exposure_index.json)、[六份空白模板](data/convergence_c3_v1/templates/)、[验收回执](results/convergence_c3_v1/offline_preparation/verification.json)。只完成可独立开展的材料框架；新候选来源0、真实标注0、IAA未计算，正式材料仍待补，#3/#5保持开放。

C5 新增零调用诊断：[Configuration FN 响应重放报告](CONVERGENCE_C4_CONFIGURATION_FN_DIAGNOSIS_V1.md)、[逐例证据](results/convergence_c4_v1/final_result_v1/review/configuration_fn_diagnosis_v1/analysis.json)、[验证回执](results/convergence_c4_v1/final_result_v1/review/configuration_fn_diagnosis_v1/verification.json)。321个实体响应/窗口和21个文档合并逐项一致，全部48个raw FN有完整请求窗口及选择归属覆盖；主要观察分类为解析缩短2、同名偏移歧义19、重叠表述偏移歧义6、已定位边界差异13、当前位置无定位预测8，另1个最终后处理FN单列。分类不等于可恢复TP/关系数；v2仅有Train侧候选假设，未实现或准入，原v1原字节不变。

C3 旧Test独立性已进一步审计：[逐篇报告](CONVERGENCE_C3_OLD_TEST_AUDIT_V1.md)、[机器记录](results/convergence_c3_v1/old_test_audit_v1/analysis.json)、[回执](results/convergence_c3_v1/old_test_audit_v1/verification.json)。三方法历史冻结清单覆盖全部21篇，但所引用原预测/评分文件未包含在当前tree；21篇均在boundary审计中，12篇/78个Configuration进入MCPU批次，2篇有3处明确跨度修改。核心policy/JSON audit绑定通过，历史review Markdown附属哈希不匹配单列保留。结论为旧Test保留历史/开发审计用途，不认证为新的最终holdout；不宣称21篇全部进入优化器训练。新模型调用0、canonical Gold文件读取0（读取了历史Test审计记录），原门禁和新Test/真实IAA缺口保持。

v12 历史恢复入口：[超时恢复报告](CONVERGENCE_C4_TRANSPORT_REPAIR_V12_REPORT.md)、[独立登记](data/convergence_c4_execution_v12.json)、[恢复授权](data/convergence_c4_transport_recovery_authorization_v12.json)、[冻结源快照](data/convergence_c4_timeout_source_v12.json)、[384窗口复用回执](results/convergence_c4_v1/v12_verification/verification.json)。

历史运行登记与启动观察：[v11启动记录](results/convergence_c4_v1/v11_launch/launch.json)。修复 PR 为 [#6](https://github.com/Thehe01/experiment4/pull/6)，本次未合并 main；activation 固定使用已通过离线 CI 的提交，管理状态更新不改变运行源码。

C4 历史 v11 恢复入口：[v11修复报告](CONVERGENCE_C4_REPAIR_V11_REPORT.md)、[新登记](data/convergence_c4_execution_v11.json)、[续期授权](data/convergence_c4_renewal_authorization_v11.json)、[原始快照清单](data/convergence_c4_snapshot_evidence_v11.json)、[离线复用验收](results/convergence_c4_v1/v11_verification/verification.json)、[前驱链门禁](scripts/convergence_c4_snapshot_chain_v11.py)、[新监督器](scripts/supervise_convergence_c4_v11.py)。v10及此前路径保留为历史证据。v11继承已审计的六轮P_E*，新阶段仅为实体缓存→Stage2→匹配策略的五方法Dev比较；旧分数保持v10口径。Reactive小窗口降级只在实体输出耗尽后触发；子窗口请求跨阶段共用512物理上限，正常请求、失败、重试和UNKNOWN共同受原总物理预算约束。两种Full从对应相同raw派生，backfill/v14关闭；Rule仅用63 Train文档。费用仍未知。新模型工作流仅在独立activation分支或显式dispatch启动；修复分支的CI只做无模型凭据的离线校验。

C2 当前入口：[第一轮结果与停止报告](CONVERGENCE_C2_ROUND1_REPORT.md)、[保存决定](results/convergence_c2_v1/round1/summary.json)、[运行复核](results/convergence_c2_v1/round1/verification.json)、[独立审计](results/convergence_c2_v1/round1/independent_audit.json)、[campaign 账本](results/convergence_c2_v1/campaign/request_ledger.jsonl)。主评价 strict/joint TP/FP/FN=4/0/9、F1 47.06%；v13/v14 全部实体 payload 相同，目标变化为 0，其他保护条件通过。Full 与 ProTeGi_Full 同时关闭待准入的 `fixed_backfill_v14_train_cpe` 组合；v13 只是比较器，不自动获得替代准入。

C2 历史准备证据：[恢复报告](CONVERGENCE_C2_REPORT.md)、[运行登记](data/convergence_c2_pilot_v1.json)、[原阻塞 preflight](results/convergence_c2_v1/preflight.json)、[准备回执](results/convergence_c2_v1/verification.json)。原中断稿未找回，本次重建为三主来源/十三正例；不声称复原原稿的十六正例。历史零请求阻塞记录保留；本轮运行已解除凭据/SDK 阻塞并得到有效非准入结果。

C1 交付：[报告](CONVERGENCE_C1_REPORT.md)、[范围/预算草案](data/convergence_c1_scope_budget_draft_v1.json)、[复算回执](results/convergence_c1_v1/verification.json)。草案不可直接用于运行，不能代替科学预注册或新推理授权。

这是可更新的管理入口。README、`CURRENT_EXPERIMENT_STATUS.md` 及各版本报告是冻结的历史证据，保留原字节。科学登记和程序门禁优先于本计划的状态描述。

## 1. 当前状态

审计基线：分支 `codex/configuration-v11-fix-20261004`，提交 [552e680](https://github.com/Thehe01/experiment4/commit/552e6807c092f8ae3c90e66bbb32cec2cd3ed1a0)；main 为 `c71cfbd`。

| 对象 | 已确认的事实 | 对推进的意义 |
|---|---|---|
| Gold v11 | 105 文档、5545 实体、855 关系、571 Configuration；开发划分 63/21/21 | 保持冻结，不为提高分数补标 |
| v12 新推理 | 主评价 F1 28.57%，全部角色诊断 F1 72% | 开发证据，不代表总体效能 |
| v13 新来源 pilot | 主评价 TP/FP/FN=0/0/14，原判定 `failed_thresholds` | 保留失败结论 |
| v14 已知错误回放 | 主评价 12/0/2、F1 92.31%；全部角色 33/1/2、F1 95.65% | 已知错误开发回放，不替代新样本证据 |
| v14 离线复核 | `--check` 通过；299 个直接绑定匹配、295 次正向测试执行、60 保存窗口回放、0 新模型调用 | 工程复核通过，不能直接开 Stage2/Test |
| C2 第一轮前瞻开发 pilot | 六次成功请求；主评价 4/0/9、F1 47.06%；v13/v14 相同，目标变化 0，正确 span/CPE 无损失 | `enhancement_not_admitted`；关闭本候选组合，停止 C2，不追加第二轮 |
| 正式有效性 | 人工 IAA、新预留未见最终 Test 尚缺；v14 formal adapter 未启用 | 正式与 Test 门禁关闭 |

证据：

- [数据冻结清单](data/dataset_freeze_manifest_v6.json)
- [v13 新来源原始报告](CONFIGURATION_V13_FRESH_TRAIN_PILOT_V1_REPORT.md)
- [v14 回放报告](CONFIGURATION_V14_OFFLINE_FIX_V1_REPORT.md)
- [v14 注册](data/configuration_v14_offline_fix_v1.json)与[复核回执](results/protegi_optimization/configuration_v14_offline_fix_v1/verification.json)

当前已知缺口：两个混合 base/R2 候选 FN 保留为性能限制，不要求达到零 FN。C1 已核对 Skia 是组件提及，但独立 CPE 仍未解决；新评价对所有未决身份/跨度/CPE 争议统一在推理前隔离至 pending_label 控制层，不计主 TP/FP/FN，不追改原 v13 pilot 标签或分数。除非发现冻结协议违反、评分错误或正确实体被误删，不自动新增规则。

## 2. 本轮要完成什么

核心问题：在相同数据、运行条件和评分口径下，ProTeGi 提示优化与固定确定性增强分别带来多少收益，失败发生在哪里？

最小主比较固定为五种方法：Rule、匹配的零优化两阶段 P0、Full、ProTeGi、ProTeGi_Full。C1 发现旧 Multipass 和 ProTeGi 的初始提示及额外关系修复路径不同；新主比较统一从 ENTITY_PROMPT_P0/RELATION_PROMPT_P0 开始并使用同一 TaskEvaluator 推理路径，旧 Multipass 只保留为历史参照。P0/ProTeGi 与 Full/ProTeGi_Full 形成同条件的增强对照，两种 Full 共用同一确定性规则组合。ProTeGi 只采用 constrained；MC、greedy、uniform、unconstrained 搜索范围及单组件消融暂列扩展。C1 已核对章节承诺并记录此次范围收缩，不能把未完成的消融写成已完成贡献。

主结果报告四类实体严格 P/R/F1、三类关系严格 P/R/F1、规范化事实指标及分类型结果；Configuration span/CPE 联合匹配单列。配对差值和置信区间优于只比较总 F1。映射层的覆盖率、来源与限制独立报告，没有独立映射 Gold 时不声称语义准确率。

完成不以达到 95.65% 或 100% 为条件。完成应包含：冻结方法与数据、执行注册内的对比、保存失败/负结果、说明限制、能离线复算。没有有效新最终 Test/IAA 时，交付名为“开发实验报告，正式评价受阻”，不称正式实验完成。

## 3. 五项任务

这是有限任务清单，发现新问题归入现有任务或扩展 backlog。C2登记第一轮已停止，C4登记内Train/Dev执行已完成；本次归档和状态同步没有新增模型请求。

| ID | 任务 | 依赖 | 当前状态 | 验收产物 |
|---|---|---|---|---|
| [C1 / #1](https://github.com/Thehe01/experiment4/issues/1) | 固定最小比较、标注争议处置和预算 | 无 | **已完成离线交付** | 报告、不可执行范围/预算草案、复算脚本与回执；三项验证退出码 0 |
| [C2 / #2](https://github.com/Thehe01/experiment4/issues/2) | 有上限的独立 Train 开发 pilot 与实现准入 | C1 | **已完成并停止：`enhancement_not_admitted`**；六次成功请求，关闭 Issue | 六完整响应、发送前账本、raw/v13/v14、独立复算与停止报告；目标变化为 0 |
| [C3 / #3](https://github.com/Thehe01/experiment4/issues/3) | 新最终 Test 与真实人类 IAA 准备 | C1；离线部分不依赖新推理 | **离线准备完成，真实材料待补**；新Test候选/独立人工标注/IAA尚缺 | [操作说明与六份模板](data/convergence_c3_v1/README.md)、[已知暴露元数据索引](data/convergence_c3_v1/known_exposure_index.json)、[准备报告](CONVERGENCE_C3_OFFLINE_PREPARATION_V1.md)、[回执](results/convergence_c3_v1/offline_preparation/verification.json)；未冻结新Test，formal/Test关闭 |
| [C4 / #4](https://github.com/Thehe01/experiment4/issues/4) | 当前lineage的Stage1、实体缓存和Stage2开发 | C1 + C2停止分支 + 当前lineage及运行登记 | **已完成并关闭#4**；实体/关系各六轮、1152缓存窗口、五方法Dev比较完成，累计14864/580 | [运行37818651924](https://github.com/Thehe01/experiment4/actions/runs/37818651924)、[结果v1](results/convergence_c4_v1/final_result_v1/README.md)；[完整ZIP分片清单](results/convergence_c4_v1/final_result_v1/archive_parts/manifest.json)、[验收回执](results/convergence_c4_v1/final_result_v1/archive_parts/verification.json)已保存 |
| [C5 / #5](https://github.com/Thehe01/experiment4/issues/5) | 同条件对比、误差分析和可复现交付 | C4；正式 Test 还依赖 C3 | **Dev交付/完整归档/状态同步已完成；正式评价受阻**，#5保持开放跟踪C3 | [分析](results/convergence_c4_v1/final_result_v1/review/analysis.json)、[复核脚本](scripts/review_convergence_c4_final_v1.py)、[交接](HANDOFF_C4_FINAL_V1.md)；formal/Test关闭 |

C1 已完成的离线工作（具体决定与证据见交付报告）：

1. 建立三类问题表：协议/数据/评分错误；工程安全错误；性能不足。每项给证据和处置，不用“要做到 v 几”作为目标。
2. 对 R2 保留现有隔离语义；Skia 给出独立身份与标注口径决定，争议未决则新评价在推理前按统一规则排除/隔离并单列计数。原 pilot 原样保留。
3. 确定 Full 与 ProTeGi_Full 共用的规则组合。v14 是待准入候选，不把回放分数当作准入；若不准入，记录关闭该组件或采用经当前 lineage 校验的替代路径，不擅自借旧 v7 门禁。
4. 列出旧结果能否复用及理由。run10 的历史 `formal_eligible` 不自动适用于 Gold v11；旧缓存、旧预测只在精确 lineage 一致时复用。
5. 用实际窗口数及优化配置计算主对比的 task/optimizer 调用上限、时间/费用估算和停止条件。主实验预算未登记即为 0，不能用本计划启动运行。

## 4. Pilot 与停止条件

下列是本轮收敛策略的硬上限；不构成新推理授权。每次推理还须有独立预注册、适用用户授权及通过 preflight。

- 最多两轮前瞻开发 pilot；每轮最多 8 个窗口、12 次 hy3 物理请求，两轮合计最多 24 次。失败、重试及 UNKNOWN 均计入；续跑不重置。optimizer 调用为 0。
- 第一轮默认验证现有 v14。第二轮仅在第一轮发现可定位的协议执行/评分/正确实体保护错误、且一次集中修复完成后开展；修复后使用另外预注册的来源，原失败保留。单纯 F1 较低不启动第二轮。
- 一轮覆盖主评价、挑战和负例控制，主评价至少 3 个独立来源文档、12 个 Configuration 正例；全部来源/文本、排除规则、Gold、CPE 依据、角色、跨度归属、提示、runtime 和调用预算在推理前冻结。不能靠模板挑战抬高主评价结果。
- 注册需审计来源与已暴露来源的重合，目录排除本轮文档；source-disjoint 仅指已核验范围，不等同于新 Test 或未知产品能力。
- 工程晋级要求：响应和账本完整、预算/终止性成立、主评价 strict 与 joint TP 均大于 0、正确 raw 实体及 CPE 无损失、非 Configuration payload 不变、实际规则至少改变一个预注册目标窗口。评分与正确实体保护独立复算。没有主评价正例或没有触发规则则记覆盖不足并停止，不自动补来源重开。
- 不设“必须复现 95.65%”或“零 FN”门槛。符合工程准入也只支持对应 Train/Dev 开发推进，未证明效能提升。正式改善结论只来自后续固定条件的比较。
- 原登记、原程序门禁若更严格，继续按更严格条件执行；此计划不覆写它们。新实现需新路径/冻结，不能修改旧绑定实现使历史验证失效。

| 发生的情况 | 必须采取的动作 | 收敛状态 |
|---|---|---|
| 一轮有效、工程门槛通过，但 F1 有不足 | 记录误差，按有效准入推进 C4；不追加优化规则 | `pilot_admitted_for_development` |
| 覆盖不足或只有性能门槛/泛化不足 | 保留失败；关闭该增强或收缩方案与结论，不自动再 pilot | `enhancement_not_admitted` |
| 第一次发现协议/正确性错误 | 最多一次集中修复与独立复核，登记后才可用第二轮 | `one_correctness_repair_allowed` |
| 第二轮失败、总额度耗尽或出现第二批需要算法修复的错误 | 结束本轮规则增强路线，交付原因和剩余限制 | `enhancement_stopped` |
| 数据/评分/冻结错误无法在上述限额内解决 | 不执行相关无效比较，保存复现与阻塞 | `engineering_blocked` |
| 开发对比完成，新 Test/IAA 未提供 | 交付受限开发报告与待补材料，不开正式门禁 | `development_complete_formal_blocked` |
| 固定对比、有效最终 Test/IAA、结果和复现均完成 | 关闭任务，普通 bad case 留误差分析 | `formal_complete` |

主开发预算的 C1 原草案保持 15136/546；C4 独立离线草案落实停止分支后为 **14494/546**，只取消两种 Full 各 321 次增强后关系请求。Train/Dev 为 831/321 窗口，每阶段 6 轮、Beam=4、64 pulls×最多 8 实际窗口。拟定硬帽仍为任务 18000、优化器 600 个物理请求，24 小时；失败/重试/UNKNOWN 计入。历史草案已落实到 v4 可执行登记；用户明示取消金额条件并授权目的地与数据范围，当前总有效物理额度 18000/600，启动前已计入旧 task=8 UNKNOWN。C4 必须冻结实际调用路径、账本守卫、金额限制与独立运行登记；未知新最终 Test 的额度不包含在其中。结果不理想也不自动增加轮数或换种子。记录停止决定不是绕过错误或宣布虚假成功。

## 5. 本次管理交付与验证

- 新增本计划与 `AGENTS.md`，创建 C1–C5 Issues，提交现有开发分支。
- 不修改算法、Gold、历史冻结/报告/账本，不启动模型推理，不安装 Spec Kit/MLflow 或建立额外平台。
- 管理文件未加入旧科学哈希绑定，不影响旧复核。后续科学注册只绑定当时必要的不可变输入；当前管理入口独立更新。

已有可用的离线复核命令（有完整仓库与依赖时执行）：

```bash
python scripts/audit_convergence_c1_budget_v1.py --check
python scripts/verify_configuration_v14_offline_fix_v1.py --check
python scripts/freeze_dataset_manifest_v6.py --check --train-dev-only
```

每次推进把状态、结果路径/哈希、调用账本统计、失败原因和下一项可开展任务写回本计划。科学产物仍在新登记自己的目录中保存，不复制成第二份“最新结果”。

首次管理交付：新增两个管理文件，C1–C5 Issues 均已建立；原 v14 复核通过，历史证据保持只读。

C1 本次交付：新增报告、范围/预算草案、离线复算脚本和回执；更新本总计划与 Issue #1。以上三条命令最终退出码均为 0。C1 核对 45 项源文件绑定与 84 个 Train/Dev Gold 文档，复算窗口和调用预算；v14 复核为 295 次正向执行、60 保存窗口、299 直接绑定保持一致；Gold v11 Train/Dev 原检查通过、Test 标注打开数为 0（Test 哈希继承历史，非全数据现场复核）。新增模型调用为 0，未改算法、Gold、原冻结报告/账本，未合并 main。文件 UTF-8/LF、JSON、代码块和本地证据链接已核对。

合并节点：C1/C2 给出固定方案与明确准入或停用决定后，相关实现通过集成回归和冻结验证并形成可审查 PR，即可合并开发代码；不必等完 C3/C5或修到零 FN。正式评价仍需 C3 的新最终 Test 与真实独立人类 IAA。

## 6. 决定记录

- 2026-10-05：用户要求开始收敛整理。建立单一执行入口与五项任务；本次管理整理预算为 0 新模型调用。
- 2026-10-05：历史 README 与状态页已被注册绑定，保持只读；本文件承载当前执行状态，旧报告承载对应历史事实。
- 2026-10-05：性能不足不自动变成算法修复任务；限制 pilot 为两轮/24 物理请求，第二轮只用于一次正确性修复后的独立验证。
- 2026-10-05：保留现有五方法作为默认最小比较，扩展优化/搜索空间消融暂缓；最终范围与论文承诺核对在 C1 离线完成。
- 2026-10-05：C1 完成。发现旧 Multipass 与 ProTeGi 初始 P0/调用路径不一致；新主比较统一为匹配 P0 与共用推理路径，旧结果保持历史角色。Skia 组件身份与 CPE 分开处理，新评价统一隔离未决标签，不追改旧评分。
- 2026-10-05：登记完整开发流程逻辑预算 15136/546，拟定物理硬帽 18000/600、24 小时，pilot 仍限两轮/24 任务请求；当前有效推理额度 0。下一步先完成 C2 预注册，不从此草案启动模型请求。
- 2026-10-06：恢复 C2。原准备稿未落入可访问目录或远端；在新推理前重建六来源，主评价三来源/十三正例，并明确恢复缺口。固定 P0、63 文档 Train-only catalog、v13/v14 共用 raw 及账本；14 项测试、C1/v14/Gold 既有复核通过。preflight 缺 hy3 凭据与精确 SDK 依赖，物理请求 0；C2 保持开放，C4/正式/Test 门禁关闭。运行条件具备后只执行已登记第一轮，不据此扩展版本或主实验额度。
- 2026-10-06：用户提供凭据后，精确 SDK 依赖在仓库外安装，ready preflight 与已发布登记树通过；第一轮六窗口各一次，全部 HTTP 200/hy3/stop，重试及 UNKNOWN 均 0，optimizer=0。`--run` 退出 2 是非准入判定，`--verify` 和单独集合评分审计均退出 0。v14 主评价 strict/joint 4/0/9、F1 47.06%，正确 raw/v13 span/CPE 与非目标 payload 无损失；v13/v14 六窗口完全相同，唯一未满足条件是可评分目标变化为 0。按冻结协议记录 `enhancement_not_admitted`，Full/ProTeGi_Full 同时关闭本候选组合，停止 C2 并关闭 #2；不启动第二轮或新规则。C4 先明确剩余共用增强路径及当前 lineage，不能自动复用 v13 或旧门禁；本次不执行 C4，正式/Test/Stage2 继续关闭。
- 2026-10-06：C4 离线准备完成。沿用 C1 非准入分支，保留五方法及共用最终 apply_postprocess，两种 Full 从对应相同 raw 派生，不新增关系调用；独立适配器保护 raw。旧 Rule Train+Dev 资源会使用 Dev 评价标签，新路径限定 63 canonical Train，原启发式保持。冻结两份 P0、Train 词典、runtime/窗口及预算草案，共 371 项绑定；task 逻辑上限由 15136 减少 642 至 14494，optimizer 546。7 项针对性测试、1 项既有边界回归、禁止网络/Test Gold 访问审计、C1/C2/v14/Gold 原复核均通过。新请求 0，C2 累计仍 6；主开发执行器、全路径发送前账本、金额守卫及完整执行登记待接入，P_E*/缓存/P_R* 尚无，C4 Issue 保持开放，正式/Test/Stage2 关闭。
- 2026-10-07：C4 离线工程继续。新增独立四阶段五方法 runner、task/optimizer 共用并发安全账本、完整响应哈希、保守 token 金额预占、物理/金额/墙钟硬帽、UNKNOWN/跨进程 in-flight 阻断和完整上游阶段产物复验；冻结 `/v1` 地址去重、唯一 campaign 输出目录与非财务 C4 全字段，27 项 C4 离线测试通过。生成不可执行登记草案，有效额度仍为 0/0，新模型调用 0。账户价格证据、金额上限、精确授权与发布登记尚缺，故不启动 Stage1；P_E*、缓存和 P_R* 仍不存在，正式/Test 门禁不变。

- 2026-10-07：独立核验已发布 C4 执行器后，发现重定向可产生未登记发送、空/异常响应处理不完整、P0 未显式纳入最终决选、阶段账本与部分预测续跑证据不完整。在 v2 新路径修复，保留原实现/登记。禁止联网的四阶段微型回放通过，两阶段 task/optimizer 都经守卫，缓存不回退 Gold，Full 共用 raw，完成续跑新增替身调用 0。35 项离线测试与 C1/C2/v14/Gold 复核通过；冻结 v2 revision3 不可执行草案 229 项绑定（此前两份草案和守卫兼容性失败回执保留），管理总计划不进入科学绑定。真实新增请求 0/0，最终可执行登记仍缺账户价格、金额帽和适用主开发授权，故不启动 Stage1；#4 保持开放，正式/Test/实际 Stage2 门禁关闭。

- 2026-10-07 22:51（+08）：用户明确要求直接启动 C4，启动授权已收到，不重复询问该授权。立即核对当前远端与本地并执行 preflight，结果为 blocked_before_model_call / missing_published_execution_registration；账户计费依据、币种金额上限和 task/optimizer 四项单价均为空。记录 [启动检查](results/convergence_c4_v1/start_attempt_20261007T145122Z/preflight.json)，真实新增模型请求仍为 0。不以拟定物理帽代替未提供的金额帽；补齐金额登记所需实际输入后直接推进已授权运行。

- 2026-10-07 23:04（+08）：用户明确“不要这些直接启动”，覆盖此前金额/价格前置要求。保留所有历史登记，新增 v3 直接启动实现与 [授权证据](data/convergence_c4_direct_start_authorization_v1.json)、[可执行登记](data/convergence_c4_execution_v3.json)，费用未知字段为 null，不伪造零费率。task/optimizer 18000/600 物理硬帽、24小时、UNKNOWN/异常响应停止、原六轮/seed42/Train-Dev/五方法条件及正式/Test 关闭继续生效。5项直接启动门禁测试及16项既有runtime测试通过；233项绑定、凭据可用、preflight ready，发送前0请求。发布后直接启动四阶段开发链，实际运行进展在 campaign 账本与 Issue #4 记录，不再索要已取消的金额材料。

- 2026-10-07：v3 执行登记提交 c8addc5 已发布并核验，因原分支 ref 更新两次 GitHub 服务错误，使用恢复分支 codex/c4-direct-start-20261007。ready preflight 后启动 Stage1；首批8条发送前预占记录产生，2条自动记 UNKNOWN。随后 unified exec 跟进被自动审批拒绝：认为“直接启动”没有明确授权向 opencode.ai 发送实验文本、提示与含标注的优化错误样例；安全中断尝试返回 Unknown process id。保留原账本10行前缀并记录哈希，将其余6条中断未完成记录追加为 UNKNOWN；累计task=8/optimizer=0，成功响应0，未重放，也未启动后续阶段。见 [中断核对](results/convergence_c4_v1/development_run_v3/campaign/interruption_reconciliation.json)。金额/价格条件已按用户明确指令取消，不能据此恢复索要；后续受外部数据发送范围授权及UNKNOWN核对阻断。


2026-10-08 恢复入口：[v5恢复报告](CONVERGENCE_C4_RECOVERY_V5_REPORT.md)、[v5登记](data/convergence_c4_execution_v5.json)、[监督器](scripts/supervise_convergence_c4_v5.py)、[持久工作流](.github/workflows/convergence-c4-recovery.yml)。

2026-10-08 独立恢复入口：[v8报告](CONVERGENCE_C4_RECOVERY_V8_REPORT.md)、[v8登记](data/convergence_c4_execution_v8.json)、[工作流](.github/workflows/convergence-c4-recovery-v8.yml)、[bootstrap](results/convergence_c4_v1/remote_bootstrap_v8/manifest.json)。原会话及本轮会话丢失已对账；离线失败v6/v7保留，未发送模型请求。v8保持原科学检查点、预算、到期和正式/Test停止门禁。

- 2026-10-08：独立运行[37659262901](https://github.com/Thehe01/experiment4/actions/runs/37659262901)已实际核验；checkout、Python与依赖安装成功，凭据门禁明确报告 OPENCODE_API_KEY 缺失，模型步骤跳过，新请求0。恢复登记/检查点/累计账本保留；现有集成无设置Secret能力，待允许浏览器回退保存已提供凭据后以新reviewed activation启动，禁止直接rerun未知账本。

2026-10-08：用户允许浏览器保存已提供密钥并启动续跑。Secret已可见确认；远端v8错误入口在模型前停止，artifact全量对账。新入口：[v9报告](CONVERGENCE_C4_RECOVERY_V9_REPORT.md)、[登记](data/convergence_c4_execution_v9.json)、[工作流](.github/workflows/convergence-c4-recovery-v9.yml)。38项测试和284绑定通过，v8原字节保留。

2026-10-08：[launch revision2报告](CONVERGENCE_C4_REMOTE_LAUNCH_V9_REVISION2_REPORT.md)保留原v9登记/代码，仅新建精确绑定的独立启动登记和正确env的工作流；40项测试及原284绑定通过。Secret已创建，前两次远端准备失败均在模型前停止，artifact累计账本核验126次/17 UNKNOWN。

2026-10-08 恢复核验：[v10报告](CONVERGENCE_C4_RECOVERY_V10_REPORT.md)、[133次调用恢复登记](data/convergence_c4_execution_v10.json)、[42项测试回执](results/convergence_c4_v1/recovery_v10_preparation/verification.json)、[独立启动回执](results/convergence_c4_v1/independent_launch_v10_receipt/activation.json)、[实际运行作业](https://github.com/Thehe01/experiment4/actions/runs/37722384728/job/113132784042)。模型/Gold/split/评分、原物理帽与到期不变；此状态是续跑已启动，不等同于完整C4比较完成。

2026-10-08 v11修复：用户明确“帮我修复，权限续期一个月”。保留Slot3–8连续主链，以执行进度而非模型成绩选择；Slot2的818次已执行请求作为orphan计入累计预算，原始八份ZIP由SHA-256绑定并通过新离线工作流保全90天。恢复前驱采用needs作业链和精确run/attempt/slot名称，缺失即停；账本总数与主链序号分别计量，新增序号从6687开始而物理总量为7505。实体缓存逐窗落partial，恢复索引绑定stage/request/window并拒绝UNKNOWN与残缺JSON，已知截断不重复发送同上限父窗口。保留原24小时墙钟，续期不重置历史用量和时间；达到任一原停止条件即停止。

2026-10-08 21:16（+08）用户明确“开始实验”，授权启动已登记的 v11 Train/Dev 续跑。固定 activation 为已通过离线 CI 的 `930656f`，创建精确前驱作业链运行 [37783232258](https://github.com/Thehe01/experiment4/actions/runs/37783232258)，attempt=1。观察到 Slot 1 原始证据/登记/前驱门禁成功，执行步骤 in_progress；该观察不是新增物理调用或阶段完成回执，运行后用量由实际账本确认。新授权到期不替代原墙钟停止，今晚23:14仍自动停止；不重开实体优化，不开启 Test，不合并 main。管理入口与 [启动记录](results/convergence_c4_v1/v11_launch/launch.json)独立保存，不修改 activation 提交或冻结输入。

2026-10-08 22:00（+08）用户反馈再次出错。完成日志与失败快照核验：180秒等待HTTPS响应状态行后TimeoutError，请求6690无完整响应且已记UNKNOWN；未确认服务端是否完成，禁止盲目重发。三个新子窗均成功且响应哈希一致，原主账本6686条请求前缀保留；Train partial已逐窗落盘384条。失败ZIP的SHA-256为f80715455eb873f33cd2dce5f647a1d644b283db729b84ed1dd044997b921d87，artifact11552534766有效至2027-01-06。此前77项离线测试只证明恢复/预算/解析逻辑，不证明真实服务响应时延或网络稳定性。本次诊断新增模型调用0，不改冻结超时参数、UNKNOWN门禁或activation提交，不自动再次启动。

2026-10-08 22:14（+08）用户明确“帮我修复”，落实已说明的超时识别与账本恢复修复。新v12按类型识别传输故障，八次总尝试/64额外恢复物理调用双重上限；每次独立计费并链接前次，原6690的UNKNOWN不改、不声称服务端完成。保留全部v11冻结代码和科学输入，180秒单次超时与原墙钟不变。95项回归（含真实本地HTTP超时恢复）及384窗口/386完整响应重放通过，退出码0，新增模型请求0。原失败源快照6672响应哈希核验通过。新来源/运行/缓存位于v12路径；GitHub离线CI通过后，才可在原有效停止条件内续跑。

2026-10-08：v12提交083939c的GitHub离线验收[37795771222](https://github.com/Thehe01/experiment4/actions/runs/37795771222)已成功，95测试和384窗口/386响应复用均通过，源证据保全90天。沿已有“开始实验”授权建立固定activation并启动[37796478333](https://github.com/Thehe01/experiment4/actions/runs/37796478333)，attempt1。观察到Slot1恢复门禁成功、执行步骤in_progress；这是启动观察，不是新增调用完成或C4比较完成回执。[v12启动记录](results/convergence_c4_v1/v12_launch/launch.json)保存启动前累计7197/311和原停止条件，后续用量由实际账本确认。activation提交不随管理状态更新移动，原今晚23:14墙钟仍生效，main未合并。


### 2026-10-08 用户要求自动跑完：v13运行期限变更

用户在23:39:21（UTC+8）提出“为什么设截止时间，让他自己跑完不行吗”。结合本会话“权限续期一个月”和“开始实验”，本次把原24小时墙钟替换为现有授权到期，目标是原登记范围内完成即停止；原预算、阶段/轮数、算法与异常门禁不变。原注册v12及原失败快照不修改。

最新证据：运行37796478333/job113377122582明确报`campaign wall-clock cap reached`；原始artifact11559817897、ZIP SHA256 f02cb37cd67648fadac6df74621f7dd3218677ec7c3aacf9e25c060c19df35f9。已核验6851份保存响应哈希，主链6869次及废弃818次全部计费，没有新未解释UNKNOWN或在途请求。原563缓存需按v13新来源登记重建，避免混入旧冻结文件。

v13入口：[运行期限变更报告](CONVERGENCE_C4_COMPLETION_V13_REPORT.md)、[用户期限授权](data/convergence_c4_wall_authorization_v13.json)、[独立登记](data/convergence_c4_execution_v13.json)、[精确停止源](data/convergence_c4_wall_source_v13.json)、[核验回执](results/convergence_c4_v1/v13_evidence/verification.json)。原24小时草案仍为历史证据；新的有效运行期限以v13独立登记及程序门禁为准，不增加额外实验臂或推理额度。

v13启动记录：[launch.json](results/convergence_c4_v1/v13_launch/launch.json)；修复[PR#8](https://github.com/Thehe01/experiment4/pull/8)。activation固定提交8536e4401833bd1445f4e755a8b96af012c83f73，登记03fd122609a6f260849d16a1488010bda263b98c747e2175ecc6d424a1982800。管理记录更新不移动activation源码、不改变冻结登记；本次未合并main。


### 2026-10-09 v14首次阶段入口修复

用户在01:21检查完成状态，确认源运行37806261348失败；01:27:41明确“修复完后继续运行”。源码缺陷是把全局续跑标志传给尚未启动的关系优化器，工程修复无需改变算法或预算。源artifact11565812669保留90天，最新物理调用Task7965/Optimizer311，六轮实体优化和831+321完整缓存保留；原UNKNOWN与818次废弃分支仍计费。

v14入口：[阶段入口修复报告](CONVERGENCE_C4_PHASE_ENTRY_V14_REPORT.md)、[新登记](data/convergence_c4_execution_v14.json)、[精确源](data/convergence_c4_phase_source_v14.json)、[来源审计](results/convergence_c4_v1/v14_evidence/verification.json)、[零调用验收](results/convergence_c4_v1/v14_verification/verification.json)。108项回归、七项最后入口构造/保存/恢复检查、YAML与编译退出码0。最新代码修复仍须通过线上CI后使用固定提交恢复；不重发实体缓存，不合并main，不打开正式/Test。


v14启动记录：[launch.json](results/convergence_c4_v1/v14_launch/launch.json)；修复[PR#9](https://github.com/Thehe01/experiment4/pull/9)。activation固定使用8d26ae94f8a9da2ef60f7724a62ee27eb408b4ee与登记360f8f0c6eaa43cf297ca6b6ff0ca9dee60a3923a46bf2b6e203446084921602。管理状态更新不移动activation源码，不改变冻结登记，本次未合并main。


v14首个真实关系阶段检查点：[first_checkpoint.json](results/convergence_c4_v1/v14_launch/first_checkpoint.json)。源初始化7965/311之后新增8次Task请求，Slot1成功封存7973/311；Slot2进入执行。该计数是已保存快照用量，后续实时用量仍待新快照，整个开发比较尚未完成。


- 2026-10-09：用户要求保存最终结果v1并审查提升空间，随后要求handoff。源run正常完成；238产物哈希与315项评分复核0调用通过。Configuration漏召回是主要严格关系FN瓶颈；CPE联合覆盖与条件准确率分开，Full证据元数据误报在单列离线诊断中修正，原分数不改。小型结果和审查随交接提交，完整ZIP分片长期上传尚未完成，不把本地文件或未引用blob当远端保存成功。下一会话先校验源ZIP，再完成归档和#4/#5状态同步；不启动新实验。

- 2026-10-09：按HANDOFF继续，仅完成最终结果v1归档和状态同步。原ZIP的11个分片全部上传并落入[提交2494470](https://github.com/Thehe01/experiment4/commit/249447019202f6adc4849f950f2182af5715954f)；远端tree逐项Git SHA/大小一致，重组源哈希4e5eb2f25f93f5451846844f45fc34dfbfc69f8155d9ca3d11ee4de98dd94ab9。指定ZIP与无参数`--check`均退出0，238阶段产物、315评分一致，实际导入38个Python文件匹配远端；新模型调用0、Test打开0。#4按开发执行验收关闭，#5保留开放及#3依赖，PR#9保持draft/unmerged。原分数/响应/缓存/账本/Gold/登记和activation源码不动；旧交接中的“归档未完成”为当时记录，现已完成。正式材料缺失继续阻断formal，不开启额外优化、种子或Test。

- 2026-10-09：用户要求“继续”，按C3现有任务开展零模型调用离线准备。新增选样/双人独立标注/IAA与裁决材料框架，沿用v4.6和MCPU双层协议；元数据索引列105篇旧split文档、21条历史补充/参考资源记录、130条仓库来源文件，不读取旧Test标签、不宣称完整暴露审计。六份模板仍为空，7个JSON材料静态核验退出0；候选来源审计0、真实人工标注0、IAA未计算，新Test/预算/正式登记未冻结，formal/Test关闭。C3离线材料交付完成但#3保留开放，C5正式依赖未解除；C4冻结结果及归档、activation/main保持。见C3准备报告与验收回执。

- 2026-10-09：按用户当前结果审查推进48个raw Configuration FN的离线响应诊断。新增独立脚本、报告、逐例证据和回执，不覆盖原review/analysis.json。321保存实体响应重放、321窗口解析和21文档实体合并全一致；642请求/321实体响应/21 Dev Gold哈希校验通过，零窗口跨度覆盖缺失，实体子窗口请求0。分类为2解析缩短、19同名偏移歧义、6重叠表述偏移歧义、13边界差异、8当前位置无定位预测，另1最终后处理损失。全部48 raw FN中23个有同CPE预测在文档其他位置，分母/阶段与原关系端点17个线索不同；不推算恢复数。保存Train侧提及定位、CPE消歧和文档内证据关联候选设计，未执行v2或改规则。新模型调用0、Test打开0；C3真实材料缺口与#5正式阻塞保持，activation/main不动。

- 2026-10-09：用户要求判断原Test能否继续使用，完成零调用逐篇历史独立性审计。21篇均有Rule/Multipass/Full冻结清单条目和boundary v1审计条目；MCPU全量406项中，旧Test为12篇/78项（75 KEEP、3 REVISE_SPAN），2篇/3处实际跨度修改有policy与receipt互证。三方法引用的63预测/3结果文件未在当前远端tree，旧指标只作清单证据未重新验算；receipt核心policy/JSON audit哈希一致，旧review Markdown附属绑定不一致保留，不修旧文件。C4主账本14626条reserved中旧Test显式sample ID匹配0，不证明早期优化器或全部Prompt内容从未使用。旧Test不能认证为本轮全新一次性holdout，仍保留为历史/开发审计；新最终Test和真实IAA依赖不变。新模型调用0、新预测0、canonical Gold文件打开0，但历史Test审计标签记录已读；不把这写成完全未接触Test。见C3旧Test报告/机器记录/回执，冻结数据、v1结果与activation/main不变。

