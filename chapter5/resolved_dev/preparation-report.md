# v3实验接入与登记

1,724可用CVE（1,694有标签、30仅背景），固定31父候选。base Train691/691/690，augmented1547/1547/1546；配对Dev147/147/148，233不同CVE/442次出现。两条件23个主要技术按base Train≥10固定。12项UNKNOWN所属CVE整体排除；旧2跨域隔离及155保留组不进运行图。

用户核验声明已记录，未收到恢复隔离项的裁决文件；所有UNKNOWN意见不增加Gold，未声明独立人类IAA。v3来源选择的804CWE/2353CPE边正式接入；原标签与CWE/CPE保持。按spec固定DistMult/R-GCN mixed两模型、两条件、三折、三种子共36单位，最多3×240分钟CPU槽。

9行为测试RED/GREEN、28综合测试、六图独立验证、确定性ZIP、篡改/覆盖拒绝及原冻结绑定通过。登记SHA256 `ac19948da5d31cfede901073af08dbbc49c2b99950ff48e3f96bea334e075e5e`；详见checks.json、verification.json、negative-gates.json、review.md。测试含合成toy数值拟合；真实科学训练0、模型API0、reserved评分0。

接入与科学登记完成，尚待独立activation启动。本轮是v3范围上的数据扩展开发比较，不能从不同Dev的新旧分数差推出清洗的因果收益，不预报改善。
