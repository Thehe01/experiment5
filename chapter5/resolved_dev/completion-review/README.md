# v3实验完成复核与分析

[运行38152196348](https://github.com/Thehe01/experiment4/actions/runs/38152196348)于2026-10-11 23:57（UTC+8）completed/success。36/36单位在slot1完成，verify、durable reserve、campaign、close及artifact成功；slot2/3因无需续跑正常跳过。永久完成提交a247a950412c517d4c80ff5bab7e46fece8b929e。

[原结果报告](https://github.com/Thehe01/experiment4/blob/a247a950412c517d4c80ff5bab7e46fece8b929e/chapter5/resolved_dev/runs/chapter5-resolved-dev-v3-20261011/report.md)及逐单位comparison.json、status/session/manifest永久保存于同提交，不复制改写原科学结果。复核命令见checks.json，验证exit0，明细verification.json、compact-results.json；源树及执行证据在remote-tree.json、execution-evidence.log、run.json。

## 同一新Dev上的配对结果

|方法|base MRR|augmented MRR|配对差|改善|
|---|---:|---:|---:|---:|
|DistMult mixed|0.381665|0.361880|-0.019785|1/9|
|R-GCN mixed|0.391734|0.355077|-0.036658|0/9|

主要23类宏MRR配对差分别-0.016022、-0.024933。R-GCN门槛要求均值差≥+0.02、改善≥6/9及主要类宏差≥-0.01，三项均未满足，本轮开发进阶门槛失败，不触发新调参/模型臂或确认训练。

|简单基线|base MRR|augmented MRR|差|
|---|---:|---:|---:|
|Frequency|0.370206|0.351723|-0.018483|
|CWE frequency|0.401573|0.373773|-0.027800|
|Smoothed CWE alpha10|0.452538|0.416316|-0.036222|
|Neighbor vote|0.465339|0.428606|-0.036733|

两条件最佳基线均为Neighbor vote；两扩展图模型均0/9超过同折扩展基线。由此观察，本轮增加856个CVE没有改善这套固定开发比较；也不能把所有下降简单解释为R-GCN一次随机波动。

## 已核对的完成证据

36唯一登记ID与真实slot1执行日志一致，全部trained，数字绑定按实际v3图、arm、cfg、seed及注册AVX2 runtime复算一致；28科学源Git blob与本地SHA1一致，config/registration/运行ZIP同源。MRR按CVE宏均值由互斥背景组重建最大误差5.55e-17，固定主要类宏误差0；所有配对均值/改善数、基线选择alpha/最佳家族、相对基线差及进阶判定独立算术复算一致。36单位均patience早停，35–343轮，best_epoch后30轮，未到500轮上限。

永久归档51分片，总212,300,186字节；连续名称、manifest总和、各分片远端大小/存在的Git对象及2GiB限额验证。此次未下载重组分片复算ZIP SHA256、未重放全部最佳检查点/原始排名，也未从原始分数重算全部基线。因此完成证据不替代更深的独立评分审计。

## 结论边界与下一候选

两条件共用新Dev147/147/148，共233个不同CVE、442次出现；三次留出有交叠，Dev参与早停与基线选择，属于回顾性开发成绩。旧Dev150与新Dev不同，不能直接把两轮MRR差解释为来源选择或隔离的因果收益。v3统一来源/隔离并不证明所有外部标签语义正确，也没有新独立人类IAA。12个UNKNOWN所属CVE及旧2跨域项仍排除，155保留组未评分。

不支持继续只靠这批外部数据扩容；优先候选是训练/验证的来源、类别、年份及同背景标签分布匹配，和模型是否充分利用CWE/CPE进行查询区分。但本轮并未隔离这些因果贡献，不能已经归因为确定标签错误、模型错误或样本太少。既有#19查询区分候选保持未实施/未登记/未启动，需单独固定协议。本次只做完成复核与状态同步，新科学训练/模型API/保留评分0，原判定及历史结果保持。
