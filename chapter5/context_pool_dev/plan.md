# context-pool候选实施计划

1. 固定spec/config/三图支持与覆盖/9单位/旧配对输入绑定；审计REQ与AC覆盖。规范登记的开发门槛与强基线报告范围保持（REQ-001/002/004/006/008/010）。
2. stdlib数据/预算/门槛测试RED→GREEN；数值pool/解码/梯度/预测一致性先写强测试，远端synthetic-only RED→GREEN，且真实图准入不调用模型（REQ-003/005/007/009）。
3. 在独立chapter5/context_pool_dev路径实现pool模型及原训练循环适配；原采样器/辅助loss不改。单线程workflow lease、单位预算永久预留、每25epoch/完成分片归档、RNG checkpoint与UNKNOWN停止（REQ-003/004/007/008）。
4. 独立科学登记绑定代码/数据/配置/旧9单位/Neighbor vote/runtime；发布当前开发分支的新launch工作流，经无模型/数值测试和原冻结门禁后训练9单位。完整单位不重跑（REQ-001/002/008/009）。
5. 用已登记9次最佳checkpoint重放核验分数/原始排名及覆盖；只读缓存复算原评分与配对门槛/邻居差，永久归档和管理状态同步（REQ-005/006/009）。

验证：python -m unittest chapter5.context_pool_dev.test_core -q；冻结CPU运行test_model（synthetic_test_only）；python -m chapter5.context_pool_dev.campaign verify；真实训练后checkpoint replay及verify_results只读审计。每项保留命令、退出码、路径与限制。

风险：本地没有Torch，数值RED/GREEN在CPU CI完成；Dev已暴露且属于传导协议，不能变成正式测试。未知执行状态停止，不把注册9单位扩大；运行中不修改冻结源码或预算。
