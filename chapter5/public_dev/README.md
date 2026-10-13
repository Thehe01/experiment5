# 第五章公开潜在关联受控开发

独立于原 v1 实际利用任务，使用已冻结公开数据包：1035 CVE / 2332 潜在技术关联，697候选。880开发CVE做3组重复Train725/Dev155划分，155 reserved CVE不评分。背景为reported CPE/CWE及冻结ATT&CK上下文，属于已知节点的transductive补全。

四学习臂 × 3折 × 3种子 = 36个唯一训练单位。每单位最多500轮，Dev连续30轮无提升早停；频率、CWE、平滑CWE和邻居投票同折比较。仅开发进阶门槛，不自动打开保留组或35次确认实验。参数、基线全局选优规则、预算和语义见config.json、spec.md及registration.json。

```bash
export ATEN_CPU_CAPABILITY=avx2
python -m pip install -r chapter5/requirements-cpu.txt
python -m pip install -r chapter5/public_data/requirements.txt
python -m unittest discover -s chapter5 -t . -q
python -m chapter5.public_dev.campaign verify --repo .
```

`prepare`是首次注册工具；冻结后正常执行只允许`verify`，禁止用prepare覆盖登记来续跑。GitHub工作流在独立activation分支先离线验证，再预占CPU槽。每个单位首训前落盘账本，保存模型/优化器/RNG/最佳状态和摘要；续跑绑定不符或检查点丢失失败。三个240分钟CPU槽只在前槽closed且continuation_needed时串联；异常不自动重跑。

产物位于`chapter5/public_dev/runs/<protocol>/`，包含分片manifest、执行session、status以及完成后的comparison.json/report.md。完整逐轮日志、检查点、排名与基线在受摘要约束的状态归档内。数据/科学代码冻结；main不合并，模型API调用0，数据下载0（固定依赖安装除外）。
