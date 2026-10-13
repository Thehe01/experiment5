# CVE2ATT&CK 接入前处理

离线处理，预算为模型 API 0、训练 0、保留组评分 0。原图与注册不改变。

本轮清洗结果：860 个新增文本开发候选，1,552 条父技术关联；图背景待补。审计详情见 report.md，机器摘要见 audit.json 和 verification.json。处理后的数据包由用户会话交付，ZIP 字节摘要见 delivery.json；脚本能从固定作者 CSV 和原公开数据包重建。

## 复算

在仓库根目录，将已交付的数据包解压到 external-inputs，使用 Python 3.12 或更高版本，无第三方依赖。输出目录必须是新的空路径。

```bash
unzip CVE2ATTCK_preprocessed_20261011.zip -d external-inputs
python -m unittest discover -s chapter5/external_data/cve2attack_v1 -p test_prepare.py
python chapter5/external_data/cve2attack_v1/prepare.py \
  --source-dir external-inputs/original \
  --public-package chapter5/public_data/data/public-potential-v1.zip \
  --folds chapter5/public_dev/folds.json \
  --registry chapter5/external_data/cve2attack_v1/label_mapping.json \
  --config chapter5/external_data/cve2attack_v1/config.json \
  --out prepared-cve2attack
python chapter5/external_data/cve2attack_v1/verify.py \
  --source-dir external-inputs/original \
  --public-package chapter5/public_data/data/public-potential-v1.zip \
  --folds chapter5/public_dev/folds.json \
  --registry chapter5/external_data/cve2attack_v1/label_mapping.json \
  --out prepared-cve2attack
```

上述命令仅生成与核对处理数据，不启动模型，不选择新的候选范围。

## 使用边界

后续使用 new-text-candidates.jsonl，而不是全量 normalized-cves.jsonl。candidate 的 source_split 为作者来源属性，role 尚未分配。对于图模型，需要先按数据包中的 metadata-enrichment-queue.jsonl 补可靠 CWE/CPE，并保留原始元数据及来源。

config.json 绑定原作者四个 Git blob、原公开包、原划分、映射及预期规模。31 个标签都是父技术。映射名称通过 MITRE 官方页面核对，冻结候选活跃性通过现有图核对；完整 STIX 本次未重新下载。缺失标签不代表证实负例；标签集合差异清单仍未裁决。

新的数据接入或候选范围变化须独立登记，不能继续沿用已关闭的 36 单位登记，也不能与原 697 候选成绩直接计算算法增幅。
