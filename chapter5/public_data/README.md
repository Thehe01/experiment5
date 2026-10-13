# 第五章公开潜在关联基准

此目录独立准备 CIRCL/CTID 的专家 CVE—ATT&CK **潜在利用与影响**标签。当前为数据准备完成，尚未训练或评价保留组；不替代 v1 的 observed exploited_by 实验，也不解除第四章 formal/Test/IAA 门禁。

- [规范](spec.md)、[实施计划](plan.md)、[审计报告与后续方案](report-20261011.md)
- [固定输入配置](config.json)、[验证回执](verification.json)
- [数据包](data/public-potential-v1.zip)：包含原始允许字段快照、1035 个具备图背景的外部 CVE、潜在关联图、训练视图、开发划分、隔离和复核清单、逐文件摘要。

## 使用与验证

无需 PyArrow 即可检查已经准备的数据包（仓库根目录）：

```bash
python -m chapter5.public_data.verify chapter5/public_data/data/public-potential-v1.zip
```

重建需要 Python 3.12 和 `pyarrow==23.0.1`。按 config.json 的不可变 URL 下载两份 Parquet，并从 v1 已冻结归档恢复原 `data/graph.json`、`data/sources/attack.json`。下面的 `CACHE`、`V1_STATE`、`OUT` 是本地实际路径，脚本不另行请求网络：

```bash
python -m pip install -r chapter5/public_data/requirements.txt
python -m chapter5.public_data.build --source-dir CACHE --v1-graph V1_STATE/data/graph.json --attack V1_STATE/data/sources/attack.json --out OUT
python -m unittest chapter5.public_data.test_adapter chapter5.public_data.test_package
```

所有输入先核对摘要。已有不同输出时拒绝覆盖；使用新输出目录检查变更，不通过删除绑定强行恢复。ZIP 自带清单，但清单也属于包内容；分发时同时使用验证回执给出的 ZIP SHA-256，不能把攻击者一起改写的清单视为可信来源。

## 数据约束

专家并集为 potentially_associated_with；三种阶段和未分类标签存在样本记录中用于复核，**不进入背景图**。只有数字 CWE 编号生成 has_reported_cwe，CPE 家族生成 has_reported_cpe。原 CPE 缺 vulnerable/configuration 语义，因此不称 affects；候选技术、战术和固定阶段规则来自冻结 ATT&CK 19.2。

techniques_derived 与 cwes_predicted 不在数据包中。公开数据的 upstream train/test 只作为来源属性保存，当前开发划分重新按 CVE 分组。reserved_holdout 尚未评分，公开标签曾用于规模与语义审计，不宣称完全未接触或模型预训练未知。

## 来源与许可

- [CIRCL 数据集](https://huggingface.co/datasets/CIRCL/vulnerability-attack-techniques)，提交 `319c3e324e7561592cf7e51ec003deb5dd90e61b`，DOI 10.57967/hf/9621。
- [CTID 原始标签与方法](https://github.com/center-for-threat-informed-defense/attack_to_cve)、[现行 Mappings Explorer](https://ctid.mitre.org/mappings/)。二者与 CIRCL 标签同源，不能当独立数据集累加。
- [CTID 方法](https://ctid.mitre.org/mappings/about/methodology/cve-methodology/)描述潜在利用及其影响；不是每条标签的真实攻击事件验证。
- [相关论文](https://arxiv.org/abs/2607.25572)。CIRCL 数据卡的专家标注来源声明不等于本项目完成重新标注或拥有独立人类 IAA。

专家映射 Apache-2.0，描述 CC-BY-4.0，MITRE ATT&CK 内容依其条款使用；保留来源与署名。源数据中 GPLv3 自动推导列已排除，不把其派生内容纳入本包。
