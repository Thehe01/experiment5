# source_resolution_v3_20261011

离线来源选择与争议隔离版本，报告见[report.md](report.md)。本目录不替代原实验或启动训练。

主要交付：

- `source-resolved-candidates-v3.zip`：1724可用记录、1736完整记录、14项隔离及全部台账/划分预览。
- `primary-evidence-v3.zip`：107个官方CVE及15个ATT&CK19.2技术文件原字节/许可证/Git与SHA256清单。
- `review-opinions.json`：20条AI核验意见，不是人工Gold。
- `protocol.json`：输入哈希与零实验预算的数据准备协议，不是科学实验注册。
- `verification.json`、`original-completion-verification.json`：来源/数据与原冻结实验绑定核验。

在仓库根目录及现有背景补齐ZIP可用时运行；背景ZIP为已保存的`chapter5/external_data/cve2attack_background_v1`分片交付文件重组后的原包，不做NVD刷新。

```bash
python -m unittest discover -s chapter5/external_data/source_resolution_v3_20261011 -p test_resolution.py

python chapter5/external_data/source_resolution_v3_20261011/resolution.py \
  --v2 chapter5/external_data/source_alignment_v2_20261011/source-aligned-candidates-v2.zip \
  --enriched /path/to/CVE2ATTCK_background_enriched_20261011.zip \
  --sources chapter5/external_data/source_resolution_v3_20261011/primary-evidence-v3.zip \
  --opinions chapter5/external_data/source_resolution_v3_20261011/review-opinions.json \
  --protocol chapter5/external_data/source_resolution_v3_20261011/protocol.json \
  --output /new/nonexistent/output
```

将同样六个参数传给`verify.py`，追加`--receipt /new/receipt.json`可独立核验和重新生成比较字节。输出目录及回执路径必须不存在。候选ZIP的10个`outputs/*`文件由上述构建器生成，其余根目录成员为交付文档/协议/回执。

旧划分角色保持在full记录与v2包；新usable预览只移除12个UNKNOWN CVE。因此新实验需要重新冻结分母与登记。保留组155不进入样本，UNKNOWN不作为确认负例，不从AI意见补Gold。原类别/年份分布差异未人为拉平。
