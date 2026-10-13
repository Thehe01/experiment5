# CVE2ATT&CK 官方背景补齐 v1

本目录是独立离线背景补齐流程，输入上一轮860个新文本候选。用户授权「帮我补齐」。858个满足原图最低背景规则；2个官方REJECTED隔离。原标签、角色、冻结图、划分、训练预算保持，未训练/未评分。

数据包：`CVE2ATTCK_background_enriched_20261011.zip`（从本轮交付文件取得）。原始NVD响应、来源/时间/哈希、输入候选与6份机器输出在包内。代码仅保存在本Git目录，数据包不携带仓库代码。原公开ZIP仍用固定`chapter5/public_data/data/public-potential-v1.zip`。先解包数据文件，再离线复算；不要联网刷新固定快照。

```bash
python3 -m unittest discover -s chapter5/external_data/cve2attack_background_v1 -p test_enrich.py -v
python3 chapter5/external_data/cve2attack_background_v1/enrich.py \
  --candidates DATA/inputs/new-text-candidates.jsonl \
  --cache DATA/raw_nvd --out REPLAY
python3 chapter5/external_data/cve2attack_background_v1/verify.py \
  --candidates DATA/inputs/new-text-candidates.jsonl --cache DATA/raw_nvd --out REPLAY \
  --public-zip chapter5/public_data/data/public-potential-v1.zip \
  --folds chapter5/public_dev/folds.json --adapter chapter5/public_data/adapter.py \
  --receipt replay-verification.json
```

`DATA`是解压位置；`REPLAY`必须为空/不存在。`collect.py`是限速/限定重试的获取器：仅复用已完成快照时0新网络请求且不改manifest；首次获取不是旧固定快照重现。固定旧输入哈希在`spec.md`/代码中。补齐日期元数据是2026年现状，不用于2022时点回放。

使用`graph-ready-candidates.jsonl`及`background-edges.jsonl`进行后续**另行登记的数据接入准备**；尚未改变任何正式输入。`pending-review.jsonl`两个撤销编号不接入；`review/cwe-source-review.jsonl`保留92个多源CWE差异，不自动裁决。缺失标签仍不是已确认负例；父技术标签不扩展到子技术；原作者train/test仅为来源字段。

背景边表达「数据库报告的CWE/受影响CPE产品族」，保留原配置树与版本边界，不把简化产品族边解释为完整软件适用逻辑。`vulnerable=false`环境条件不建边。最低背景充分不代表已有邻居、正确标签、无时间泄漏或性能提升。详见`report.md`与验收回执。
