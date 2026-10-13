# CVE2ATT&CK接入与31父技术开发比较

用户2026-10-11授权正式接入并开启实验；独立版本，不改原冻结实验或main。先看spec.md、config.json、registration.json与离线verification.json。所有科学单位固定36，最多3×240分钟CPU槽，模型API/保留组评分0。

输入包data/paired-parent-v1.zip从旧公开数据、旧三折和已补齐官方背景包确定性派生。858新CVE全部Train，每折base监督Train700→augmented1558，Dev150固定，31父技术领域固定。旧每折Train725/Dev155中25/5个无领域标签的样本保留背景，不造监督；报告覆盖150/155。扩展组31类每折最小训练支持17，base有一类无监督支持与少量稀有类，保留配对同候选、不据Dev删类。

DistMult mixed/R-GCN mixed各两数据条件×3折×3种子。相同评分范围重新运行四简单基线；主要技术宏分母固定base Train≥10的23类。输出同时报告同方法数据增量及对简单基线差值。31类父级分数不能与旧697域分数直接比较增幅，Dev参与早停/基线选择，不称最终泛化结果。

```bash
python -m pip install -r chapter5/requirements-cpu.txt
python -m unittest chapter5.expanded_dev.test_data chapter5.expanded_dev.test_campaign chapter5.expanded_dev.test_archive chapter5.public_dev.test_core chapter5.public_dev.test_model -q
python -m chapter5.expanded_dev.campaign verify --repo .
```

Python3.12.14、Torch2.9.1+cpu固定。prepare只生成首次登记，已有登记则核验，不覆盖旧科学输入。数据重建入口data.py需要三个原始固定文件（旧公开ZIP、补背景ZIP、旧folds），拒绝篡改/覆盖；运行时只读已冻结151825字节包，无网络源刷新。

独立activation分支codex/chapter5-expanded-activation-20261011；launch.json须绑定通过离线检查的source_commit与registration哈希。新workflow仅该分支/该launch路径触发；verify后再持久预占slot和跑登记单位。任何未闭合/失败/新workflow attempt不会盲目重置或补槽；合法同workflow续槽恢复全量state。远端持久结果位于chapter5/expanded_dev/runs/chapter5-expanded-dev-v1-20261011/。

原partial标签缺失不是确认负例，2026 NVD背景是当前回顾性信息；新增CPE过滤vulnerable=false环境条件，旧CIRCL reported背景按原字节语义保留。92个多源CWE差异未裁决；两个撤销编号隔离；原Dev重合标签不自动被新来源覆盖。原保留155的节点/边已从运行图排除，且没有评分入口。无独立人类IAA与全新最终Test的声明。
