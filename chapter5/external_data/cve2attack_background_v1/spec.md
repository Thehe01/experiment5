# CVE2ATT&CK 背景补齐规范 v1

授权：用户2026-10-11「帮我补齐」，范围为上一轮860个新文本开发候选的可靠CWE/CPE背景补齐与交付。不启动科学训练、reserved评分，不改原数据、划分、标签或冻结登记。

输入：new-text-candidates.jsonl SHA256=3d50c15b49ac811839c402a8bf519430e15b4c75cea7ab8667110cc0e0ee3281；原公开ZIP SHA256=c00660f6d37cfefa2af35513ed785ca0e77f880746f34220edb204c353bfadbf；原folds及补齐前manifest仍保持。候选ID必须唯一860，原公开源、曝光记录、各折Train/Dev/reserved交集均为0。

来源：NVD官方CVE API2.0，cveIds批量参数实测返回指定两个编号。每批≤100，固定排序，序列请求起点间隔≥6.1秒，无API密钥，超时30秒，每批最多3次，总27次上限。原始HTTP响应字节、URL、采集UTC时刻、SHA256、来源published/lastModified全部保存。已有绑定快照可离线重放，不要求联网刷新。响应必须是NVD_CVE 2.0、编号在请求范围且不重复；截断、请求返回非指定编号或格式错误均拒绝。

规范化：仅接受weaknesses.description.value中的完整正数字CWE-ID，保留原来源/type/占位符和多源差异。仅接受configurations树中vulnerable=true的cpeMatch.criteria，保留原条件树、AND/OR/negate/版本边界及证据路径；非漏洞环境CPE不建背景边。采用原adapter的13段CPE2.3产品族规则，正确处理转义冒号，产品/供应商不能为*或-。不把产品名猜成CPE；不根据描述或ATT&CK标签推断CWE/CPE。

判定：REJECTED记录隔离；查无记录、获取失败、无数字CWE且无有效漏洞CPE均分别列入待补清单；具有可靠数字CWE或有效漏洞CPE之一即可graph_ready（与原OR背景门槛一致）。保留全部860记录的旧文本、标签、source_split和未分配角色；输出另列graph-ready和待补队列，不自动赋Train/Dev，不合入canonical Gold。图接入就绪仅表示数据最低背景门槛满足，不是科学模型已经可训练或验证提升。

验收：行为测试先RED再GREEN；原始响应逐编号来源定位；独立复算背景边及ID排除；输出与冻结输入哈希；重复生成字节相同；篡改快照和输入拒绝；网络失败不等价无背景；原partial31标签语义保持。快照是2026当前元数据，不声称2022时点信息或前瞻验证。训练0、模型API0、reserved评分0。代码/报告提交当前开发分支；数据原始快照及包持久保存。

获取后冻结：9批完整官方快照的manifest SHA256=e44ac6171c276513184ffab76d6a24be5887805b0e07753873498b47f705db09。独立验证必须绑定此快照及实际enrich.py哈希，后续重新联网获取不能直接替代本v1。允许新登记另存新版本，不修改本轮数据包。
