# 4. 威胁狩猎

**语言：[English](04_threat_hunting.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | 4. 威胁狩猎 | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

## 理解狩猎结果与 ATT&CK 标签

`seclogx hunt` 会运行所有能够加载并转换成功的 Sigma 规则，并报告三类信息：

- **匹配结果（`results.matches`）**：实际匹配到的事件行，每一行都附带
  `sigma_rule_id`、`sigma_rule_title`、`sigma_level` 以及 `sigma_attack_ids`（以逗号分隔的
  MITRE ATT&CK 技术编号列表，例如 `T1003.001, T1003.002`）。
- **规则汇总（`results.rule_summary`）**：**每条被评估的规则**一行（而非每条匹配一行）——包含标题、级别、作者、匹配计数、ATT&CK 标签、参考链接。某条规则
  `matches == 0` 只是说明它在这个案例的数据中没有触发；对大多数规则而言，大多数时候这都是正常且预期的结果。
- **跳过 / 失败（`results.skipped`、`results.failures`）**：无法加载/路由的规则（日志来源类别不受支持），或无法转换/执行的规则（使用了尚不支持的
  Sigma 特性，或使用了此案例的处理管线尚未映射的字段）。请务必检查这两项是否为空，或确认原因可以接受——如需扩展字段映射，请参见
  `seclogx rules validate` 与 `docs/sigma_backend.md`。

ATT&CK 技术名称/战术信息来自一个内置的小型查询表（`data/attack/techniques.json`），仅覆盖内置规则集用到的技术编号——并非完整的 ATT&CK 框架。未收录的编号仍会以裸露的
`TXXXX` 编号形式显示。

内置规则集（37 条规则，位于 `data/sigma_rules/`）专门针对 **Sysmon** 事件字段（进程创建、网络连接、文件事件、注册表变更、镜像加载、DNS
查询、命名管道、PowerShell 脚本块、进程访问）——只有当 Sysmon 确实在运行且其日志被导入时，这些规则才可能命中。它是一个精选的起点，而非详尽覆盖；如需添加更多规则，请参见下文“扩展检测能力”。

`hunt` 同样支持 Sigma 的 `category: webserver` 规则（针对 `web_logs`，即**访问日志**运行），方便你自行提供
IIS/nginx/Apache 的 webshell 或漏洞利用特征规则——v1 默认不内置此类规则。目前没有针对磁盘上计划任务定义、Web
应用**错误日志**（`web_error_logs`）、Exchange 邮件跟踪日志或数据库日志（`db_logs`）的 Sigma 日志来源类别，因此这些数据不属于 Sigma
狩猎的范围；请改用 `Case.suspicious_tasks()` / `seclogx tasks --suspicious`
排查计划任务，`web_error_logs`、Exchange 与 `db_logs` 数据则用原生 SQL 或 `search()`（见[《7. 常用查询》](07_recipes.zh-CN.md)）。

## 扩展检测能力：自定义规则与字段映射

`--rules` / `rules_dir=` 可以指向任意包含标准 Sigma YAML 规则的目录——不必局限于内置规则集。在正式依赖一套新规则之前，先运行：

```bash
seclogx rules validate --rules /path/to/your/rules
```

它会逐条报告每条规则是否成功转换。规则无法直接转换成功的常见原因：

- **使用了 seclogx 尚未映射的 Sigma 字段。** 在
  `src/seclogx/detect/pipeline.py` 的 `FIELD_MAPPING` 中添加对应条目（具体写法参见
  `docs/sigma_backend.md`——字段表达式必须加括号）。
- **针对的日志来源类别（logsource category）尚未被路由。** 如果它针对 `events`，在同一文件的
  `LOGSOURCE_ROUTES` 中添加对应条目；如果它针对其他表（例如新的、以 `web_logs`
  为目标的类别），则添加到 `LOGSOURCE_TABLE` 中。
- **使用了尚不支持的 Sigma 特性**（区分大小写的 `|cased` 匹配、数值比较修饰符、关联规则/correlation
  rules）——v1 版本暂不支持，详见 `docs/known_limitations.md`。

修改映射之后，重新运行 `rules validate`，再对一个预期会命中的、含真实数据的案例执行
`hunt`，端到端确认效果。

下一步：[《5. 命令行参考》](05_cli_reference.zh-CN.md)查看 `hunt`/`rules validate` 完整的参数说明。
