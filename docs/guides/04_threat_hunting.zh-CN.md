# 4. 威胁狩猎

**语言：[English](04_threat_hunting.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | 4. 威胁狩猎 | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

## 理解狩猎结果与 ATT&CK 标签

`seclogx hunt` 会运行所有能够加载并转换成功的 Sigma 规则，并报告三类信息：

- **匹配结果（小型狩猎使用 `results.matches`）**：实际匹配到的事件行，每一行都附带
  `sigma_rule_id`、`sigma_rule_title`、`sigma_level` 以及 `sigma_attack_ids`（以逗号分隔的
  MITRE ATT&CK 技术编号列表，例如 `T1003.001, T1003.002`）。
- **规则汇总（`results.rule_summary`）**：**每条被评估的规则**一行（而非每条匹配一行）——包含标题、级别、作者、匹配计数、ATT&CK 标签、参考链接。某条规则
  `matches == 0` 只是说明它在这个案例的数据中没有触发；对大多数规则而言，大多数时候这都是正常且预期的结果。
- **跳过 / 失败（`results.skipped`、`results.failures`）**：无法加载/路由的规则（日志来源类别不受支持），或无法转换/执行的规则（使用了尚不支持的
  Sigma 特性，或使用了此案例的处理管线尚未映射的字段）。请务必检查这两项是否为空，或确认原因可以接受——如需扩展字段映射，请参见
  `seclogx rules validate` 与 `docs/sigma_backend.md`。

ATT&CK 技术名称/战术信息来自一个内置的小型查询表（`data/attack/techniques.json`），仅覆盖内置规则集用到的技术编号——并非完整的 ATT&CK 框架。未收录的编号仍会以裸露的
`TXXXX` 编号形式显示。

内置规则集（37 条，位于 `data/sigma_rules/`）面向 **Sysmon** 遥测和 **PowerShell Operational** 事件。
Sysmon 类别需要采集并导入对应 Sysmon 日志；`ps_script`/`ps_module` 分别使用 PowerShell 4104/4103，
不依赖 Sysmon。导入 Security 4688 不会自动替代 Sysmon 的进程创建路由。内置规则是精选起点，并非详尽覆盖。

`hunt` 同样支持 Sigma 的 `category: webserver` 规则（针对 `web_logs`，即**访问日志**运行），方便你自行提供
IIS/nginx/Apache 的 webshell 或漏洞利用特征规则——v1 默认不内置此类规则。本项目当前没有为磁盘上计划任务定义、Web
应用**错误日志**（`web_error_logs`）、Exchange 邮件跟踪日志、Linux 文本日志、数据库日志（`db_logs`）、
腾讯客户端日志（`qcloud_logs`）或 Windows 注册表（`registry`——Sigma 的注册表类别针对的是*实时*监控遥测，
而不是离线的静态配置单元转储）配置 Sigma 路由，因此这些数据不属于当前 Sigma
狩猎的范围；请改用 `Case.suspicious_tasks()` / `seclogx tasks --suspicious`
排查计划任务，`Case.suspicious_registry()` / `seclogx registry --suspicious`
排查注册表，`web_error_logs`、Exchange 与 `db_logs` 数据则用原生 SQL 或 `search()`（见[《7. 常用查询》](07_recipes.zh-CN.md)）。

## 在 Jupyter 中处理大型结果

`c.hunt()` 会自动将完整匹配保存为案例 `hunts/` 目录下的 Parquet 文件。
小型结果仍可通过 `results.matches` 或 `results.to_dataframe()` 获得完整 DataFrame。
当所有规则的累计结果超过自动内存或行数预算时，这两个入口会抛出带有操作说明的 `MemoryError`。
这项行为自动生效，无需调整导入或狩猎参数。

```python
results = c.hunt()
print(results.summary_text())
print(results.total_matches)       # 已评估规则的精确总命中数
display(results.preview(100))      # 预览，不代表完整结果

results.save("all-matches.csv")    # 流式导出全部匹配，大结果同样适用
for chunk in results.iter_chunks():
    # 分析或汇总当前分块，处理后释放。
    print(chunk["sigma_rule_title"].value_counts())
```

`preview()` 在预览字节预算内返回不超过指定行数的结果，默认请求 100 行。
返回 DataFrame 的 `attrs` 包含 `total_matches`、`preview_rows`、`complete`，分别表示总命中数、
预览行数和是否完整。`is_spilled` 表示完整结果超过了自动 DataFrame 加载预算。
`iter_chunks()` 按有界批次读取所有已保存的行；请只保留需要的汇总，不要把全部分块收集到列表中。
Arrow 批次大小会根据 Parquet 元数据调整，较宽的批次在转为 pandas 之前拆分。
单条特别宽的记录或 Parquet 字典解码仍可能超过批次的字节目标，目标并非进程内存硬上限。

关闭 Case 或重启 Jupyter 后，保存的结果仍然可用：

```python
from seclogx.detect import HuntResults

saved_directory = results.result_dir  # 保存此路径，供后续会话使用
reopened = HuntResults.open(saved_directory)
display(reopened.preview())
```

同一事件可以因命中多条规则而出现多次，因此总数是规则命中数，不是唯一事件数。
完整匹配可能占用较多磁盘空间。失败规则会保留在 `failures` 中，其未完成输出不会计入结果。
每次本地狩猎读取一个已提交的案例快照；分布式 worker 分别获取已提交快照，
如需所有 worker 针对同一份数据运行，应等导入结束后再狩猎。
分布式 worker 返回结果路径和计数，需要能够访问共享的案例目录。

外部规则字段会经过校验和标识符引用，只有项目维护的字段映射可以生成 SQL 表达式。
生成的查询在独立受限连接中运行，仅允许目标案例表和支持的条件表达式；
额外 SQL 语句、任意函数和无关文件访问会被拒绝。这些限制不会判断检测规则是否有效或执行代价是否合理，
仍应检查命中数与失败信息。

## 扩展检测能力：自定义规则与字段映射

`--rules` / `rules_dir=` 可以指向任意包含标准 Sigma YAML 规则的目录；指定目录会替代内置规则选择。在正式依赖一套新规则之前，先运行：

```bash
seclogx rules validate --rules /path/to/your/rules
```

它会逐条报告加载与转换结果，并不针对某个案例执行 SQL。未映射字段有时能转换成功，但在执行时才报错。
规则需要适配的常见原因：

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
