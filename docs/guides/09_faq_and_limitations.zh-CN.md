# 9. 故障排查、常见问题与已知限制

**语言：[English](09_faq_and_limitations.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | 9. 常见问题与已知限制 | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

## 故障排查 / 常见问题

**"case '&lt;name&gt;' has no ingested data yet -- run `ingest` first"**
你创建/打开了一个案例，但尚未成功向其中导入任何数据（或所有来源文件都解析失败了）。运行
`seclogx ingest` 并检查核对报告中的错误信息。

**查询中引用的某一列不存在**
provider 特有的字段存放在 `event_data` 内部，而不是作为顶层列存在——应使用
`event_data ->> 'FieldName'`，而不是直接写 `FieldName`。完整的顶层列列表见
`docs/schema.md`。

**某次狩猎报告了处于“failed”状态的规则**
针对同一规则目录运行 `seclogx rules validate --rules <dir>`，可以看到每条规则具体的转换/字段映射错误，然后参见[《4. 威胁狩猎》](04_threat_hunting.zh-CN.md)中的“扩展检测能力”。

**某次导入中出现 `partial` 状态的文件**
损坏的 EVTX、被拒绝的文本记录，或已恢复有效记录之后发生的解析错误，都可能产生此状态。
先核对每个文件的记录数、错误数和错误消息，再决定结果是否可用。暂存写入或 flush 失败属于
致命错误，不能当作成功的部分解析。

**对一个非常大的单一文件执行 `ingest` 时速度较慢**
解析并行以来源文件为单位，单个大文件不会拆分到多个 worker。增加 worker 需要独立文件、剩余内存与
足够的 I/O 能力。EVTX `--keep-raw` 会增加 XML 解析和临时 SQLite 索引，具体成本取决于输入。
先查看报告中的暂存和转换阶段，再调整参数，见[性能与规模](08_performance_and_scale.zh-CN.md)。

**修复问题后想重新执行导入**
每次导入都会追加记录，重复导入相同来源可能造成重复，转换失败也可能留下部分 Parquet 输出。
当前没有自动续跑、去重或事务回滚。重新构建同一批证据时使用新 Case。保留的 NDJSON/Arrow 分片
有助于排查失败；调用内部 flatten 函数不是受支持的断点恢复协议。

**Jupyter 一直忙碌，或内核使用了错误的 Python 环境**
启动本地 Python 或 JupyterLab 前激活 `python314`，并检查所选内核的 `sys.executable`。
`c.ingest()` 会阻塞直到完成；`c.ingest_background(sources)`
使用同一解释器启动独立后台进程。通过 `c.job_status(job_id)` 查看进度，失败时检查
`<case>/jobs/<job_id>.log`。阶段为 `done` 后重新打开 Case，以建立最新查询视图。
后台执行不会降低内存需求，也不提供自动恢复；避免同时向同一 Case 写入。

**为什么出现 `.arrow` 文件，暂存为什么仍然很大？**
兼容的本地 Web/IIS 来源自动跳过暂存。其他来源使用 `staging_format="auto"`：达到
16 MiB 时采用 Arrow IPC/ZSTD，较小时采用 gzip NDJSON，EVTX 仍是 NDJSON。
这些来源仍先完成暂存再转换，因此临时磁盘需求可随完整暂存数据增长。转换成功后默认
删除分片；`keep_staging=True` 会保留中间文件并选择暂存路径，不会删除原始证据。
即使自动清理，也应为来源、暂存、Parquet 与临时文件共同预留空间。

**某个原本期望被导入的文件出现在“无法识别”列表中**
说明它的内容没有匹配任何已支持格式的检测规则（详见下文的已知限制部分）。常见原因包括：nginx/Apache
使用了自定义的 `log_format`（不是 Common/Combined 日志格式）、IIS/Exchange 日志头部被截断导致缺少
`#Fields:` 行，或来源路径下确实存在不受支持的文件。查看
`AuxIngestReport.unknown_samples`（或导入摘要中的示例列表）以获取确切路径。

**某条 Web 访问日志的 `log_type` 显示为 `web_access` 而不是 `nginx`/`apache`/`tomcat`**
三者默认使用的 Common/Combined 日志格式在字节层面完全一致；该标签只是一个尽力而为的路径/文件名启发式结果，而非确切检测。`web_access` 只是意味着没有找到任何线索——数据本身不受影响。

**`seclogx hunt` 报告某条规则“case has no '&lt;table&gt;' table ingested”**
说明该规则对应的日志来源类别所针对的表（`events` 或 `web_logs`）在这个案例里还没有任何数据，这不是转换错误。用
`seclogx sources <case>` 查看案例实际拥有哪些数据。

**对一张大表（尤其是 `web_logs`）执行查询时内存占用过高或返回很慢**
`c.query()`/`c.table()`/`c.web_logs()` 等方法会把整个结果一次性取成一个
DataFrame。改用对应的 `_chunks` 方法（`c.query_chunks()`、`c.web_logs_chunks()`
等）并迭代处理——见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)中的“大表的有界内存访问”。如果你使用的是命令行，`--out`/控制台预览已经自动采用了分块方式；如果仍然很慢，请检查你的查询
`WHERE` 子句是否真的具有选择性（一个未加过滤的 `SELECT * FROM web_logs`
无论是否分块，都需要扫描整张表——分块限制的是*内存*，而不是需要扫描的数据量）。

**`Case.search()` 抛出了 `ResultTooLargeError`**
这不是 bug——估算的结果被判定为超出了这台机器可用内存能安全容纳一个
DataFrame 的范围。错误信息里会给出估算的行数/大小；用 `search_chunks()`
以有界大小分批迭代同一个查询，或用 `search_to_csv()` 把所有匹配行流式写入文件。在命令行中，`seclogx
search` 永远不会因此报错——遇到同样的情况，它只会展示一个有界预览并给出提示，告诉你改用
`--out`。

**`seclogx search` / `Case.search()` 提示某个字段"不是……的列，而且这张表也没有可供查找的
JSON 字段"**
说明这个字段名既不是该表的真实列，这张表也没有 JSON 对象类型的兜底字段可供按
key 查找（例如内置的 `scheduled_tasks` 和 `registry` 表——见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)中的“不写 SQL 也能查询”）。错误信息会列出该表实际拥有的列名。如果你是想查
`actions`/`triggers` 内部的某个字段，请直接用 `--contains`/`--regex`
对这一整列做文本匹配，而不要尝试按字段名深入到其中某一项——它们是 JSON
*数组*，不是对象，按 key 提取不适用。

## 已知限制

完整、最新的 v1 范围决策与已知边界列表位于
**`docs/known_limitations.md`**（英文）——请以该文件为准（它会随项目演进持续更新；本节不能替代它）。以下是日常使用中最可能遇到的几点：

- 基于 `UserData` 的 provider（部分 RDP/任务计划/Defender 事件）会被存储并支持全文检索，但目前尚未像基于
  `EventData` 的 provider 那样做字段级映射以支持 Sigma 狩猎。
- Sigma 日志来源类别会被路由到其对应的 **Sysmon** 等价事件，而非原生 Security
  通道的等价事件（例如进程创建 -> Sysmon 事件 ID 1，而非 Security 4688）。
- 非 EVTX 格式的判定基于内容而非绝对保证——不规范的日志头部可能被误判为无法识别（会被报告，绝不会静默丢弃）。
- 导入时文本和注册表记录逐条输出到有界暂存批次，不再保留每个来源的全部行。计划任务 XML 整文档解析、
  注册表恢复和巨大的单个值仍是例外。worker 数量会放大解析器和缓冲开销；`memory_limit` 只控制单个
  DuckDB 转换的受管理内存，不是总 RSS 上限。见[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)。
- 解析与转换尚未形成带磁盘背压的流水线。自动续跑、跨次导入幂等、数据湖原子提交和查询快照均未实现；
  元数据锁也不会使并发导入成为事务。
- `.query()`/`.table()`/`.web_logs()` 等方法会把完整结果物化成一个 DataFrame；对于尚未过滤/聚合到较小规模的场景，请改用对应的
  `_chunks` 方法（见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)）。

其余内容——Exchange/Web 日志格式覆盖范围、计划任务格式支持、Sigma 特性覆盖范围、`search()`
精确匹配语义与内存估算的注意事项等——请直接查看 `docs/known_limitations.md`。
