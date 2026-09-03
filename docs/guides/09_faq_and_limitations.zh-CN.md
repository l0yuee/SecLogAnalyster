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
对于损坏的 `.evtx` 文件，这是预期行为——解析器会在损坏点之前尽可能恢复数据，并准确报告恢复了多少条记录。这不是缺陷；详见下文的已知限制部分。

**对一个非常大的单一文件执行 `ingest` 时速度较慢**
单个超大 `.evtx` 文件不会被拆分到多个工作进程中处理（并行是按文件粒度的）；当你有很多个文件时，`--workers`
的效果最明显。也请确认是否在不必要的情况下开启了 `--keep-raw`，因为它会使单文件处理成本大致翻倍。

**修复问题后想重新执行导入**
每次导入都是增量追加，重复执行是安全的；如果保留了暂存文件（`--keep-staging`，默认行为），可以直接调用归一化步骤（见
`src/seclogx/ingest/evtx/flatten.py`）在不重新解析源 `.evtx` 的情况下重新处理已有的 NDJSON——但对大多数用户来说，直接对相同来源重新执行
`seclogx ingest` 即可。

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
key 查找（在内置的表里，只有 `scheduled_tasks` 会遇到这种情况——见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)中的“不写 SQL 也能查询”）。错误信息会列出该表实际拥有的列名。如果你是想查
`actions`/`triggers` 内部的某个字段，请直接用 `--contains`/`--regex`
对这一整列做文本匹配，而不要尝试按字段名深入到其中某一项——它们是 JSON
*数组*，不是对象，按 key 提取不适用。

## 已知限制

完整、最新的 v1 范围决策与实测发现的边界情况列表位于
**`docs/known_limitations.md`**（英文）——请以该文件为准（它会随项目演进持续更新；本节不能替代它）。以下是日常使用中最可能遇到的几点：

- 基于 `UserData` 的 provider（部分 RDP/任务计划/Defender 事件）会被存储并支持全文检索，但目前尚未像基于
  `EventData` 的 provider 那样做字段级映射以支持 Sigma 狩猎。
- Sigma 日志来源类别会被路由到其对应的 **Sysmon** 等价事件，而非原生 Security
  通道的等价事件（例如进程创建 -> Sysmon 事件 ID 1，而非 Security 4688）。
- 非 EVTX 格式的判定基于内容而非绝对保证——不规范的日志头部可能被误判为无法识别（会被报告，绝不会静默丢弃）。
- 导入的有界内存是按单个文件计算的（单个文件的解析开销 × `--workers`），而不是按整个批次计算的——但每个 worker
  仍然是一次性读入单个文件，所以单个异常巨大的文件仍然是按文件计算的内存开销。见[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)。
- `.query()`/`.table()`/`.web_logs()` 等方法会把完整结果物化成一个 DataFrame；对于尚未过滤/聚合到较小规模的场景，请改用对应的
  `_chunks` 方法（见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)）。

其余内容——Exchange/Web 日志格式覆盖范围、计划任务格式支持、Sigma 特性覆盖范围、`search()`
精确匹配语义与内存估算的注意事项等——请直接查看 `docs/known_limitations.md`。
