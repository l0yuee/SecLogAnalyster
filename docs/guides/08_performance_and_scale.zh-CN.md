# 8. 性能与规模说明

**语言：[English](08_performance_and_scale.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | 8. 性能与规模 | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

- 默认面向单台工作站设计——无需任何额外配置、不依赖外部服务。此外还提供一种可选启用、通过环境变量激活的分布式模式（见[《10.
  分布式部署》](10_distributed_deployment.zh-CN.md)）：当一批导入任务的文件足够多，把解析工作分摊到多台机器上确实能节省总耗时；当
  Sigma 规则集足够大，逐条规则在单机上求值本身成了瓶颈；或者多名分析师希望在不各自保留本地完整拷贝的前提下，同时查询同一个共享案例时，分布式模式会有帮助。但它**不会**加速单条查询或单个较小的案例——无论是否启用分布式模式，查询执行本身始终是单机
  DuckDB 完成的，具体边界见该指南。在此前提下，不同日志类别的现实规模差异很大：EVTX
  案例通常远低于 100GB，而一个案例范围内的 Web 访问/错误日志现实中可以达到 TB 级别。
- 导入并行度（`--workers`）随 CPU 核心数扩展——各文件在独立进程中互不依赖地解析（在分布式模式下，则可以分布到任意数量机器上的
  `seclogx worker` 进程中）。
- 查询与狩猎都直接通过 DuckDB 针对按 Hive 方式分区的 Parquet 数据湖执行，具备惰性、核外（out-of-core）执行能力与谓词下推：一个限定了主机/通道/时间范围的查询，只会读取实际需要的
  Parquet 行组，而不会把整个数据湖都载入内存。不过，*取回*一个未加过滤的大结果时，默认仍然是单个
  DataFrame（`.query()`/`.table()`/`.web_logs()` 等，底层调用 DuckDB 的
  `fetchdf()`）——对于尚未过滤/聚合到较小规模的表或查询，请改用 `_chunks`
  同名方法（`.query_chunks()`、`.web_logs_chunks()`、`.timeline_chunks()` 等），其内存占用由
  `chunksize` 决定，而非结果总量。完整说明与示例见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)中的“大表的有界内存访问”；命令行（`query`/`table`/`tasks`/`timeline`）在
  `--out` 导出和控制台预览时都会自动使用这一机制，无需任何额外参数即可获得有界内存的行为。
- `.search()` 会在取回结果之前先估算其规模（精确的 `count(*)`，乘以从一个
  `LIMIT` 有界样本得出的单行字节数，再外推到全部行数——两步的开销都与表的总大小无关，因此这个估算过程本身不会耗尽它原本想要保护的内存），并与机器当前实际可用内存的四分之一做比较，超出就拒绝取回而不是硬取。可用内存的检测是尽力而为的（Linux
  上读 `/proc/meminfo`，其他平台用更粗略的兜底方式），如果完全无法确定，则回退为固定假设
  200MB 可用，而不是假设机器内存无限。见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)中的“内存安全检查”。
- `--keep-raw` 会使被应用文件的导入耗时与峰值内存大致翻倍——建议只在需要完整 XML
  保真度的特定证据上选择性使用，而不要对整个大型案例默认开启。
- 计划任务/IIS/Web 访问/Exchange/syslog/auditd/journal 日志现在也和 EVTX
  一样，先按文件暂存为 NDJSON，再由 DuckDB 直接从磁盘读取（`read_ndjson_auto`）后写入
  Parquet，而不再是把某张表在整个批次范围内的所有已解析行都累积在 Python 内存中。导入时的峰值内存现在由
  “单个文件的解析开销 × `workers` 数”决定，而不再由整个批次的总大小决定——即便一个批次的文件多到总量达到
  TB 级别，导入过程也不需要把它们一次性放进内存。单个文件的解析本身（编码检测需要）仍然是一次性整文件读取，所以单个异常巨大的文件仍然是按文件计算的内存开销，而不是按批次。

下一步：[《9. 常见问题与已知限制》](09_faq_and_limitations.zh-CN.md)，排查思路与完整已知限制的入口。
