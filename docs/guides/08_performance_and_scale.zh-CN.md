# 8. 性能与规模说明

**语言：[English](08_performance_and_scale.md) | 中文**

**[指南索引](../index.zh-CN.md)** · [Python API](06_python_api.zh-CN.md) · [分布式部署](10_distributed_deployment.zh-CN.md)

导入将文本日志和注册表记录逐条写入磁盘，并限制每次 DuckDB 转换的输入量。
实际资源消耗仍取决于格式、单条记录大小、worker 数量和存储条件。本文说明可用参数及其边界，
不承诺固定吞吐或整个进程的内存硬上限。

## 在 Notebook 中显式设置预算

本项目的本地 Python 运行和测试使用专用环境：

```bash
conda activate python314
python -m jupyterlab
```

选择 `python314` 内核，并在 Notebook 中检查 `sys.executable`；从该环境启动服务器
不会自动切换已有内核。

```python
from seclogx import Case, IngestOptions

c = Case.create("large_case")  # 后续会话用 Case.open("large_case")
options = IngestOptions(
    memory_limit="2GB",
    threads=2,
    staging_chunk_bytes=64 * 1024 * 1024,
    flatten_batch_bytes=256 * 1024 * 1024,
    staging_format="auto",
)
report = c.ingest([r"E:\evidence:HOST01"], workers=2, options=options)
print(report.summary_text())
```

示例中的 `IngestOptions` 是库的默认值，`workers=2` 则显式降低了解析并行度。**2GB 限制的是单个 DuckDB 转换实例管理的内存，不是 Notebook RSS 或整个进程树的硬上限。** Python 对象、原生库分配、解析工作进程、注册表恢复、其他查询和后台任务均可能额外占用内存。`threads` 控制转换线程，与解析 worker 分开设置。

`staging_format` 对每个受支持的辅助来源文件分别选择暂存格式：

| 设置 | 辅助来源暂存 |
|---|---|
| `"auto"`（默认） | 达到 16 MiB 时使用 Arrow IPC / ZSTD level 1；较小来源使用 gzip NDJSON |
| `"arrow"` | 不论来源大小，均使用 Arrow IPC / ZSTD level 1 |
| `"ndjson"` | gzip NDJSON，压缩级别为 1 |

三种设置下的 EVTX 暂存都仍是 NDJSON。辅助来源的 Parquet 输出在两种暂存路径下均使用 ZSTD level 1。CLI 对应 `--staging-format auto`、`--staging-format arrow` 或 `--staging-format ndjson`，与 `--background` 配合使用时同样有效。

## 可选原生解析器

独立安装的[原生组件](../../native/README.md)使用 Rust 有界解析 UTF-8 的
Common/Combined Web 访问日志和 IIS W3C 访问日志。应安装到 Notebook 内核及导入
worker 使用的同一环境中。现有 `Case` 方法和结果表结构保持一致。

| `IngestOptions.parser_backend` | 对已识别辅助来源的行为 |
|---|---|
| `"python"`（默认） | 无论是否安装组件，都保留 Python 兼容路径 |
| `"auto"` | 显式启用可选原生解析；组件、编码、格式及所选输出路径均兼容时使用原生，否则回退 Python |
| `"native"` | 必须支持原生解析，不可用或不兼容时失败 |

CLI 对应 `--parser-backend auto|python|native`，默认为 `python`，后台导入同样支持。EVTX 保持现有解析器。
在暂存路径显式启用原生解析后，`staging_format="auto"` 下的较小文件仍选择 NDJSON 并使用 Python；如需对小文件使用
原生解析，应设置 `staging_format="arrow"`。严格原生模式适用于兼容来源，不适合
同时含有其他已识别日志类型的混合集合。

原生解析器直接构建 Arrow 字符串缓冲，在读取和解析时释放 GIL。默认暂存路径的批次由同一文件
worker 消费，协调器只接收清单，因此原生路径无需逐条创建 Python 字典。
规范化仍使用相同的 DuckDB SQL。来源哈希和完整编码验证仍在解析之前完成，
默认路径在转换前仍会写出 Arrow IPC 暂存；仅启用原生解析不会消除这部分 I/O，也不把单个文件拆给多个 worker。

`auto` 模式下遇到原生路径不支持、需要 Python 兼容处理的语法时，先删除该文件的
全部原生暂存分片，再通过 Python 完整重读。因此发生回退时可能多读一遍来源。
读写错误、已检测的来源变化及不符合接口约定的原生批次均为致命错误；普通解析错误保留既有的已接受前缀语义。
`report.aux.staged_files` 中每项的 `parser_backend` 和 `backend_reason` 记录实际后端及
回退原因，可用于区分“安装了组件”和“确实使用了组件”。

## 可选直接 Parquet 转换

`direct_parquet` 默认是 `False`。对于本地兼容的 Web 访问/IIS 来源，需要显式启用
直接转换，并关闭暂存保留：

```python
from seclogx import Case, IngestOptions

web_case = Case.create("web_direct")
report = web_case.ingest(
    [r"E:\evidence\web:HOST01"],
    keep_staging=False,
    options=IngestOptions(parser_backend="auto", direct_parquet=True),
)
```

CLI 对应 `--parser-backend auto --direct-parquet --no-keep-staging`，前台和后台导入都支持。此模式要求
本地存储、未配置 broker，且 `parser_backend` 为 `"auto"` 或 `"native"`。
原生 Arrow 有界批次直接进入 DuckDB，沿用固定 VARCHAR 输入、规范化 SQL 和 ZSTD
Parquet 输出。小文件同样可以直接转换，不要求 `staging_format="arrow"`；暂存格式
只影响兼容回退及其他来源。

普通辅助来源先在工作池中完成暂存，工作池关闭后，符合条件的直接来源再由协调器
逐个处理。普通 worker 预算保持不变，直接来源不会并行转换。直接转换与 EVTX、
旧暂存转换共用 `CONVERSION_LOCK`，同一进程同时只有一个导入 DuckDB 转换使用
其内存和线程预算。这仍不是 RSS 硬上限，独立进程也不共享该锁。

来源哈希和严格编码准备仍需预读。`auto` 模式遇到组件不可用或不兼容、编码或语法
不兼容时，先清理私有原生输出，再对整份来源执行 Python 暂存回退，复用同一准备对象
中的来源身份和编码；严格 `native` 模式则失败。来源变化、I/O、异常批次及转换故障
均为致命错误；普通解析错误可以将已接受的完整前缀作为 `partial` 发布。

每份来源先写入 `lake/` 之外的 `<case>/_ingest_private/`，完成转换、关闭和来源核验
后才发布。没有恢复任何行时报告 `failed`，不发布文件。这是来源级边界，不是整次导入
原子事务：后续来源失败时，先前已发布的文件可能保留。崩溃也可能留下私有文件；当前没有
自动恢复、续跑或防重复保证。清单中的 `parser_backend` / `backend_reason` 表示解析选择，
`output_format`（`staged` 或 `parquet`）/ `parquet_paths` 则单独记录输出形式。

Windows 使用拒绝覆盖已有文件的重命名操作发布。POSIX 要求私有输出与目标位于
同一文件系统，且支持硬链接。如果发布操作不受支持或失败，导入会报错，不会改为
复制或 Python 重放。这些平台相关规则不代表所有平台及依赖版本组合都已验证。

## Worker 预算与后台导入

`workers` 是 EVTX 与辅助日志通路共享的**本地解析总预算**，显式指定时也如此。混合输入会拆分预算；`workers=1` 在调用方进程中串行运行两条通路。默认本地最多八个 worker，本地队列也限制待执行任务数。分布式 worker 单独管理，本地参数不构成集群内存上限。

同一协调器或 Notebook 进程中的导入转换由 `CONVERSION_LOCK` 串行执行，解析工作仍可能同时运行。独立进程、后台任务和其他 Notebook 不共享这把锁。

需要后台执行时，以下调用**替代**前台导入：

```python
job_id = c.ingest_background([r"E:\evidence:HOST01"], workers=2, options=options)
c.job_status(job_id)
```

子进程使用内核的 `sys.executable`，并接收上述导入选项。后台执行让 Notebook 可以继续运行其他单元，
不会减少导入本身的工作量、内存或磁盘需求。查看阶段是否为 `done` 或 `failed`，失败时检查
`<case>/jobs/<job_id>.log`。完成后重新打开 Case 再查询，以建立最新视图；其他进程的导入不会
刷新已有查询连接。后台任务不等于可断点恢复的事务。

不要为了切换方式而对同一份证据执行两个示例：重复导入可能产生重复记录。进度回调和脚本入口保护见 [Python API](06_python_api.zh-CN.md)。

## 内存与磁盘边界

- 文本日志和注册表解析器在导入时把完整记录逐条 emit 到暂存。直接调用且省略 `emit` 时，仍保留完整列表及其内存开销。计划任务 XML 仍整文档解析，导入时限制为 8 MiB。注册表使用文件支持的 hive 读取，但 regipy 事务日志恢复和异常巨大的单个值仍是内存例外。
- 辅助文本导入将 SHA-256 和严格 UTF-8 验证合并为一次有界的整文件读取，再执行解析读取。非 UTF-8 来源保留严格的 UTF-16/GB18030/Latin-1 回退顺序，可能需要更多次读取；QCloud 只有 BOM 存在时才尝试 UTF-16。编码验证完成前不会输出记录，复用验证结果时还会核对文件身份、大小和时间戳，但这不等于不可变证据快照。在导入之外直接调用解析器，仍会独立验证编码。
- 物理文本行上限为 8 Mi 字符；逻辑记录和格式限制也适用，包括 QCloud 的 4 Mi 字符或 100,000 行、数据库限制及 CSV 字段大小。超大记录会明确报错，具体边界见[已知限制](../known_limitations.md)。
- `staging_chunk_bytes` 按**未压缩字节数**设置目标：gzip 路径计算编码后的 NDJSON 字节，IPC 路径计算 Arrow 批次缓冲区字节。gzip 在记录之间轮换分片，使用 256 KiB 有界写缓冲。Arrow 按最多 16,384 行及 16 MiB 大小估算限制批次，在批次之间轮换分片，每个活跃 writer 另有 1 MiB 输出缓冲。单条记录可能超过批次或分片目标；编码后大于 32 MiB 的记录会被拒绝。
- 临时路径按批次隔离为 `staging/<batch_id>/<host>/` 和 `staging_aux/<batch_id>/<host>/`。走暂存路径的来源先完成暂存，再分组转换。`flatten_batch_bytes` 是目标，不可拆分的分片可能超过它。文件和分片元数据随其数量增长；即使启用直接转换，其他格式及兼容回退仍可能在转换前积累完整暂存数据。
- gzip 和 Arrow 两种路径都**默认保留暂存**。单独设置 `keep_staging=False` 只会在转换成功后删除本轮分片，不会跳过暂存或消除暂存磁盘峰值。只有显式启用直接转换后，兼容来源才绕过这些分片。磁盘预算应同时覆盖证据、暂存、Parquet 和临时工作文件；压缩比例取决于具体内容。
- EVTX `keep_raw=True` 使用临时 SQLite 索引，不再构造整文件 XML 字典；但仍增加一次 XML 解析、索引读写、更大的输出和临时磁盘需求，不能假定固定的耗时或内存倍数。
- 原先排除大于 2 GiB 非 EVTX 来源文件的限制已经移除；受支持的大文件会进入解析器，单记录和文档限制仍适用。两条通路共享一次扫描并按少量前缀分类，未知文件会被报告，不做整文件哈希或提交解析任务。

DuckDB 读取每组分片并输出分区 Parquet。Arrow 暂存以批次直接交给 DuckDB，省去解析器与转换之间的 NDJSON 序列化和重新解析；Arrow 构造、压缩、读取、类型规范化及 Parquet 写入仍有实际成本。

辅助来源在暂存时还会收集有界分区清单，使 Windows 本地存储可以直接预创建 Hive 目录，不必重读全部暂存行。每个来源最多收集 4,096 个分区、1 MiB 编码后的分区值；单个转换组超过 4,096 个唯一分区时也会回退。旧清单、不支持的值或超过上限时，仍执行 DuckDB `SELECT DISTINCT` 兼容扫描；这些限制只关闭优化，不会拒绝导入。EVTX 保留原有分区发现路径；POSIX 和对象存储不需要 Windows 的目录预创建步骤。

辅助日志转换使用固定 VARCHAR 输入列再进行规范类型转换，不再抽样推断 schema，避免分片边界不同导致日期样式的普通文本被重写。Tomcat 超过 200 条续行时会在输出当前记录之前报错，不输出截断的堆栈；此前完整记录可以按 partial 状态保留。

## 增加并行度之前先测量

对比配置时使用新 Case 和有代表性的证据，保持输入与计时范围一致，同时检查恢复记录的正确性和速度。记录：

- 总耗时、吞吐量，以及扫描、暂存、转换各阶段耗时。
- 协调器与**全部 worker** 的峰值总 RSS，以及系统可用内存。
- 暂存及临时磁盘峰值、最终 Parquet 大小。
- 发现、成功、部分成功、失败文件数，以及恢复和写入记录数。

内存紧张时从 `workers=1` 开始，每次只调一种设置。流式解析下，更多 worker 仍可能增加磁盘争用和总内存。更小的 DuckDB 内存设置可能增加溢写或导致转换失败，应预留临时磁盘并检查具体错误。

当前仍没有自动续跑、跨批次幂等、原子查询快照或即时 flatten 磁盘背压。部分分组转换成功后的失败可能留下不完整的数据湖输出。保留分片有助于排查，但不等于具备恢复和提交协议。

导入后使用过滤查询或 `_chunks` 方法处理大结果。未过滤的 `.query()`、`.web_logs()` 仍会构造整份 DataFrame，导入资源参数不会改变这一点。详见[查询与搜索](03_querying_and_search.zh-CN.md)。

下一步：[9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md)。
