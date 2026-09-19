# 8. 性能与规模说明

**语言：[English](08_performance_and_scale.md) | 中文**

**[指南索引](../index.zh-CN.md)** · [Python API](06_python_api.zh-CN.md) · [分布式部署](10_distributed_deployment.zh-CN.md)

导入将文本日志和注册表记录逐条写入磁盘，并限制每次 DuckDB 转换的输入量。
实际资源消耗仍取决于格式、单条记录大小、worker 数量和存储条件。本文说明可用参数及其边界，
不承诺固定吞吐或整个进程的内存硬上限。

## 在 Notebook 中自动导入

按[安装指南](01_getting_started.zh-CN.md#安装)一次性准备环境，选择 Jupyter 的
`python314` 内核，然后使用普通 API：

```python
from seclogx import Case

c = Case.create("large_case")
report = c.ingest([r"E:\evidence:HOST01"])
print(report.summary_text())
```

正常安装已包含 Rust 解析器。兼容的本地 UTF-8 Common/Combined 和 IIS W3C 来源自动
使用原生解析、有界 Arrow 批次及直接 Parquet 输出；其他来源自动走兼容路径。
分析员无需挑选加速器或填写一组调优参数。来源哈希、严格编码检查和规范结果结构均保留。

暂存分片**默认在转换成功后删除**，不会删除原始证据。需要保留中间文件以便诊断时，
显式传入 `keep_staging=True`，系统会自动选择暂存路径。这调整了旧版默认保留暂存的行为。

## 自动原生解析

[原生组件](../../native/README.md)随主包一起构建和安装，在释放 GIL 时完成读取、解析
和 Arrow 字符串缓冲构建，不逐行跨越 Python 边界创建字典。批次留在文件 worker 或
直接转换协调器内部，跨进程只传递清单；最终行仍由相同的 DuckDB SQL 规范化。

默认 `parser_backend="auto"` 自动选择兼容的原生解析，不支持的格式、编码或语法使用
Python。运行时无法加载已安装扩展时，兼容处理会记录原因并改用 Python；这与缺少
构建工具导致的源码安装失败不同。EVTX 保持现有解析器。遇到后段能力不兼容时，先删除
该来源全部私有原生输出，再由 Python 整源重放，可能多读一遍。I/O 故障、来源变化和
不符合接口约定的原生批次会报错，不会以切换后端掩盖。

`report.aux.staged_files` 与 `report.aux.to_dataframe()` 中的
`parser_backend` / `backend_reason` 记录辅助来源实际使用的解析器与选择原因。
普通解析错误仍可保留完整的已接受前缀，作为部分恢复结果。

## 自动直接 Parquet 转换

`direct_parquet=None` 表示自动选择。普通默认调用会让符合条件的 Web/IIS 文件跳过
IPC/NDJSON 暂存，由有界原生 Arrow 批次直接进入 DuckDB。适用条件为本地执行、
本地存储且未配置 broker，小文件同样可用。要求保留暂存、远程执行、对象存储或显式
只用 Python 解析时，自动选择暂存路径。前台、后台及 CLI 共享这些默认行为，普通本地
导入无需填写 `--direct-parquet`。

其他辅助来源先在工作池完成暂存，关闭工作池后，协调器逐个处理直接来源。直接转换
与 EVTX、暂存转换共用 `CONVERSION_LOCK`，同一进程同时只有一个导入 DuckDB
转换使用其内存与线程预算。独立进程不共享该锁。

哈希与严格编码准备仍在解析前完成。不兼容原生输入会复用同一准备对象中的来源身份及
编码，完整重放 Python 暂存路径。直接批次沿用固定 VARCHAR 输入、规范化 SQL 和
ZSTD Parquet 输出；`staging_format` 只影响其他来源及兼容回退。

每份直接来源先写入 `lake/` 外的 `<case>/_ingest_private/`，完成转换、关闭与来源
核验后才发布。普通解析错误可将完整的已接受前缀发布为 `partial`；零恢复行则报告
`failed` 且不发布。来源变化、I/O、异常批次及转换错误会失败，不会切换后端。
清单分别记录解析选择，以及 `output_format`（`staged` 或 `parquet`）与 `parquet_paths`。

这是来源级边界，不是整次导入原子事务：后续来源失败时，先前已发布来源仍保留，崩溃
也可能留下私有文件。当前不支持自动恢复、续跑或跨批次去重。Windows 发布拒绝覆盖
已有目标；POSIX 要求私有输出与目标位于同一文件系统并支持硬链接，不支持的发布操作
会失败，不会改为复制或 Python 重放。这些路径不代表所有平台与依赖组合均已验证。

## 高级部署与诊断控制

默认使用最多八个本地解析 worker，每个 DuckDB 转换的受管内存为 2GB、线程数为 2。
**2GB 不是整个进程或 Notebook RSS 的硬上限**；原生/Python 分配、Arrow 缓冲、解析
进程、注册表恢复、查询和独立后台任务仍需额外内存。部署环境有预算约束时才需要调整，
无需把调优作为日常分析步骤。

| `IngestOptions` 设置 | 含义 |
| --- | --- |
| `parser_backend="auto"`（默认） | 兼容时使用原生，否则使用 Python。 |
| `parser_backend="python"` | 强制 Python 兼容解析，同时关闭自动直接输出。 |
| `parser_backend="native"` | 已识别辅助来源不能原生解析时失败，用于兼容输入的诊断。 |
| `direct_parquet=None`（默认） | 根据执行环境选择直接输出或暂存。 |
| `direct_parquet=False` | 强制暂存。 |
| `direct_parquet=True` | 要求本地执行/存储、无 broker、`keep_staging=False`，后端为 `auto` 或 `native`；配置不兼容时报错。 |

在暂存来源中，`staging_format="auto"` 对达到 16 MiB 的文件使用 Arrow IPC/ZSTD
level 1，较小时使用 gzip NDJSON；`"arrow"` / `"ndjson"` 可覆盖选择。
暂存路径原生解析需要 Arrow；严格原生模式处理小文件时也需 `staging_format="arrow"`。
EVTX 暂存仍是 NDJSON，直接转换没有暂存大小门槛。CLI 提供对应高级覆盖项
`--parser-backend`、`--direct-parquet` / `--no-direct-parquet`、`--staging-format`；
省略时保留自动选择。

## Worker 预算与后台导入

`workers` 是 EVTX 与辅助日志通路共享的**本地解析总预算**，显式指定时也如此。混合输入会拆分预算；`workers=1` 在调用方进程中串行运行两条通路。默认本地最多八个 worker，本地队列也限制待执行任务数。分布式 worker 单独管理，本地参数不构成集群内存上限。

同一协调器或 Notebook 进程中的导入转换由 `CONVERSION_LOCK` 串行执行，解析工作仍可能同时运行。独立进程、后台任务和其他 Notebook 不共享这把锁。

需要后台执行时，以下调用**替代**前台导入：

```python
job_id = c.ingest_background([r"E:\evidence:HOST01"])
c.job_status(job_id)
```

子进程使用内核的 `sys.executable`，并接收上述导入选项。后台执行让 Notebook 可以继续运行其他单元，
不会减少导入本身的工作量、内存或磁盘需求。查看阶段是否为 `done` 或 `failed`，失败时检查
`<case>/jobs/<job_id>.log`。完成后重新打开 Case 再查询，以建立最新视图；其他进程的导入不会
刷新已有查询连接。后台任务不等于可断点恢复的事务。

不要为了切换方式而对同一份证据执行两个示例：重复导入可能产生重复记录。进度回调和脚本入口保护见 [Python API](06_python_api.zh-CN.md)。

## 内存与磁盘边界

- Python 兼容路径中的文本日志和注册表解析器把完整记录逐条 emit 到暂存。直接调用解析器且省略 `emit` 时，仍保留完整列表及其内存开销。计划任务 XML 仍整文档解析，导入时限制为 8 MiB。注册表使用文件支持的 hive 读取，但 regipy 事务日志恢复和异常巨大的单个值仍是内存例外。
- 辅助文本导入将 SHA-256 和严格 UTF-8 验证合并为一次有界的整文件读取，再执行解析读取。非 UTF-8 来源保留严格的 UTF-16/GB18030/Latin-1 回退顺序，可能需要更多次读取；QCloud 只有 BOM 存在时才尝试 UTF-16。编码验证完成前不会输出记录，复用验证结果时还会核对文件身份、大小和时间戳，但这不等于不可变证据快照。在导入之外直接调用解析器，仍会独立验证编码。
- 物理文本行上限为 8 Mi 字符；逻辑记录和格式限制也适用，包括 QCloud 的 4 Mi 字符或 100,000 行、数据库限制及 CSV 字段大小。超大记录会明确报错，具体边界见[已知限制](../known_limitations.md)。
- `staging_chunk_bytes` 按**未压缩字节数**设置目标：gzip 路径计算编码后的 NDJSON 字节，IPC 路径计算 Arrow 批次缓冲区字节。gzip 在记录之间轮换分片，使用 256 KiB 有界写缓冲。Arrow 按最多 16,384 行及 16 MiB 大小估算限制批次，在批次之间轮换分片，每个活跃 writer 另有 1 MiB 输出缓冲。单条记录可能超过批次或分片目标；编码后大于 32 MiB 的记录会被拒绝。
- 临时路径按批次隔离为 `staging/<batch_id>/<host>/` 和 `staging_aux/<batch_id>/<host>/`。走暂存路径的来源先完成暂存，再分组转换。`flatten_batch_bytes` 是目标，不可拆分的分片可能超过它。文件和分片元数据随其数量增长；即使启用直接转换，其他格式及兼容回退仍可能在转换前积累完整暂存数据。
- gzip 和 Arrow 暂存均**默认在转换成功后删除**。自动直接输出让兼容本地来源跳过分片；其他来源仍可能在转换前积累完整暂存。`keep_staging=True` 保留中间文件并选择暂存路径，不会删除原始证据。磁盘预算仍需覆盖来源、暂存、Parquet 和临时文件；事后清理不能消除暂存峰值。
- EVTX `keep_raw=True` 使用临时 SQLite 索引，不再构造整文件 XML 字典；但仍增加一次 XML 解析、索引读写、更大的输出和临时磁盘需求，不能假定固定的耗时或内存倍数。
- 原先排除大于 2 GiB 非 EVTX 来源文件的限制已经移除；受支持的大文件会进入解析器，单记录和文档限制仍适用。两条通路共享一次扫描并按少量前缀分类，未知文件会被报告，不做整文件哈希或提交解析任务。

DuckDB 读取每组分片并输出分区 Parquet。Arrow 暂存以批次直接交给 DuckDB，省去解析器与转换之间的 NDJSON 序列化和重新解析；Arrow 构造、压缩、读取、类型规范化及 Parquet 写入仍有实际成本。

辅助来源在暂存时还会收集有界分区清单，使 Windows 本地存储可以直接预创建 Hive 目录，不必重读全部暂存行。每个来源最多收集 4,096 个分区、1 MiB 编码后的分区值；单个转换组超过 4,096 个唯一分区时也会回退。旧清单、不支持的值或超过上限时，仍执行 DuckDB `SELECT DISTINCT` 兼容扫描；这些限制只关闭优化，不会拒绝导入。EVTX 保留原有分区发现路径；POSIX 和对象存储不需要 Windows 的目录预创建步骤。

辅助日志转换使用固定 VARCHAR 输入列再进行规范类型转换，不再抽样推断 schema，避免分片边界不同导致日期样式的普通文本被重写。Tomcat 超过 200 条续行时会在输出当前记录之前报错，不输出截断的堆栈；此前完整记录可以按 partial 状态保留。

## 部署诊断：调整并行度前先测量

对比配置时使用新 Case 和有代表性的证据，保持输入与计时范围一致，同时检查恢复记录的正确性和速度。记录：

- 总耗时、吞吐量，以及扫描、暂存、转换各阶段耗时。
- 协调器与**全部 worker** 的峰值总 RSS，以及系统可用内存。
- 暂存及临时磁盘峰值、最终 Parquet 大小。
- 发现、成功、部分成功、失败文件数，以及恢复和写入记录数。

内存紧张时从 `workers=1` 开始，每次只调一种设置。流式解析下，更多 worker 仍可能增加磁盘争用和总内存。更小的 DuckDB 内存设置可能增加溢写或导致转换失败，应预留临时磁盘并检查具体错误。

当前仍没有自动续跑、跨批次幂等、原子查询快照或即时 flatten 磁盘背压。部分分组转换成功后的失败可能留下不完整的数据湖输出。保留分片有助于排查，但不等于具备恢复和提交协议。

导入后使用过滤查询或 `_chunks` 方法处理大结果。未过滤的 `.query()`、`.web_logs()` 仍会构造整份 DataFrame，导入资源参数不会改变这一点。详见[查询与搜索](03_querying_and_search.zh-CN.md)。

下一步：[9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md)。
