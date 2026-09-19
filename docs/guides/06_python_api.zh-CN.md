# 6. Python / Notebook API

**语言：[English](06_python_api.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | 6. Python API | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

Python API 为 Notebook 和脚本提供 DataFrame、分块迭代器、导入报告与任务状态对象。下面用到的有界内存（`_chunks`）与
`search()` 内存安全机制，完整讲解见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)。

## Notebook 环境

使用本项目独立于 `base` 的 conda `python314` 环境：

```bash
conda activate python314
python -m pip install -e .
python -m jupyterlab
```

这些命令要求该环境中已安装 JupyterLab 和 `ipykernel`。若内核列表没有对应选项，可执行 `python -m ipykernel install --user --name python314 --display-name "Python (python314)"` 注册。选择该内核后，在单元格中运行 `import sys; print(sys.executable)` 确认解释器。非交互脚本使用 `conda run --no-capture-output -n python314 python ...`。后台导入启动当前解释器，因此 Notebook 内核环境也决定后台导入的 Python 环境。

## Notebook 大批量导入的资源设置

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

示例中的 `IngestOptions` 是库的默认值，`workers=2` 则显式设置解析并行度。`workers` 是两条通路共享的本地解析总预算；`workers=1` 在调用方进程中串行执行。`threads` 和 `memory_limit` 作用于单个 DuckDB 转换，同一个 Notebook 进程中的转换会串行运行，独立后台任务则各有预算。这些配置用于导入转换，不作用于之后的分析查询。**2GB 不是内核及工作进程总 RSS 的硬上限**。两个字节参数分别设置未压缩暂存分片和转换分组的目标大小，完整记录及分片不会被切断。

默认 `staging_format="auto"` 按每个受支持的辅助来源文件大小选择：达到 16 MiB 时使用 Arrow IPC / ZSTD level 1，小于 16 MiB 时使用 gzip NDJSON。也可显式设为 `"arrow"` 或 `"ndjson"`。EVTX 暂存仍使用 NDJSON；辅助来源生成的 Parquet 在两种暂存路径下均使用 ZSTD level 1。两条路径都保留固定文本输入列和相同的 SQL 规范化规则。

`parser_backend="python"` 默认保留 Python 兼容路径。显式选择 `"auto"` 时，对兼容的 UTF-8 Common/Combined 和 IIS 日志，在暂存路径使用 Arrow 且已安装独立原生组件时选择原生解析，其他输入回退到 Python。`"native"` 要求每个已识别辅助来源都能使用原生解析，否则失败。暂存路径对小文件强制使用原生解析时还应设置 `staging_format="arrow"`。详见[原生解析选择与回退](08_performance_and_scale.zh-CN.md#可选原生解析器)。后台任务和分布式文件 worker 同样接收此选项；存在 `report.aux` 时，可通过 `report.aux.to_dataframe()` 的 `parser_backend` / `backend_reason` 列查看实际选择。

兼容的原生 Web 访问/IIS 来源可选择本地直接转换。开始一次新导入时，可用以下调用替代上面的暂存示例：

```python
web_case = Case.create("web_direct")
report = web_case.ingest(
    [r"E:\evidence\web:HOST01"],
    keep_staging=False,
    options=IngestOptions(parser_backend="auto", direct_parquet=True),
)
```

`direct_parquet` 默认为 `False`。启用后要求本地存储、未配置 broker、`keep_staging=False`，
且 `parser_backend` 为 `"auto"` 或 `"native"`。小文件也可直接转换，无需强制 Arrow 暂存。
`auto` 模式遇到组件、编码或语法不兼容时，会复用同一来源准备对象，整源回退到 Python；
`staging_format` 控制这些回退及其他来源。普通工作池关闭后，直接来源由协调器逐个处理，
与 EVTX 和暂存转换共享 DuckDB 转换锁。来源哈希和编码预读仍保留。
后台 `ingest_background()` 同样支持这些选项，并须传入 `keep_staging=False`；CLI 对应
`--parser-backend auto --direct-parquet --no-keep-staging`。

辅助报告中的 `output_format` 和 `parquet_paths` 区分直接 Parquet 与暂存输出，
`parser_backend` 和 `backend_reason` 则单独说明解析选择。直接来源的私有 Parquet 在关闭和
来源核验后才发布；普通解析错误可以保留 `partial` 前缀。这不是整次导入事务，也不支持自动续跑。
详见[直接转换边界](08_performance_and_scale.zh-CN.md#可选直接-parquet-转换)。

若工作站有足够空闲内存和 CPU，可选用 `IngestOptions(memory_limit="4GB", threads=8, staging_format="auto")`，并将导入的 `workers` 设为 `8`。库的通用默认值仍为 2GB 和两个转换线程，也不构成进程 RSS 上限；需要给 Notebook、解析进程和其他程序预留内存。

需要后台执行时，将前台调用替换为 `job_id = c.ingest_background([r"E:\evidence:HOST01"], workers=2, options=options)`，然后用 `c.job_status(job_id)` 查看状态。不要对同一份证据先后执行两种导入：当前没有跨批次去重或续跑。默认仍保留暂存，单独设置 `keep_staging=False` 只在转换成功后删除，既不绕过暂存，也不能消除暂存磁盘峰值。解析限制和编码验证 I/O 见[性能与规模](08_performance_and_scale.zh-CN.md)。

走暂存路径的来源先完成暂存再转换；只有显式启用的直接路径会为兼容来源绕过分片。后台执行并不提供提前查询保证，也不保证正在写入的数据湖呈现原子快照。应等状态为 `done`、检查任务日志与逐文件报告后再重新打开 Case。`done` 也可能包含部分恢复、失败或无法识别的来源文件。可捕获异常会标记为 `failed`；强制终止或状态写入失败可能留下过期快照，当前没有独立的存活监督器或自动续跑。状态与标准输出/错误位于 `c.case_dir / "jobs"`；找不到任务时 `job_status()` 返回 `None`。重新打开 Case 可避免后台导入前已创建对象中的缓存视图过期。

CLI 对应参数为 `--staging-format auto`，也接受 `arrow`、`ndjson`，配合 `--background` 同样有效。辅助文本导入会在一次读取中完成 SHA-256 和严格 UTF-8 验证，其他编码保留严格回退读取；有界分区清单完整时，也会省去 Windows 上通常需要的额外分区预扫，旧清单、不支持或超出上限的元数据仍走兼容扫描。

导入完成后，无范围限制的 `c.query()`、`c.web_logs()` 仍会构造完整 DataFrame，可能耗尽 Jupyter 内核内存。应先用 SQL 筛选，或逐批消费 `c.query_chunks()`、`c.web_logs_chunks()`；导入预算不会限制返回的 DataFrame 大小。分块按行数而非字节数限制，应按记录宽度设置 `chunksize`，并在处理后释放每块。

## 常规 API 示例

> **在 `.py` 脚本里调用 `ingest()`？请把它放在 `if __name__ == "__main__":`
> 保护块里。** 导入过程会用 Python 的 `spawn`
> 方式启动工作进程来并行暂存文件，而每个工作进程都会重新 import
> 你的脚本——如果没有这个保护块，每个工作进程都会重新跑一遍导入，而不是各自承担一部分工作，Python
> 随后会直接中止整个进程池。遇到这种情况时，`seclogx` 会抛出
> `UnguardedMainError` 并说明原因。Notebook、交互式解释器以及 `seclogx`
> 命令行都不受影响；`workers=1`（在调用方进程内暂存，不使用进程池）在任何环境下都可用。
>
> ```python
> from seclogx import Case
>
> def main():
>     c = Case.create("incident42")
>     print(c.ingest(["/mnt/kape_output/WKS01:WKS01"]).summary_text())
>
> if __name__ == "__main__":
>     main()
> ```

```python
from seclogx import Case, IngestOptions

# 创建或打开一个案例
c = Case.create("incident42")          # 首次创建
# c = Case.open("incident42")          # 后续会话改用此行

# 导入（语义与命令行一致；接受 "PATH" 或 "PATH:HOST" 字符串）
report = c.ingest(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
    workers=8,
    on_progress=lambda snapshot: print(snapshot["phase"], snapshot.get("files_scanned", 0)),
)
print(report.summary_text())
report.to_dataframe()                  # 每个文件的暂存详情，以 DataFrame 形式返回（EVTX 一侧）
report.aux.to_dataframe()              # 已发现的辅助候选文件及其状态
```

`on_progress` 提供阶段、遍历/分类/暂存计数、文件状态汇总和各表已写入行数。进度事件会节流（约 0.3 秒或 25 个完成文件），这不是固定心跳或逐字节剩余时间估计；大文件处理期间计数可能不变。回调应保持轻量。

也可将上面的前台 `c.ingest(...)` 调用**替换**为以下后台调用，不要对同一份证据依次执行两种导入：

```python
job_id = c.ingest_background(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
    workers=8,
    options=IngestOptions(staging_format="auto"),
)
c.job_status(job_id)                   # dict 快照；任务不存在则返回 None
c.job_status()                         # 最近一次启动的任务
c.list_jobs()                          # list[dict]，按启动时间从新到旧排列
```

以下分析示例假定已选择的导入已经完成。对于可能超过可用内存的结果，请先过滤或改用 `_chunks()` 方法。

```python
c = Case.open("incident42")

# 探索
c.summary()
c.channels()
c.hosts()
c.table_counts()                       # DataFrame：每张表名称 -> 行数，覆盖该案例拥有的所有表

# 任意 SQL -> DataFrame
df = c.query("""
    SELECT time_created, computer, (event_data ->> 'Image') AS image
    FROM events
    WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
""")

# 不确定某张表里到底有什么字段，或者该查哪一个？fields() 会采样案例中的真实数据——
# 每一行是一个字段（真实列，或者样本中 event_data 这类 JSON 兜底字段里的某个 key），
# 附带出现频率和一个真实的示例值。完整讲解与速查表见第 2 节的“我能查询哪些字段？”。
c.fields("events")       # -> Image、CommandLine、TargetUserName 等（来自 event_data）+ 真实列
c.fields("web_logs")     # -> status、uri_stem、client_ip 等（真实列）

# ……或者不写 SQL 做同样的事：针对任意表的纯字段/取值条件。
# eq= 精确匹配，contains= 模糊/子串匹配，regex= 正则匹配；默认不区分大小写；
# 不同条件之间默认按 AND 组合（match="any" 表示 OR）；同一字段的多个取值按 OR 组合。
# 字段名无论是不是"真正的"列都能用——Image/CommandLine 等会自动到
# event_data 里查找。完整讲解见第 3 节。
df = c.search(
    "events",
    contains={"Image": "mimikatz"},
    eq={"channel": "Microsoft-Windows-Sysmon/Operational"},
)
c.search("web_logs", contains={"uri_stem": "admin"}, eq={"status": [401, 403]})
c.search("events", regex={"CommandLine": r".*-enc.*"})

# 如果估算结果太大、装不进内存，search() 会拒绝执行（抛出
# ResultTooLargeError），而不是冒着耗尽内存的风险硬取——见第 3 节
# “内存安全检查”中 search_chunks()/search_to_csv() 这两种替代方案。

# 每一类日志都有对应的一等 DataFrame 访问器——与 events 待遇完全相同，
# 无需借助原生 SQL 就能拿到 DataFrame。案例中若还没有该表的数据，
# 会返回一个空 DataFrame，而不是报错。在真实规模的 Web 日志案例上不加过滤地调用这些方法之前，
# 请先看第 3 节的“大表的有界内存访问”。
c.web_logs()                           # 访问日志：IIS/nginx/Apache/Tomcat/Exchange-HttpProxy
c.web_logs(log_type="nginx")           # 只看某一种引擎
c.web_error_logs()                     # 错误日志：nginx/Apache/Tomcat/IIS HTTPERR
c.web_error_logs(log_type="apache")
c.scheduled_tasks()
c.exchange_message_tracking()
c.exchange_logs(log_type="HttpProxy")
c.syslog()                             # 通用 syslog，含 auth.log/secure 的内容
c.auditd_logs()                        # Linux 审计框架
c.journal_logs()                       # systemd journal 导出
c.db_logs(log_type="mysql_slow")       # MySQL/MariaDB、PostgreSQL、MSSQL、Oracle 日志
c.qcloud_logs(log_type="ydservice")    # 腾讯云主机安全客户端日志
c.registry()                           # Windows 注册表配置单元：SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER/...
c.registry(hive_type="software")
c.suspicious_registry()                # 高熵值 + Run/服务/COM/IFEO 持久化启发式检测

# CaseDB 的便捷方法可通过 c.db 访问
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # 对 event_data/provider/computer 做全文检索
c.db.tables                            # list[str]：该案例实际拥有的表
c.db.table("web_error_logs")           # 通用兜底方法：按名称取任意表，返回 DataFrame

# 计划任务排查（启发式规则，非 Sigma——见第 4 节）
c.suspicious_tasks()

# syslog 之上的登录/账户事件排查（启发式规则，非 Sigma）：SSH 成功/失败、
# sudo 命令、PAM 会话开启/关闭、账户管理
c.auth_events()

# 狩猎
results = c.hunt()                      # 或 c.hunt(rules_dir=Path("..."), min_level="high")
results.matches                         # DataFrame：匹配的事件行 + sigma_rule_id/title/level/attack ids
results.rule_summary                    # DataFrame：每条被评估的规则一行，含匹配计数
results.skipped                         # list[(path, reason)]，日志来源类别不受支持的规则
results.failures                        # list[RuleFailure]，转换/执行失败的规则
results.save("matches.csv")

# 时间线
tl = c.timeline(host="WKS01", event_id=[4624, 4625])

# 干净地关闭 DuckDB 连接
with Case.open("incident42") as c:
    df = c.summary()
```

## 方法一览

| 分类 | 方法 |
|---|---|
| 生命周期 | `Case.create(name, case_root=, cluster_config=)`、`Case.open(name, case_root=, cluster_config=)`、`Case.list_cases(case_root=)`、`c.info()` |
| 导入 | `c.ingest(sources, workers=, keep_raw=, keep_staging=, on_progress=, options=)` -> `IngestReport`；`c.ingest_background(sources, workers=, keep_raw=, keep_staging=, options=)` -> `job_id`；`c.job_status(job_id=)` -> `dict \| None`；`c.list_jobs()` -> `list[dict]` |
| 导入资源 | `IngestOptions(memory_limit="2GB", threads=2, staging_chunk_bytes=64 * 1024 * 1024, flatten_batch_bytes=256 * 1024 * 1024, staging_format="auto", parser_backend="python", direct_parquet=False)` |
| 探索 | `c.summary()`、`c.channels()`、`c.hosts()`、`c.table_counts()` |
| 字段发现 / 免 SQL 搜索 | `c.fields(table, sample_size=)`、`c.search(table, eq=, contains=, regex=, match=, case_sensitive=)`、`c.search_chunks(...)`、`c.search_to_csv(table, path, ...)` |
| 原生 SQL | `c.query(sql)`、`c.query_chunks(sql, chunksize=)`、`c.db.table(name)`、`c.db.table_chunks(name, chunksize=)` |
| 各日志家族的专属访问器 | `c.events()` / `c.events_chunks()`，`c.web_logs(log_type=)` / `_chunks`，`c.web_error_logs(log_type=)` / `_chunks`，`c.scheduled_tasks()` / `_chunks`，`c.exchange_message_tracking()` / `_chunks`，`c.exchange_logs(log_type=)` / `_chunks`，`c.syslog()` / `_chunks`，`c.auditd_logs()` / `_chunks`，`c.journal_logs()` / `_chunks`，`c.db_logs(log_type=)` / `_chunks`，`c.qcloud_logs(log_type=)` / `_chunks`，`c.registry(hive_type=)` / `_chunks` |
| 计划任务排查 | `c.suspicious_tasks()` |
| 登录事件排查（基于 `syslog`） | `c.auth_events()` |
| 注册表排查 | `c.suspicious_registry(entropy_threshold=7.0, min_size=32)` |
| 检测 | `c.hunt(rules_dir=, min_level=)` -> `HuntResults` |
| 时间线 | `c.timeline(start=, end=, host=, channel=, event_id=)` / `c.timeline_chunks(...)` |
| `CaseDB`（`c.db`） | `.tables`、`.table(name)` / `.table_chunks(name)`、`.sql(query)` / `.sql_chunks(query)`、`.by_event_id(ids)`、`.by_host(host)`、`.search(text)`、`.estimate(query)` -> `ResultSizeEstimate` |

## 在 Python 中使用分布式模式

`Case.create()` 与 `Case.open()` 在构造 Case 时从环境变量解析 `ClusterConfig`，也可传入显式的 `cluster_config=`。之后的前台 `ingest()` 与 `hunt()` 使用 Case 保存的配置，两个方法本身均不接受 `cluster_config` 参数。请在创建或打开 Case 前设置[《10. 分布式部署》](10_distributed_deployment.zh-CN.md)所述的 `SECLOGX_BROKER_URL`/`SECLOGX_STORAGE_BACKEND`/`SECLOGX_S3_*` 环境变量，或在这两个工厂方法中传入配置。

`ingest_background()` 会启动新的 CLI 进程，由子进程从继承的环境变量解析集群配置；内存中的显式 `c.cluster_config` 不会序列化给它。因此应在启动后台任务前配置环境变量。本地 `workers` 预算不控制分布式队列的工作进程总数。

下一步：[《7. 常用查询》](07_recipes.zh-CN.md)，用这套 API（以及对应的 `seclogx search` 免 SQL 写法）给出的实际可用的例子。
