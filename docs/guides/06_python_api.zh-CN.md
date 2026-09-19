# 6. Python / Notebook API

**语言：[English](06_python_api.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | 6. Python API | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

Python API 为 Notebook 和脚本提供 DataFrame、分块迭代器、导入报告与任务状态对象。下面用到的有界内存（`_chunks`）与
`search()` 内存安全机制，完整讲解见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)。

## Notebook 环境

先按[安装指南](01_getting_started.zh-CN.md#安装)一次性准备环境；源码安装需要 Rust/Cargo
和对应平台的编译工具。正常安装主包就已包含原生解析器。随后在专用环境启动 Jupyter：

```bash
conda activate python314
python -m jupyterlab
```

选择 **Python (python314)** 内核，并在单元格中检查 `sys.executable`。
安装指南包含 JupyterLab/ipykernel 安装与内核注册。重建或升级包后应重启已有内核。
后台导入沿用所选内核的解释器。

## 在 Notebook 中导入

```python
from seclogx import Case

c = Case.create("large_case")  # 后续会话用 Case.open("large_case")
report = c.ingest([r"E:\evidence:HOST01"])
print(report.summary_text())
```

无需填写性能参数。兼容的本地 UTF-8 Common/Combined 和 IIS 来源自动使用 Rust 解析、
有界 Arrow 批次与直接 Parquet 输出；其他格式及不兼容输入自动使用 Python 兼容解析。
来源哈希、编码检查和规范化 SQL 保持不变。正常安装包含原生扩展；运行时无法加载时，
自动模式会回退并记录原因。

默认设置为 `parser_backend="auto"`、`direct_parquet=None`（自动选择）、
`keep_staging=False`。本地执行、本地存储且无 broker 时，自动启用兼容来源的直接转换。
要求保留暂存或使用分布式/对象存储时，自动改用暂存路径。默认在转换成功后删除暂存分片，
**不会删除原始证据**。仅在诊断需要中间文件时传入 `keep_staging=True`；这是对旧版
“默认保留暂存”行为的调整。

需要保持 Notebook 可操作时，用下面的调用**替代**前台导入：

```python
job_id = c.ingest_background([r"E:\evidence:HOST01"])
c.job_status(job_id)
```

等状态为 `done`、检查日志与逐文件报告后，再重新打开 Case 建立最新查询视图。
`done` 可能仍包含部分恢复、失败或未知来源。可捕获异常会标记为 `failed`，强制终止
则可能留下过期状态。日志和状态快照位于 `c.case_dir / "jobs"`；不存在的任务返回 `None`。
前台与后台是替代用法，不要对同一份证据依次导入，否则可能追加重复记录。
两者均不提供自动续跑、提前查询保证或整次导入的原子可见性。

存在 `report.aux` 时，`report.aux.to_dataframe()` 的 `parser_backend` /
`backend_reason` 说明实际解析器，`output_format` / `parquet_paths` 说明输出形式。
直接来源的私有 Parquet 在关闭及来源核验后发布；普通解析错误可以保留完整前缀并标记
`partial`。其他格式与兼容回退仍先暂存再转换。详见[性能与规模](08_performance_and_scale.zh-CN.md)。

## 高级资源与诊断控制

`IngestOptions` 用于部署预算和故障诊断，不是分析员的必填流程。默认最多使用八个本地
解析 worker，`memory_limit="2GB"`、`threads=2`，暂存目标 64 MiB、转换分组目标
256 MiB。**2GB 不是 Notebook 或进程树 RSS 的硬上限**；解析器、Arrow、原生分配、
其他查询与独立后台任务都需要额外内存。`workers` 由 EVTX 与辅助解析共享；
`workers=1` 在调用进程串行执行。转换线程数是另一项预算。

| 覆盖设置 | 用途 |
| --- | --- |
| `IngestOptions(parser_backend="python")` | 通过 Python 兼容路径排查解析差异，同时关闭自动直接输出。 |
| `IngestOptions(parser_backend="native")` | 要求每个已识别辅助来源均支持原生；含不兼容来源的混合输入会失败。 |
| `IngestOptions(direct_parquet=False)` | 为诊断强制走暂存路径。 |
| `IngestOptions(direct_parquet=True)` | 严格要求执行配置兼容；保留暂存、非本地存储、配置 broker 或纯 Python 后端均报错。`auto` 下单个不兼容输入仍可回退。 |
| `c.ingest(sources, keep_staging=True)` | 保留中间分片并自动走暂存路径，不影响原始来源。 |

`staging_format="auto"` 只影响需要暂存的来源：达到 16 MiB 时采用 Arrow IPC/ZSTD，
较小时采用 gzip NDJSON；`"arrow"` / `"ndjson"` 可强制格式，EVTX 仍为 NDJSON。
暂存路径严格使用原生解析时必须选择 Arrow，小文件也如此；直接输出没有这一小文件门槛。

导入后的无限制 `c.query()`、`c.web_logs()` 仍会构造完整 DataFrame。先过滤或逐批消费
`query_chunks()` / `web_logs_chunks()`；导入预算不限制分析结果大小。

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
from seclogx import Case

# 创建或打开一个案例
c = Case.create("incident42")          # 首次创建
# c = Case.open("incident42")          # 后续会话改用此行

# 导入（语义与命令行一致；接受 "PATH" 或 "PATH:HOST" 字符串）
report = c.ingest(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
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
| 导入资源 | `IngestOptions(memory_limit="2GB", threads=2, staging_chunk_bytes=64 * 1024 * 1024, flatten_batch_bytes=256 * 1024 * 1024, staging_format="auto", parser_backend="auto", direct_parquet=None)` |
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
