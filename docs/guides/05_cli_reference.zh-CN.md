# 5. 命令行参考

**语言：[English](05_cli_reference.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | 5. 命令行参考 | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

在本项目中先执行 `conda activate python314`。案例管理命令 `case init/list/info` 使用 `--dir <root>`；多数导入和分析命令使用 `--case-root <root>`（默认 `./cases`）。`worker`、`cluster`、`rules validate` 等命令不接受案例根目录。执行具体命令加 `--help` 可查看完整参数。下面的多行示例采用 Shell 的 `\` 续行；在 PowerShell 中请合为一行或改用反引号续行。

## `seclogx case init <name>`

在 `--dir`（默认 `./cases`）下创建新的案例工作区。

```bash
seclogx case init incident42
```

## `seclogx case list`

列出 `--dir`（默认 `./cases`）下的所有案例。

## `seclogx case info <name>`

以 JSON 形式打印案例元数据：目前已导入的主机，以及每次导入运行的历史记录（批次 ID、时间戳、文件/记录数）。使用 `--dir` 指定其他案例根目录。

```bash
seclogx case info incident42
```

## `seclogx ingest <case> --source PATH[:HOST] [--source ...]`

在来源路径下一次性发现、分类并归一化所有支持的文件，导入到案例中：`.evtx`、计划任务定义、IIS/nginx/Apache/Tomcat
访问与错误日志、Exchange CSV 日志、Linux syslog/`auth.log`、auditd 与 systemd
 journal 导出日志、MySQL/MariaDB/PostgreSQL/MSSQL/Oracle 数据库日志、腾讯云主机安全
客户端日志，以及原始 Windows 注册表配置单元文件。这是核心命令。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--source PATH[:HOST]` | 必填，可重复 | 要递归扫描的文件或目录。`:HOST` 可显式指定主机标签；省略时使用来源根路径的名称，直接传入文件时就是文件名。含空格路径请加引号。 |
| `--workers N` | 最多 8 | EVTX 与辅助通路共享的本地解析工作进程总预算。`1` 表示在调用方进程中暂存，且两条通路串行运行；文件分类另有有界线程池。 |
| `--keep-raw` | 关闭 | 仅 EVTX：将原始 XML 写入 `raw_xml` 列，会增加 XML 解析和磁盘索引开销，实际成本随记录而异。 |
| `--keep-staging` / `--no-keep-staging` | 删除 | 默认在转换成功后删除临时分片，不删除原始证据。`--keep-staging` 保留中间文件并自动选择暂存路径。清理不能消除暂存峰值，也不提供续跑。 |
| `--memory-limit SIZE` | `2GB` | 单个 DuckDB 转换连接的受管内存预算，不是进程树 RSS 硬上限。 |
| `--duckdb-threads N` | `2` | 单个 DuckDB 转换使用的线程数，与解析工作进程预算独立。 |
| `--staging-chunk-mb N` | `64` | 单个暂存分片未压缩大小的目标值，单位实际为 MiB（1,048,576 字节）；不会拆开完整记录。 |
| `--flatten-batch-mb N` | `256` | 单组转换的未压缩大小目标，单位为 MiB；单个暂存分片不可再拆分。 |
| `--staging-format FORMAT` | `auto` | 辅助暂存格式：`auto` 对 >=16 MiB 的来源使用 Arrow IPC / ZSTD level 1，较小来源使用 gzip NDJSON；`arrow` 或 `ndjson` 可强制指定。EVTX 仍使用 NDJSON。 |
| `--parser-backend BACKEND` | `auto` | 高级诊断覆盖：默认兼容时自动使用原生，否则使用 Python。`python` 强制兼容解析；`native` 要求每个已识别辅助来源均支持原生。EVTX 保持现有解析器。 |
| `--direct-parquet` / `--no-direct-parquet` | 自动 | 日常无需填写：兼容本地 Web/IIS 自动直接输出，其他情况暂存。正向覆盖严格要求不保留暂存、本地执行/存储、无 broker，后端为 `auto` 或 `native`；反向覆盖强制暂存。 |
| `--case-root` | `./cases` | 案例工作区所在位置。 |
| `--background` / `-b` | 关闭 | 将导入过程放到后台进程中执行并立即返回——见下文。 |

如果 `<case>` 尚不存在，`ingest` 会自动创建它。可以单独导入 EVTX 或辅助日志；发现结果为空时抛出 `NoSourcesFoundError`。仅含无法识别的辅助候选文件时，也可能返回导入零行的报告，因此应检查逐文件状态与表行数。

来源目录树只遍历一次，辅助文件的内容前缀分类并行进行。当两条通路都有已识别的任务且 `workers > 1` 时，它们共享预算并发运行；`workers=1` 时串行运行。同一协调进程内的 DuckDB 转换会串行化。辅助 Parquet 在两种暂存格式下均采用 ZSTD level 1。字节目标限制工作分组，并非解析器、Arrow、DuckDB 或整个进程树的内存上限。

默认自动选择本地直接转换时，普通辅助来源先在工作池中完成暂存，随后
直接来源由协调器逐个转换，与 EVTX 和暂存转换共享转换锁。来源哈希和严格编码准备仍然
保留。`auto` 遇到组件、编码或语法不兼容时，会复用同一准备对象，整源回退到 Python 暂存；
严格 `native` 则失败。逐文件 `parser_backend` / `backend_reason` 记录解析选择，
`output_format` / `parquet_paths` 单独表示输出形式。

前台进度展示阶段、遍历/分类/暂存计数及各表写入行数。这些是文件/批次级进度，不是逐字节进度或剩余时间估计；处理大文件时计数可能较久不变。详见[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)。

每次调用都会追加新批次，目前不支持跨批次去重或断点续跑。暂存来源先完成暂存再转换；直接来源的私有 Parquet 在关闭和来源核验后才发布，也可能将完整前缀报告为 `partial`，这不等于整次导入原子提交。崩溃可能留下 `_ingest_private` 文件，当前不支持自动恢复。`--background` 和保留暂存均不保证提前查询或原子快照。应等导入完成并检查报告后再查询 Case。

示例：

```bash
# 单一来源，主机标签从目录名自动推断
seclogx ingest incident42 --source /evidence/wks01

# 来自多台主机、互不相关的采集路径，显式指定标签
seclogx ingest incident42 \
  --source /mnt/kape_output/WKS01:WKS01 \
  --source /mnt/kape_output/DC01:DC01 \
  --source /home/analyst/manual_copy/extra_logs:WKS01

# 对一小部分高价值证据保留原始 XML
seclogx ingest incident42 --source /evidence/dc01:DC01 --keep-raw

# 本地 Web/IIS 自动使用兼容的原生直接输出路径
seclogx ingest web_case --source /evidence/web:WEB01

# 另一种选择：在新 Case 后台导入，使用自动默认设置
seclogx ingest large_case --source /evidence/full_kape_output --background
seclogx ingest-status large_case --watch
```

前台导入正常结束后，seclogx 会打印**核对报告（reconciliation report）**：发现的文件数、成功导入数、部分恢复数、失败数，以及暂存记录数与写入数据湖的行数。解析不完整的文件会附带错误原因和恢复计数。EVTX 报告同时保存到 `cases/<name>/logs/ingest_<batch_id>.log`；后台任务会把两份报告都写入 `cases/<name>/jobs/<job_id>.log`。

```
Ingest batch 66777433-... for case 'incident42'
  files discovered : 27
  files ok         : 25
  files partial    : 2  <-- some records lost mid-file, see per-file errors
  files failed     : 0
  records staged   : 101865
  records in lake  : 101865
  files with issues:
     /evidence/.../sysmon.evtx -- Failed to parse chunk header (358 recovered)
```

`partial`（部分恢复）表示该文件有恢复出的记录，也有解析错误。部分解析器会越过损坏记录继续处理，其他错误则会中止文件解析；应检查具体错误和恢复计数，不能将它当成完整导入。

紧接着 EVTX 报告之后会打印辅助来源报告，包括无法分类的候选文件。已知无关后缀、空的辅助文件和不可访问路径可能在发现阶段被排除，不会全部计入 `files unrecognized`：

```
Auxiliary log ingest (Scheduled Tasks / IIS / web access & error logs / Exchange):
  files discovered : 7
  files ok         : 6
  files partial    : 0
  files failed     : 0
  files unrecognized: 1  <-- content didn't match any supported format, not ingested
  rows written per table:
    exchange_message_tracking: 1
    scheduled_tasks: 1
    web_error_logs: 2
    web_logs: 4
  sample unrecognized files:
    /evidence/wks01/notes.txt
```

与 EVTX 一侧的 `IngestReport.to_dataframe()` 相对应，`IngestReport.aux.to_dataframe()`（或直接使用
`run_aux_ingest` 返回的 `AuxIngestReport`）同样能得到一份按文件维度的 DataFrame——每个被发现的文件一行，包含其状态、目标表、记录数/错误数。

## `seclogx ingest-status <case> [job_id] [--watch]`

查看一个 `seclogx ingest --background` 任务的状态：当前阶段（`scanning`/`staging`/`flattening`/`done`/`failed`）、目前已扫描的文件数、发现/暂存计数（成功/部分/失败/不支持），以及目前已写入各表的行数。读取的是
`cases/<name>/jobs/<job_id>.json`——后台任务在运行过程中持续更新的一份小体积
JSON 快照（见[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)）。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `job_id` | 最近一次任务 | 要查看哪个任务；省略则显示最近启动的那一个。 |
| `--watch` | 关闭 | 每秒轮询一次，状态发生变化时重新打印，直到任务进入 `done` 或 `failed`。 |
| `--case-root` | `./cases` | 案例工作区所在位置。 |

```bash
seclogx ingest-status incident42
seclogx ingest-status incident42 3b594cbe-f419-40d7-b598-31780bbe6c6f --watch
```

后台导入使用调用方的 Python 解释器，立即返回任务 ID。可捕获异常会记录为 `failed`，详情见 `cases/<name>/jobs/<job_id>.log`。强制终止进程、系统崩溃或状态写入失败可能留下过期快照：当前没有独立的进程存活监督器，`--watch` 可能持续等待。`done` 仅表示任务结束，不表示所有文件都无错误。当前没有取消/续跑命令。任务完成后，已有的 Python `Case` 对象应重新打开，以更新缓存视图。

## `seclogx query <case> "<SQL>"`

对案例中的任意一张表（`events` 或其他日志表）执行任意 SQL，并打印或导出结果。结果会以有界大小的分块方式流式获取，而不是先整体取成一个
DataFrame——无论是控制台预览还是 `--out` 导出，都不需要整个结果先能装进内存，这一点在你针对真实规模的
Web 日志表做查询时尤为重要（见[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)）。

| 参数 | 含义 |
|---|---|
| `--out FILE.csv` | 将完整结果流式写入 CSV，而不是打印表格 |
| `--limit N` | 取回结果前在 SQL 中应用 `LIMIT`，限制返回行数；查询仍可能需要大量扫描、聚合或排序。 |

```bash
seclogx query incident42 "
  SELECT time_created, computer, (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
  FROM events
  WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  ORDER BY time_created
" --out process_creations.csv

# 导出所有 4xx/5xx 的 Web 访问日志命中记录，无论这张表有多大——
# 都不会先整体装入内存
seclogx query incident42 "SELECT * FROM web_logs WHERE status >= 400" --out web_errors.csv
```

## `seclogx summary <case>`

按 `(host, channel, event_id)` 分组统计 `events`（Windows 事件日志）表，每组一行，附带计数与首次/最后一次出现时间——是快速了解案例中事件日志数据实际包含哪些内容的最快方式。

## `seclogx channels <case>`

列出 `events` 表中出现的所有不同通道（用于确认实际采集到了哪些日志来源，例如确认 Sysmon 当时确实在运行）。

## `seclogx sources <case>`

列出案例当前拥有的每张表（`events`、`web_logs`、`web_error_logs`、`scheduled_tasks`、`exchange_message_tracking`、`exchange_logs`、`syslog`、`auditd_logs`、`journal_logs`、`db_logs`、`qcloud_logs`、`registry`，视实际情况而定）及其行数。在针对具体表写查询之前，这是了解案例实际拥有哪些日志类型最快的方式。

```bash
seclogx sources incident42
```

## `seclogx table <case> <name>`

预览任意表，或通过 `--out` 将行流式导出为 CSV，适用于没有专属命令的表。它与 `query` 一样分块取回结果，不会先构造 `Case.web_logs()` 返回的完整 DataFrame。

| 参数 | 含义 |
|---|---|
| `--out FILE.csv` | 流式写入完整结果到 CSV |
| `--limit N` | 限制返回行数（下推到查询中） |

```bash
seclogx table incident42 web_error_logs
seclogx table incident42 exchange_message_tracking --out mailflow.csv
```

## `seclogx fields <case> <table>`

我能查询哪些字段？列出表的列及有界样本中发现的 JSON 键，见[《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)中的“我能查询哪些字段？”。低频 JSON 键可能未出现在样本中，特别宽的采样行仍可能占用较多内存。

| 参数 | 含义 |
|---|---|
| `--sample-size N` | 采样的行数（默认 5000） |

```bash
seclogx fields incident42 events
seclogx fields incident42 web_logs --sample-size 20000
```

## `seclogx search <case> <table>`

不写 SQL 也能查询任意一张表——条件和匹配方式的完整讲解见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)。命令执行前总会先展示估算的行数/大小；`--out`
无论结果多大都会流式导出全部匹配行，控制台预览则始终只拉取有界数量的行。

| 参数 | 含义 |
|---|---|
| `--eq FIELD=VALUE` | 精确匹配。多个取值用逗号分隔表示 OR（`status=404,500`）。可重复。 |
| `--contains FIELD=VALUE` | 模糊/子串匹配。逗号分隔表示 OR。可重复。 |
| `--regex FIELD=PATTERN` | 正则匹配（不按逗号拆分——每个参数就是一个完整模式）。可重复。 |
| `--match-any` | 所有条件按 OR 组合，而不是默认的 AND |
| `--case-sensitive` | 区分大小写匹配（默认不区分大小写） |
| `--out FILE.csv` | 将所有匹配行流式写入 CSV，而不是打印预览 |
| `--limit N` | 限制返回行数（下推到查询中） |

```bash
# 疑似 webshell：不常见的扩展名、状态码 200
seclogx search incident42 web_logs --contains uri_stem=.aspx --eq status=200

# 编码后的 PowerShell，默认不区分大小写
seclogx search incident42 events --regex CommandLine=".*-enc.*"

# 持久化排查：被隐藏的任务，或者调用了 LOLBin 的任务
seclogx search incident42 scheduled_tasks --eq hidden=true --match-any --contains actions=powershell

# 无论有多少行，把所有匹配结果都导出到 CSV
seclogx search incident42 web_error_logs --eq severity=error,SEVERE --out errors.csv
```

## `seclogx tasks <case> [--suspicious]`

列出已导入的 `scheduled_tasks` 计划任务定义。

普通列表与导出按块读取；`--suspicious` 会先构造整个计划任务表的 DataFrame 做启发式分析。

| 参数 | 含义 |
|---|---|
| `--suspicious` | 只显示内置启发式规则标记出的任务（动作可执行文件位于 Temp/AppData/Public 之下、命令类似 LOLBin、任务被隐藏、未记录作者，或伪装成已知的微软计划任务——完整列表以及说明每行具体匹配原因的 `suspicion_reasons` 列，见[《2. 日志类型与 Schema》](02_log_types_and_schema.zh-CN.md)中的“其他表”一节）。这不是 Sigma 规则——参见[《4. 威胁狩猎》](04_threat_hunting.zh-CN.md)。 |
| `--out FILE.csv` | 导出完整结果 |

```bash
seclogx tasks incident42 --suspicious
```

## `seclogx auth <case>`

列出 `syslog` 中被识别为 SSH/sudo/PAM/账户管理事件的行（具体识别哪些内容见
`Case.auth_events()` / [《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)）。这不是
Sigma 规则——是对已导入 `syslog` 数据的启发式筛选，相当于
`auth.log`/`secure` 版本的 `tasks --suspicious`。

当前该命令会将 syslog 数据整体读入 pandas 做启发式分析，`--out` 不会使此路径变成流式处理。对于大 syslog 表，应使用带过滤条件的 `query`/`search` 导出或 Python 分块分析。

| 参数 | 含义 |
|---|---|
| `--out FILE.csv` | 导出完整结果 |

```bash
seclogx auth incident42
seclogx auth incident42 --out auth_events.csv
```

## `seclogx registry <case> [--suspicious] [--hive-type TYPE]`

列出已导入的注册表键/值（来自 `registry`）。加上 `--suspicious`
则改为运行 `Case.suspicious_registry()`——内置的持久化/熵值启发式检测（具体覆盖哪些内容见[《2.
日志类型与模式》](02_log_types_and_schema.zh-CN.md)），与 `tasks --suspicious`/`auth`
一样，是"启发式筛选，不是 Sigma"。

普通列表与导出按块读取；可疑项结果目前会先整体构造为 DataFrame，再预览或导出。

| 参数 | 含义 |
|---|---|
| `--suspicious` | 只显示被内置启发式规则标记的条目 |
| `--hive-type TYPE` | 普通列表只看某一类配置单元（`system`/`software`/`sam`/`security`/`default`/`ntuser`/`usrclass`/`amcache`/`bcd`）；当前与 `--suspicious` 同用时会被忽略。 |
| `--out FILE.csv` | 导出完整结果 |

```bash
seclogx registry incident42 --hive-type software
seclogx registry incident42 --suspicious
seclogx registry incident42 --suspicious --out suspicious_registry.csv
```

## `seclogx hunt <case>`

对案例执行 Sigma 检测规则，报告匹配结果并附带 MITRE ATT&CK 标签。`logsource.category` 为
`process_creation`、`network_connection` 等的规则针对 `events` 运行；`category: webserver`
的规则则针对 `web_logs` 运行。如果某条规则的目标表在该案例中还没有数据，会被报告为失败（“case has no
'&lt;table&gt;' table ingested”），而不是被静默跳过。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--rules DIR` | 内置精选规则集 | 使用指定目录下的 Sigma `.yml` 规则，替代（如果你自己合并目录，也可以是补充）内置规则集。 |
| `--min-level LEVEL` | 无 | 仅运行不低于该严重级别的规则：`informational`、`low`、`medium`、`high`、`critical`。 |
| `--out FILE.csv` | 无 | 将所有匹配到的事件行写入 CSV。 |

```bash
seclogx hunt incident42
seclogx hunt incident42 --min-level high --out high_severity_matches.csv
seclogx hunt incident42 --rules ~/my-sigma-rules/
```

输出示例：

```
Hunt: 37 rules evaluated, 1 total matches
  rules skipped (unsupported logsource): 0
  rules failed (conversion/execution error): 0
  rules with matches:
    [high] HackTool - Mimikatz Execution -- 1 matches (ATT&CK: T1003.001, T1003.002, ...)
```

一次狩猎运行**绝不会静默丢弃任何规则**：日志来源类别不受支持的规则会在“skipped（跳过）”中报告；无法转换为 SQL 或执行失败的规则会在“failed（失败）”中报告，并附带具体原因。详见[《4. 威胁狩猎》](04_threat_hunting.zh-CN.md)。

## `seclogx rules validate [--rules DIR]`

检查指定目录（默认为内置规则集）中的 Sigma 规则能否成功转换为 DuckDB 查询，但不会针对任何数据实际执行。在你添加了自己的规则或修改字段映射之后非常有用。

```bash
seclogx rules validate --rules ~/my-sigma-rules/
```

## `seclogx timeline <case>`

跨主机、按时间排序、可过滤的视图——即经典 DFIR 中的“超级时间线（supertimeline）”，聚焦于你当前真正关心的范围。与上面的
`query` 一样采用分块流式获取——一个大案例上未加过滤或过滤条件很宽松的时间线，其体量仍可能远超舒适装入内存的程度。

| 参数 | 含义 |
|---|---|
| `--start` / `--end` | ISO 时间戳边界 |
| `--host` | 限定单个主机 |
| `--channel` | 限定单个通道 |
| `--event-id` | 限定一个或多个事件 ID（可重复） |
| `--out FILE.csv` | 流式写入完整时间线到 CSV |

```bash
# 导出某台主机上所有 4624（成功登录）事件
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv

# 特定时间窗口内所有主机的事件
seclogx timeline incident42 --start 2026-01-14T00:00:00 --end 2026-01-14T06:00:00
```

## `seclogx worker`

运行一个分布式模式的 worker：消费由 `seclogx ingest`/`seclogx hunt`
放入队列的导入/狩猎任务（前提是设置了 `SECLOGX_BROKER_URL`）。完整的环境变量参考以及
Docker Compose/Kubernetes 操作步骤见[《10.
分布式部署》](10_distributed_deployment.zh-CN.md)——这是可选启用的功能，除非你配置了集群模式，否则不会有任何影响。

| 选项 | 默认值 | 含义 |
|---|---|---|
| `--burst` | 关闭 | 只处理当前队列中已有的任务，然后立即退出，而不是无限期监听——适合测试/CI 场景。 |

```bash
export SECLOGX_BROKER_URL=redis://broker:6379/0
seclogx worker
```

如果没有设置 `SECLOGX_BROKER_URL`，会立即报错退出——没有配置 broker 就没有可供消费的任务。

## `seclogx cluster config`

以 JSON 格式打印从环境变量（`SECLOGX_STORAGE_BACKEND`/`SECLOGX_S3_*`/`SECLOGX_BROKER_URL`）解析出的分布式模式配置。绝不会打印任何凭据——凭据本来就不会进入这份配置（见[《10.
分布式部署》](10_distributed_deployment.zh-CN.md)）。

```bash
seclogx cluster config
```

## `seclogx cluster status`

报告当前在线的 `seclogx worker` 进程数量以及所配置 broker
上各队列的排队情况。如果没有设置 `SECLOGX_BROKER_URL`，会明确说明这一点并正常退出——此时导入/狩猎都在本地运行，并非分布式，因此没有集群可供报告。

```bash
seclogx cluster status
```

## `seclogx version`

打印已安装的包版本。`seclogx --help` 可查看命令列表。

下一步：[《6. Python API》](06_python_api.zh-CN.md)，对应的 Python / notebook 接口。
