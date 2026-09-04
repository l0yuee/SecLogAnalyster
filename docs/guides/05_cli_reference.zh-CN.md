# 5. 命令行参考

**语言：[English](05_cli_reference.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | 5. 命令行参考 | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

所有命令都支持 `--case-root <dir>` 参数（默认 `./cases`）以指向不同位置的案例工作区。执行任意命令加 `--help` 可查看最新、完整的参数列表。

## `seclogx case init <name>`

创建一个新的案例工作区。

```bash
seclogx case init incident42
```

## `seclogx case list`

列出 `--dir`（默认 `./cases`）下的所有案例。

## `seclogx case info <name>`

以 JSON 形式打印案例元数据：目前已导入的主机，以及每次导入运行的历史记录（批次 ID、时间戳、文件/记录数）。

```bash
seclogx case info incident42
```

## `seclogx ingest <case> --source PATH[:HOST] [--source ...]`

在来源路径下一次性发现、分类并归一化所有支持的文件，导入到案例中：`.evtx`、计划任务定义、IIS/nginx/Apache/Tomcat
访问日志、Exchange CSV 日志、Linux syslog/`auth.log`、auditd 与 systemd
 journal 导出日志、MySQL/MariaDB/PostgreSQL/MSSQL/Oracle 数据库日志、腾讯云主机安全
客户端日志，以及原始 Windows 注册表配置单元文件。这是核心命令。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--source PATH[:HOST]` | 必填，可重复 | 要递归扫描的文件或目录。可选地用 `PATH:HOST` 语法显式指定主机标签；若省略，则使用来源目录本身的名称作为主机标签。 |
| `--workers N` | 最多 8 | 并行处理文件的工作进程数。受限的默认值用于平衡 CPU 吞吐、进程内存与证据磁盘争用；可根据机器和存储性能显式调整。 |
| `--keep-raw` | 关闭 | 仅对 `.evtx` 来源生效：同时将每条记录的原始 XML 一并写入数据湖（`raw_xml` 列），适用于需要完整证据保真度的场景。会使被应用文件的导入耗时与内存占用大致翻倍。 |
| `--keep-staging` / `--no-keep-staging` | 保留 | 是否在归一化完成后保留中间 NDJSON 文件——EVTX 来源存放在 `staging/` 下，其他所有日志类型存放在 `staging_aux/` 下。保留可以在后续调整时低成本重新处理；删除则节省磁盘空间。 |
| `--case-root` | `./cases` | 案例工作区所在位置。 |

如果 `<case>` 尚不存在，`ingest` 会自动创建它。只要来源路径下至少有一种受支持的非
EVTX 产物（反之亦然），即使没有任何 `.evtx` 文件也不算错误——只有当两条通路都一无所获时，`ingest`
才会报错。

示例：

```bash
# 单一来源，主机标签从目录名自动推断
seclogx ingest incident42 --source /evidence/wks01

# 来自多台主机、互不相关的采集路径，显式指定标签
seclogx ingest incident42 \
  --source /mnt/kape_output/WKS01:WKS01 \
  --source /mnt/kape_output/DC01:DC01 \
  --source /home/analyst/manual_copy/extra_logs:WKS01

# 对一小部分高价值证据保留原始 XML；使用更多工作进程
seclogx ingest incident42 --source /evidence/dc01:DC01 --keep-raw --workers 16
```

每次导入结束后，seclogx 都会打印一份**核对报告（reconciliation report）**：发现的文件数、成功导入数、部分恢复数、失败数，以及暂存记录数与最终写入数据湖的行数是否一致。任何解析不完整的文件都会附带具体错误原因及失败点之前已恢复的记录数——该报告同时也会保存到
`cases/<name>/logs/ingest_<batch_id>.log`。

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

出现 `partial`（部分恢复）状态的文件不需要惊慌——它准确地表示：在某个损坏的数据块导致解析中断之前，已经成功恢复了一定数量的记录。失败点之前的数据不会丢失。

紧接着 EVTX 的核对报告之后，还会打印第二份针对非 EVTX 数据的核对报告，遵循同样“绝不静默丢弃”的原则——完全无法识别的文件会被明确列出，而不是被跳过：

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

## `seclogx query <case> "<SQL>"`

对案例中的任意一张表（`events` 或其他日志表）执行任意 SQL，并打印或导出结果。结果会以有界大小的分块方式流式获取，而不是先整体取成一个
DataFrame——无论是控制台预览还是 `--out` 导出，都不需要整个结果先能装进内存，这一点在你针对真实规模的
Web 日志表做查询时尤为重要（见[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)）。

| 参数 | 含义 |
|---|---|
| `--out FILE.csv` | 将完整结果流式写入 CSV，而不是打印表格 |
| `--limit N` | 限制返回行数——直接下推到查询本身（`LIMIT`），而不是取回结果后再截断，因此对一张巨大的表加限制不会白白多读数据 |

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

列出案例当前拥有的每张表（`events`、`web_logs`、`web_error_logs`、`scheduled_tasks`、`exchange_message_tracking`、`exchange_logs`、`syslog`、`auditd_logs`、`journal_logs`、`db_logs`、`registry`，视实际情况而定）及其行数。在针对具体表写查询之前，这是了解案例实际拥有哪些日志类型最快的方式。

```bash
seclogx sources incident42
```

## `seclogx table <case> <name>`

以 DataFrame 形式返回案例中任意一张表的完整内容——是 `Case.web_logs()`/`Case.scheduled_tasks()`
等方法在命令行侧的对应物，适合那些还没有专属命令的表。与上面的 `query` 一样，采用分块流式获取。

| 参数 | 含义 |
|---|---|
| `--out FILE.csv` | 流式写入完整结果到 CSV |
| `--limit N` | 限制返回行数（下推到查询中） |

```bash
seclogx table incident42 web_error_logs
seclogx table incident42 exchange_message_tracking --out mailflow.csv
```

## `seclogx fields <case> <table>`

我能查询哪些字段？列出这个案例真实、已导入的数据中，某张表实际拥有的每一个字段——见[《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)中的“我能查询哪些字段？”。基于一个有界样本计算，因此无论表有多大都能安全运行。

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

| 参数 | 含义 |
|---|---|
| `--suspicious` | 只显示被内置启发式规则标记的条目 |
| `--hive-type TYPE` | 只看某一类配置单元（`system`/`software`/`sam`/`security`/`default`/`ntuser`/`usrclass`/`amcache`/`bcd`） |
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

下一步：[《6. Python API》](06_python_api.zh-CN.md)，对应的 Python / notebook 接口。
