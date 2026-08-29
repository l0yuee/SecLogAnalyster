# seclogx 用户指南

**语言：[English](user_guide.md) | 中文**

本指南面向使用 seclogx 进行取证日志分析与威胁狩猎的分析师：Windows 事件日志、磁盘上的计划任务（Scheduled Task）定义、IIS/nginx/Apache/Tomcat
Web 访问日志，以及 Exchange 日志，提供从安装到日常取证工作流的完整说明。内部设计细节请参阅同目录下的
`architecture.md`、`schema.md`、`sigma_backend.md` 和 `known_limitations.md`（目前为英文）。

## 目录

1. [seclogx 是做什么的](#1-seclogx-是做什么的)
2. [安装](#2-安装)
3. [核心概念](#3-核心概念)
4. [命令行参考](#4-命令行参考)
5. [Python / Notebook API](#5-python--notebook-api)
6. [分析师工作流 / 常用查询](#6-分析师工作流--常用查询)
7. [理解狩猎结果与 ATT&CK 标签](#7-理解狩猎结果与-attck-标签)
8. [扩展检测能力：自定义规则与字段映射](#8-扩展检测能力自定义规则与字段映射)
9. [性能与规模说明](#9-性能与规模说明)
10. [故障排查 / 常见问题](#10-故障排查--常见问题)
11. [已知限制](#11-已知限制)
12. [许可证与规则来源](#12-许可证与规则来源)

---

## 1. seclogx 是做什么的

取证采集获得的 Windows 事件日志（`.evtx`）文件很难直接分析：它是二进制格式，导出后是冗长的 XML，而且写入该日志的数百种提供程序（provider）字段极不统一。为了一次性的案例分析而把这些数据导入 ELK 之类的 SIEM，往往更糟——脆弱的索引映射（mapping）会在你毫无察觉的情况下丢弃你需要的字段。

seclogx 的目标就是让排查的最初几个小时变得高效：

- 指向一个或多个取证采集目录（它们不需要在同一个父目录下，也可以来自不同的主机）。
- 它会**通用地**解析每一个 `.evtx` 通道（channel）——Security、System、Application、Sysmon Operational、PowerShell Operational、WMI-Activity 等等——统一归一化为一张可查询的表。
- 同一次导入过程中，它还会发现并归一化：磁盘上的**计划任务**定义（一种持久化痕迹）、**IIS** W3C
  访问日志、**nginx/Apache/Tomcat** 访问日志，以及 **Exchange** CSV 日志（邮件跟踪日志拥有一等列，其余
  Exchange 日志类型进入一个不丢弃任何数据的兜底表）。每种格式都是根据内容而非文件名判断的，因此被重命名或迁移过的证据文件同样能被正确识别。
- 你得到的是原生 `pandas.DataFrame` 接口（命令行表格/CSV 导出，或在 notebook 中使用的 Python `Case` 对象），并内置基于 Sigma 规则的威胁狩猎能力，自动打上 MITRE
  ATT&CK 标签，覆盖 Windows 事件日志与 Web 访问日志两类数据。
- 每一个解析错误、每一个无法识别的文件、以及每一条不支持的规则都会被明确报告，绝不会被静默丢弃。

seclogx 面向单台工作站上、单个分析师处理的现实案例规模（远低于 100GB）设计——不需要集群，也不依赖外部服务。

## 2. 安装

需要 Python 3.10 及以上版本。

```bash
cd SecLogAnalyster
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

请在本仓库的检出目录内以可编辑模式（editable install）运行 `seclogx`，因为内置的 Sigma 规则集位于仓库根目录下的 `data/sigma_rules/`，程序在运行时会基于此相对路径查找。

验证安装：

```bash
seclogx version
seclogx --help
```

## 3. 核心概念

### 案例工作区（Case workspace）

一切都围绕**案例（case）**展开——它是位于 `./cases/<name>/` 下的一个命名工作区（可用 `--case-root` 覆盖路径），其中包含：

```
cases/<name>/
  case.json                     # 已导入的主机列表、导入运行历史
  staging/<host>/*.ndjson       # 中间解析结果（仅 EVTX，默认保留）
  logs/ingest_<batch_id>.log    # 每次导入的核对报告
  lake/
    events/host=<h>/channel=<c>/*.parquet                       # Windows 事件日志
    web_logs/host=<h>/log_type=<t>/*.parquet                    # IIS/nginx/Apache/Tomcat 访问日志
    web_error_logs/host=<h>/log_type=<t>/*.parquet               # nginx/Apache/Tomcat/IIS HTTPERR 错误日志
    scheduled_tasks/host=<h>/*.parquet                           # 计划任务定义
    exchange_message_tracking/host=<h>/*.parquet                 # Exchange 邮件流转
    exchange_logs/host=<h>/log_type=<t>/*.parquet                # 其他 Exchange CSV 日志
```

你只需创建一次案例（`seclogx case init`），之后可以对它执行任意多次 `ingest`（导入）——来自不同的来源路径、不同的主机，甚至相隔数周也没问题。每次导入都是增量追加，并记录在
`case.json` 中。一次 `ingest` 会在来源路径下一次性发现并导入所有支持的格式——不需要对每种日志类型分别导入。案例只会暴露它实际拥有数据的表；可用
`seclogx sources <case>` / `Case.table_counts()` 查看。

### 归一化事件模式（Normalized event schema）

无论来自哪个通道、哪个 provider，每一条记录都会被归一化为同一组列——完整列表见 `docs/schema.md`。日常查询中最重要的几列：

| 列名 | 含义 |
|---|---|
| `time_created` | 事件时间戳（UTC） |
| `host` | 你在导入时**自己指定**的主机标签 |
| `computer` | 日志本身内嵌的主机名（可能与 `host` 不同） |
| `channel` | 例如 `Security`、`Microsoft-Windows-Sysmon/Operational` |
| `event_id` | Windows 事件 ID |
| `provider_name` | 事件提供程序 |
| `process_id` / `thread_id` | 产生该事件的进程/线程 |
| `user_sid` | 安全上下文 SID |
| `event_data` | provider 特有字段，以 JSON 形式存储（见下文） |
| `source_file` / `source_path` / `file_sha256` | 溯源信息 / 证据链 |

### `event_data` 字段

所有 provider 特有的内容（Sysmon 的 `Image`、`CommandLine`、`ParentImage`；Security 的
`TargetUserName`、`LogonType` 等）都存放在同一个 `event_data` JSON 列中，因为不同 provider、不同事件类型的字段差异极大。使用 DuckDB 的
`->>` 运算符提取某个字段：

```sql
SELECT (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
```

> **只要 `WHERE` 子句中把 `(event_data ->> 'Field')` 与其他条件用
> `AND`/`OR`/`LIKE` 组合在一起，就务必给它加上括号。** 经过实测确认，DuckDB
> 的 `->`/`->>` 运算符在复合表达式中与 `LIKE`/`AND` 的结合优先级并不符合直觉——不加括号的
> `event_data ->> 'Image' LIKE '%foo%' AND ...`
> 可能会被错误解析，并在执行时报出一个令人困惑的类型转换错误
>（`Could not convert string '{...}' to BOOL`），而不是一个清晰的语法错误。像本指南中的每一个示例那样，把提取表达式整体加上括号即可完全避免这个问题。如果查询中只有单独一个
> `event_data ->> 'Field'` 条件、没有和其他 `AND`/`OR` 组合，加不加括号都没问题。

如果你不确定某个信息具体在哪个字段里，可以用 `CaseDB.search()` /
`seclogx query ... event_data::VARCHAR ILIKE '%...%'` 对其做全文检索（见[第 6 节](#6-分析师工作流--常用查询)）。

### 其他表：`web_logs`、`web_error_logs`、`scheduled_tasks`、`exchange_message_tracking`、`exchange_logs`

Windows 事件日志并不是 `ingest` 唯一会归一化的数据。以下每一类数据的形态都与事件日志本质不同，因此各自拥有独立的表，而不是硬塞进
`events` 里——完整列参考见 `docs/schema.md`。其中每一张表也都有对应的 `Case`
访问器，直接返回 `pandas.DataFrame`（`c.web_logs()`、`c.scheduled_tasks()` 等），与
`events` 通过 `summary()`/`hosts()`/`channels()` 获得的一等待遇完全相同——见[第 5
节](#5-python--notebook-api)。

| 表 | 存放内容 | 关键列 |
|---|---|---|
| `web_logs` | **访问日志**：IIS、nginx、Apache、Tomcat 的 HTTP 访问日志，统一存放 | `log_type`、`client_ip`、`method`、`uri_stem`、`uri_query`、`status`、`user_agent`、`referer` |
| `web_error_logs` | **错误/诊断日志**：nginx、Apache、Tomcat 以及 IIS HTTP.sys（HTTPERR）——Web 应用另一大类日志，统一存放 | `log_type`、`severity`、`client_ip`、`message`，以及 IIS HTTPERR 特有的 `method`/`uri`/`status` |
| `scheduled_tasks` | 磁盘上的计划任务定义（`System32\Tasks\**`）——一种持久化痕迹，区别于计划任务的*事件日志*（已在 `events` 中覆盖） | `task_path`、`author`、`enabled`、`hidden`、`actions`（JSON）、`triggers`（JSON） |
| `exchange_message_tracking` | Exchange 邮件流转记录（谁给谁发了什么） | `sender_address`、`recipient_address`、`message_subject`、`event_id`（Exchange 自身的事件标识，**不是** Windows 事件 ID） |
| `exchange_logs` | 其他所有 Exchange CSV 日志类型（HttpProxy、ActiveSync、EWS 等），字段原样保留 | `log_type`、`fields`（JSON，用 `fields ->> 'field-name'` 查询） |

在查询这些表之前，有几点需要了解：

- **格式判定基于文件内容，而非文件名或扩展名**——活跃系统上的计划任务文件根本没有扩展名，取证工具也经常重命名导出的日志。任何不匹配已支持格式的文件都会在导入摘要中被报告为“无法识别”，绝不会被静默跳过。
- **`web_logs` 覆盖访问日志类别，`web_error_logs` 覆盖错误/诊断日志类别**——这是每个
  Web 应用都会产生的两大日志类别。二者被拆成两张独立的表，因为它们在结构上完全不相关（访问日志有请求/响应的形态；错误日志只是严重级别加自由文本）。
- **在 `web_logs` 中，nginx、Apache、Tomcat 之间的区分是尽力而为的标签，并非确切检测**——三者默认使用的
  Common/Combined 日志格式在字节层面完全一致；当没有路径/文件名线索时，`log_type` 会回退为
  `web_access`。IIS 总能被可靠识别（其头部自描述）。
- **在 `web_error_logs` 中，引擎标签才是真正的检测结果**——与访问日志不同，每种引擎的错误日志格式各不相同且互不歧义。只有各引擎的默认/标准格式会被识别（自定义的
  `log_format`/`ErrorLogFormat`，或混入 Tomcat `catalina.out`
  中的原始未结构化标准输出，会导致这些行被报告为解析错误，而不是被错误解析）。
- **Exchange 支持范围以邮件跟踪日志为一等列**；其余十余种 Exchange 日志类型都进入
  `exchange_logs`，所有字段都保存在 `fields` 中，虽未提升为真正的列，但依然完全可查询。
- 常用查询见[第 6 节](#6-分析师工作流--常用查询)，完整的取舍决定见 `docs/known_limitations.md`。

## 4. 命令行参考

所有命令都支持 `--case-root <dir>` 参数（默认 `./cases`）以指向不同位置的案例工作区。执行任意命令加 `--help` 可查看最新、完整的参数列表。

### `seclogx case init <name>`

创建一个新的案例工作区。

```bash
seclogx case init incident42
```

### `seclogx case list`

列出 `--dir`（默认 `./cases`）下的所有案例。

### `seclogx case info <name>`

以 JSON 形式打印案例元数据：目前已导入的主机，以及每次导入运行的历史记录（批次 ID、时间戳、文件/记录数）。

```bash
seclogx case info incident42
```

### `seclogx ingest <case> --source PATH[:HOST] [--source ...]`

在来源路径下一次性发现、分类并归一化所有支持的文件，导入到案例中：`.evtx`、计划任务定义、IIS/nginx/Apache/Tomcat
访问日志，以及 Exchange CSV 日志。这是核心命令。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--source PATH[:HOST]` | 必填，可重复 | 要递归扫描的文件或目录。可选地用 `PATH:HOST` 语法显式指定主机标签；若省略，则使用来源目录本身的名称作为主机标签。 |
| `--workers N` | CPU 核心数 | 并行处理文件的工作进程数。各文件相互独立解析，因此该参数随核心数线性扩展效果明显。 |
| `--keep-raw` | 关闭 | 仅对 `.evtx` 来源生效：同时将每条记录的原始 XML 一并写入数据湖（`raw_xml` 列），适用于需要完整证据保真度的场景。会使被应用文件的导入耗时与内存占用大致翻倍。 |
| `--keep-staging` / `--no-keep-staging` | 保留 | 是否在归一化完成后保留 `staging/` 下的中间 NDJSON 文件（仅 EVTX——其他格式不会先落盘暂存）。保留可以在后续调整时低成本重新处理；删除则节省磁盘空间。 |
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

### `seclogx query <case> "<SQL>"`

对案例中的任意一张表（`events` 或其他日志表）执行任意 SQL，并打印或导出结果。结果会以有界大小的分块方式流式获取，而不是先整体取成一个
DataFrame——无论是控制台预览还是 `--out` 导出，都不需要整个结果先能装进内存，这一点在你针对真实规模的
Web 日志表做查询时尤为重要（见[第 9 节](#9-性能与规模说明)）。

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

### `seclogx summary <case>`

按 `(host, channel, event_id)` 分组统计 `events`（Windows 事件日志）表，每组一行，附带计数与首次/最后一次出现时间——是快速了解案例中事件日志数据实际包含哪些内容的最快方式。

### `seclogx channels <case>`

列出 `events` 表中出现的所有不同通道（用于确认实际采集到了哪些日志来源，例如确认 Sysmon 当时确实在运行）。

### `seclogx sources <case>`

列出案例当前拥有的每张表（`events`、`web_logs`、`web_error_logs`、`scheduled_tasks`、`exchange_message_tracking`、`exchange_logs`，视实际情况而定）及其行数。在针对具体表写查询之前，这是了解案例实际拥有哪些日志类型最快的方式。

```bash
seclogx sources incident42
```

### `seclogx table <case> <name>`

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

### `seclogx tasks <case> [--suspicious]`

列出已导入的 `scheduled_tasks` 计划任务定义。

| 参数 | 含义 |
|---|---|
| `--suspicious` | 只显示内置启发式规则标记出的任务：动作可执行文件位于类似 Temp/AppData/Public
  的路径下、命令类似 LOLBin（powershell/cmd/wscript/cscript/mshta/rundll32/regsvr32）、任务被隐藏，或任务未记录作者。这不是
  Sigma 规则——参见[第 7 节](#7-理解狩猎结果与-attck-标签)。 |
| `--out FILE.csv` | 导出完整结果 |

```bash
seclogx tasks incident42 --suspicious
```

### `seclogx hunt <case>`

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

一次狩猎运行**绝不会静默丢弃任何规则**：日志来源类别不受支持的规则会在“skipped（跳过）”中报告；无法转换为 SQL 或执行失败的规则会在“failed（失败）”中报告，并附带具体原因。详见[第 7 节](#7-理解狩猎结果与-attck-标签)。

### `seclogx rules validate [--rules DIR]`

检查指定目录（默认为内置规则集）中的 Sigma 规则能否成功转换为 DuckDB 查询，但不会针对任何数据实际执行。在你添加了自己的规则或修改字段映射之后非常有用。

```bash
seclogx rules validate --rules ~/my-sigma-rules/
```

### `seclogx timeline <case>`

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

## 5. Python / Notebook API

命令行能做的一切，都有对应的 Python API，且全程返回 `pandas.DataFrame` 对象——可以直接嵌入到你日常使用的 Jupyter notebook 与 pandas 分析流程中。

```python
from seclogx import Case

# 创建或打开一个案例
c = Case.create("incident42")          # 首次创建
c = Case.open("incident42")            # 后续会话中打开

# 导入（语义与命令行一致；接受 "PATH" 或 "PATH:HOST" 字符串）
report = c.ingest(
    ["/mnt/kape_output/WKS01:WKS01", "/mnt/kape_output/DC01:DC01"],
    workers=8,
)
print(report.summary_text())
report.to_dataframe()                  # 每个文件的暂存详情，以 DataFrame 形式返回（EVTX 一侧）
report.aux.to_dataframe()              # 计划任务/IIS/Web/Exchange 一侧的同等信息

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

# 每一类日志都有对应的一等 DataFrame 访问器——与 events 待遇完全相同，
# 无需借助原生 SQL 就能拿到 DataFrame。案例中若还没有该表的数据，
# 会返回一个空 DataFrame，而不是报错。在真实规模的 Web 日志案例上不加过滤地调用这些方法之前，
# 请先看下文的“大表的有界内存访问”。
c.web_logs()                           # 访问日志：IIS/nginx/Apache/Tomcat/Exchange-HttpProxy
c.web_logs(log_type="nginx")           # 只看某一种引擎
c.web_error_logs()                     # 错误日志：nginx/Apache/Tomcat/IIS HTTPERR
c.web_error_logs(log_type="apache")
c.scheduled_tasks()
c.exchange_message_tracking()
c.exchange_logs(log_type="HttpProxy")

# CaseDB 的便捷方法可通过 c.db 访问
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # 对 event_data/provider/computer 做全文检索
c.db.tables                            # list[str]：该案例实际拥有的表
c.db.table("web_error_logs")           # 通用兜底方法：按名称取任意表，返回 DataFrame

# 计划任务排查（启发式规则，非 Sigma——见第 7 节）
c.suspicious_tasks()

# 狩猎
results = c.hunt()                      # 或 c.hunt(rules_dir=Path("..."), min_level="high")
results.matches                         # DataFrame：匹配的事件行 + sigma_rule_id/title/level/attack ids
results.rule_summary                    # DataFrame：每条被评估的规则一行，含匹配计数
results.skipped                         # list[(path, reason)]，日志来源类别不受支持的规则
results.failures                        # list[RuleFailure]，转换/执行失败的规则
results.save("matches.csv")

# 时间线
tl = c.timeline(host="WKS01", event_id=[4624, 4625])
```

### 大表的有界内存访问

上面提到的每一个返回 DataFrame 的访问器——`.query()`、`.table()`、
`.web_logs()`、`.timeline()`，无一例外——都有一个 `_chunks`
同名方法，返回 `Iterator[pd.DataFrame]` 而不是单个 DataFrame。这一点很重要，因为
`.query()`/`.table()`/等方法底层调用的是 DuckDB 的 `.fetchdf()`，会把*整个*结果一次性物化成一个
DataFrame：对于已经过滤/聚合到较小规模的结果没问题，但 Web
访问/错误日志在整个案例范围内很可能达到 TB 级别，远超单个 DataFrame 能舒适容纳的规模——DuckDB
惰性、核外（out-of-core）的*查询执行*本身并不能解决这个问题，因为瓶颈出在最后一步把所有结果一次性拉进一个对象里。`_chunks`
系列方法改用 DuckDB 的分块获取机制，因此内存占用由 `chunksize`（每块的行数，默认
100,000）决定，而不是由结果总量决定。经过实测验证：以分块方式读取 500 万行，峰值内存增加约
190MB，而同样的查询用 `fetchdf()` 则增加约 2.7GB。

```python
from seclogx import Case
c = Case.open("incident42")

# 不要在大表上这样做（会一次性把所有内容物化）：
# df = c.web_logs(log_type="nginx")

# ……而是迭代有界大小的分块：
for chunk in c.web_logs_chunks(log_type="nginx"):
    # chunk 就是一个普通的 pandas.DataFrame，只是不是完整结果
    suspicious = chunk[chunk["status"] >= 400]
    if not suspicious.empty:
        suspicious.to_csv("web_errors.csv", mode="a", header=False, index=False)

# 同样的模式适用于任意原生 SQL、任意表，以及时间线：
for chunk in c.query_chunks("SELECT * FROM web_error_logs WHERE severity IN ('error', 'SEVERE')"):
    ...
for chunk in c.db.table_chunks("exchange_message_tracking"):
    ...
for chunk in c.timeline_chunks(host="WKS01"):
    ...

# 如果默认值不适合你的行宽，可以调整 chunksize（每块的行数）：
for chunk in c.web_logs_chunks(chunksize=20_000):
    ...
```

每一个 `_chunks` 访问器都与其对应的一次性方法拥有相同的签名（同样的过滤条件、同样的
`log_type=`/`host=` 等关键字参数），外加一个 `chunksize`
关键字参数；如果案例中没有该表的数据，会返回一个空的迭代器，而不是报错——与一次性方法在这种情况下返回空
DataFrame 保持一致。

命令行会自动应用这一机制：`seclogx query`/`table`/`tasks`/`timeline`
在 `--out` 时会将分块直接流式写入 CSV，控制台预览也只会拉取足够填满表格的行数（绝不会拉取完整结果）——见[第
4 节](#4-命令行参考)。你不需要任何 `--chunks` 之类的参数；这就是这些命令本来的工作方式。

`Case` 支持上下文管理器协议，便于干净地关闭其 DuckDB 连接：

```python
with Case.open("incident42") as c:
    df = c.summary()
```

## 6. 分析师工作流 / 常用查询

以下是一些具体、可直接复制使用的起点。它们既可以通过
`seclogx query <case> "<SQL>"`，也可以在 Python 中通过 `c.query("<SQL>")` 以完全相同的方式运行。

**发现 LOLBin 滥用（由异常父进程启动的进程）：**

```sql
SELECT time_created, host, computer,
       (event_data ->> 'ParentImage') AS parent, (event_data ->> 'Image') AS image,
       (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND (event_data ->> 'Image') ILIKE '%\rundll32.exe'
ORDER BY time_created
```

**编码后的 PowerShell 命令：**

```sql
SELECT time_created, host, computer, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND ((event_data ->> 'CommandLine') ILIKE '%-enc%' OR (event_data ->> 'CommandLine') ILIKE '%-encodedcommand%')
ORDER BY time_created
```

**跨所有主机按登录类型查看成功登录（排查可疑的 RDP/网络登录）：**

```sql
SELECT time_created, host, computer,
       (event_data ->> 'TargetUserName') AS user,
       (event_data ->> 'LogonType') AS logon_type,
       (event_data ->> 'IpAddress') AS src_ip
FROM events
WHERE channel = 'Security' AND event_id = 4624
ORDER BY time_created
```

**在不确定具体字段的情况下，对所有已导入主机排查某个已知失陷指标（哈希、IP、域名、文件名）：**

```bash
seclogx query incident42 "SELECT * FROM events WHERE event_data::VARCHAR ILIKE '%<indicator>%'"
```

或在 Python 中：`c.db.search("<indicator>")`。

**按主机统计进程创建数量，找出异常主机：**

```sql
SELECT host, count(*) AS n
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
GROUP BY host ORDER BY n DESC
```

**围绕某台主机上的特定进程，构建父子进程链：**

```sql
SELECT time_created, event_id,
       (event_data ->> 'ParentImage') AS parent, (event_data ->> 'Image') AS image,
       (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE host = 'WKS01' AND channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND time_created BETWEEN TIMESTAMP '2026-01-14 02:10:00' AND TIMESTAMP '2026-01-14 02:20:00'
ORDER BY time_created
```

**运行内置 Sigma 狩猎，然后直接在 pandas 中对高危命中结果做进一步排查：**

```python
from seclogx import Case
c = Case.open("incident42")
r = c.hunt(min_level="high")
r.matches[["time_created", "host", "sigma_rule_title", "sigma_attack_ids"]].sort_values("time_created")
```

**一次性排查 IIS/nginx/Apache/Tomcat 的 4xx/5xx 状态码：**

```sql
SELECT host, log_type, time_created, client_ip, method, uri_stem, status
FROM web_logs
WHERE status >= 400
ORDER BY time_created
```

**在 IIS/Web 日志中排查可能的 webshell 活动（对不常见扩展名的请求返回 200，或查询字符串可疑）：**

```sql
SELECT host, log_type, time_created, client_ip, uri_stem, uri_query, status
FROM web_logs
WHERE status = 200
  AND ((uri_stem) ILIKE '%.aspx' OR (uri_stem) ILIKE '%.jsp' OR (uri_stem) ILIKE '%.php')
  AND ((uri_query) ILIKE '%cmd=%' OR (uri_query) ILIKE '%eval%' OR (uri_query) ILIKE '%whoami%')
ORDER BY time_created
```

**一次性汇总所有 Web 应用错误日志中的高严重级别条目（nginx 的 `error`、Apache 的
`error`、Tomcat 的 `SEVERE` 等）：**

```sql
SELECT host, log_type, time_created, severity, message
FROM web_error_logs
WHERE severity IN ('error', 'SEVERE', 'crit', 'alert', 'emerg')
ORDER BY time_created
```

**IIS HTTP.sys（HTTPERR）拒绝的请求——这些请求在到达 IIS 工作进程之前就被
HTTP.sys 本身拒绝（畸形请求、队列上限、应用程序池问题等），它们根本不会出现在
`web_logs` 中，这正是为什么需要单独检查 `web_error_logs`：**

```sql
SELECT host, time_created, client_ip, client_port, method, uri, status, message AS reason
FROM web_error_logs
WHERE log_type = 'iis_httperr'
ORDER BY time_created
```

**Exchange 邮件流转：查找与某个可疑地址相关的所有邮件：**

```sql
SELECT time_created, sender_address, recipient_address, message_subject, recipient_status
FROM exchange_message_tracking
WHERE (sender_address) ILIKE '%<可疑域名或地址>%'
   OR (recipient_address) ILIKE '%<可疑域名或地址>%'
ORDER BY time_created
```

**在不了解具体字段结构的情况下，按内容排查其他任意 Exchange 日志类型（HttpProxy、EWS、ActiveSync 等）：**

```sql
SELECT host, log_type, time_created, fields
FROM exchange_logs
WHERE CAST(fields AS VARCHAR) ILIKE '%<indicator>%'
ORDER BY time_created
```

**计划任务：找出所有作者不明、被隐藏、或调用了 LOLBin 的任务——与 `--suspicious`
使用的是同一套启发式规则：**

```python
from seclogx import Case
c = Case.open("incident42")
c.suspicious_tasks()[["host", "task_path", "author", "hidden", "actions"]]
```

## 7. 理解狩猎结果与 ATT&CK 标签

`seclogx hunt` 会运行所有能够加载并转换成功的 Sigma 规则，并报告三类信息：

- **匹配结果（`results.matches`）**：实际匹配到的事件行，每一行都附带
  `sigma_rule_id`、`sigma_rule_title`、`sigma_level` 以及 `sigma_attack_ids`（以逗号分隔的
  MITRE ATT&CK 技术编号列表，例如 `T1003.001, T1003.002`）。
- **规则汇总（`results.rule_summary`）**：**每条被评估的规则**一行（而非每条匹配一行）——包含标题、级别、作者、匹配计数、ATT&CK 标签、参考链接。某条规则
  `matches == 0` 只是说明它在这个案例的数据中没有触发；对大多数规则而言，大多数时候这都是正常且预期的结果。
- **跳过 / 失败（`results.skipped`、`results.failures`）**：无法加载/路由的规则（日志来源类别不受支持），或无法转换/执行的规则（使用了尚不支持的
  Sigma 特性，或使用了此案例的处理管线尚未映射的字段）。请务必检查这两项是否为空，或确认原因可以接受——如需扩展字段映射，请参见
  `seclogx rules validate` 与 `docs/sigma_backend.md`。

ATT&CK 技术名称/战术信息来自一个内置的小型查询表（`data/attack/techniques.json`），仅覆盖内置规则集用到的技术编号——并非完整的 ATT&CK 框架。未收录的编号仍会以裸露的
`TXXXX` 编号形式显示。

内置规则集（37 条规则，位于 `data/sigma_rules/`）专门针对 **Sysmon** 事件字段（进程创建、网络连接、文件事件、注册表变更、镜像加载、DNS
查询、命名管道、PowerShell 脚本块、进程访问）——只有当 Sysmon 确实在运行且其日志被导入时，这些规则才可能命中。它是一个精选的起点，而非详尽覆盖；如需添加更多规则，请参见[第 8 节](#8-扩展检测能力自定义规则与字段映射)。

`hunt` 同样支持 Sigma 的 `category: webserver` 规则（针对 `web_logs`，即**访问日志**运行），方便你自行提供
IIS/nginx/Apache 的 webshell 或漏洞利用特征规则——v1 默认不内置此类规则。目前没有针对磁盘上计划任务定义、Web
应用**错误日志**（`web_error_logs`）或 Exchange 邮件跟踪日志的 Sigma 日志来源类别，因此这些数据不属于 Sigma
狩猎的范围；请改用 `Case.suspicious_tasks()` / `seclogx tasks --suspicious`
排查计划任务，`web_error_logs` 与 Exchange 数据则使用第 6 节中的原生 SQL 查询。

## 8. 扩展检测能力：自定义规则与字段映射

`--rules` / `rules_dir=` 可以指向任意包含标准 Sigma YAML 规则的目录——不必局限于内置规则集。在正式依赖一套新规则之前，先运行：

```bash
seclogx rules validate --rules /path/to/your/rules
```

它会逐条报告每条规则是否成功转换。规则无法直接转换成功的常见原因：

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

## 9. 性能与规模说明

- 面向单台工作站设计，不提供分布式/集群模式。在此前提下，不同日志类别的现实规模差异很大：EVTX
  案例通常远低于 100GB，而一个案例范围内的 Web 访问/错误日志现实中可以达到 TB 级别。
- 导入并行度（`--workers`）随 CPU 核心数扩展——各文件在独立进程中互不依赖地解析。
- 查询与狩猎都直接通过 DuckDB 针对按 Hive 方式分区的 Parquet 数据湖执行，具备惰性、核外（out-of-core）执行能力与谓词下推：一个限定了主机/通道/时间范围的查询，只会读取实际需要的
  Parquet 行组，而不会把整个数据湖都载入内存。不过，*取回*一个未加过滤的大结果时，默认仍然是单个
  DataFrame（`.query()`/`.table()`/`.web_logs()` 等，底层调用 DuckDB 的
  `fetchdf()`）——对于尚未过滤/聚合到较小规模的表或查询，请改用 `_chunks`
  同名方法（`.query_chunks()`、`.web_logs_chunks()`、`.timeline_chunks()` 等），其内存占用由
  `chunksize` 决定，而非结果总量。完整说明与示例见[第 5 节](#5-python--notebook-api)中的“大表的有界内存访问”；命令行（`query`/`table`/`tasks`/`timeline`）在
  `--out` 导出和控制台预览时都会自动使用这一机制，无需任何额外参数即可获得有界内存的行为。
- `--keep-raw` 会使被应用文件的导入耗时与峰值内存大致翻倍——建议只在需要完整 XML
  保真度的特定证据上选择性使用，而不要对整个大型案例默认开启。
- 计划任务/IIS/Web 访问/Exchange 日志按文件直接解析为 Python 字典（没有中间 NDJSON
  暂存步骤），并且与 EVTX 导入流程不同，**这几类日志的导入目前尚未做到有界内存**：单次导入运行会在整个批次范围内，把某张表的所有已解析行都保存在内存中，之后才一次性写入
  Parquet。以目前实际验证过的规模而言没有问题；但如果单次导入处理的文件多到在一个批次内就达到 TB
  级别，即便之后查询生成的数据湖完全没问题，导入过程本身也可能耗尽内存。这是导入阶段特有的边界，与上面提到的查询侧分块机制是两回事，后者并不能解决这个问题——详见
  `docs/known_limitations.md`。

## 10. 故障排查 / 常见问题

**"case '<name>' has no ingested data yet -- run `ingest` first"**
你创建/打开了一个案例，但尚未成功向其中导入任何数据（或所有来源文件都解析失败了）。运行
`seclogx ingest` 并检查核对报告中的错误信息。

**查询中引用的某一列不存在**
provider 特有的字段存放在 `event_data` 内部，而不是作为顶层列存在——应使用
`event_data ->> 'FieldName'`，而不是直接写 `FieldName`。完整的顶层列列表见
`docs/schema.md`。

**某次狩猎报告了处于“failed”状态的规则**
针对同一规则目录运行 `seclogx rules validate --rules <dir>`，可以看到每条规则具体的转换/字段映射错误，然后参见[第 8 节](#8-扩展检测能力自定义规则与字段映射)。

**某次导入中出现 `partial` 状态的文件**
对于损坏的 `.evtx` 文件，这是预期行为——解析器会在损坏点之前尽可能恢复数据，并准确报告恢复了多少条记录。这不是缺陷；详见
`docs/known_limitations.md`。

**对一个非常大的单一文件执行 `ingest` 时速度较慢**
单个超大 `.evtx` 文件不会被拆分到多个工作进程中处理（并行是按文件粒度的）；当你有很多个文件时，`--workers`
的效果最明显。也请确认是否在不必要的情况下开启了 `--keep-raw`，因为它会使单文件处理成本大致翻倍。

**修复问题后想重新执行导入**
每次导入都是增量追加，重复执行是安全的；如果保留了暂存文件（`--keep-staging`，默认行为），可以直接调用归一化步骤（见
`src/seclogx/ingest/flatten.py`）在不重新解析源 `.evtx` 的情况下重新处理已有的 NDJSON——但对大多数用户来说，直接对相同来源重新执行
`seclogx ingest` 即可。

**某个原本期望被导入的文件出现在“无法识别”列表中**
说明它的内容没有匹配任何已支持格式的检测规则（详见 `docs/known_limitations.md`）。常见原因包括：nginx/Apache
使用了自定义的 `log_format`（不是 Common/Combined 日志格式）、IIS/Exchange 日志头部被截断导致缺少
`#Fields:` 行，或来源路径下确实存在不受支持的文件。查看
`AuxIngestReport.unknown_samples`（或导入摘要中的示例列表）以获取确切路径。

**某条 Web 访问日志的 `log_type` 显示为 `web_access` 而不是 `nginx`/`apache`/`tomcat`**
三者默认使用的 Common/Combined 日志格式在字节层面完全一致；该标签只是一个尽力而为的路径/文件名启发式结果，而非确切检测（详见
`docs/known_limitations.md`）。`web_access` 只是意味着没有找到任何线索——数据本身不受影响。

**`seclogx hunt` 报告某条规则“case has no '&lt;table&gt;' table ingested”**
说明该规则对应的日志来源类别所针对的表（`events` 或 `web_logs`）在这个案例里还没有任何数据，这不是转换错误。用
`seclogx sources <case>` 查看案例实际拥有哪些数据。

**对一张大表（尤其是 `web_logs`）执行查询时内存占用过高或返回很慢**
`c.query()`/`c.table()`/`c.web_logs()` 等方法会把整个结果一次性取成一个
DataFrame。改用对应的 `_chunks` 方法（`c.query_chunks()`、`c.web_logs_chunks()`
等）并迭代处理——见[第 5 节](#5-python--notebook-api)中的“大表的有界内存访问”。如果你使用的是命令行，`--out`/控制台预览已经自动采用了分块方式；如果仍然很慢，请检查你的查询
`WHERE` 子句是否真的具有选择性（一个未加过滤的 `SELECT * FROM web_logs`
无论是否分块，都需要扫描整张表——分块限制的是*内存*，而不是需要扫描的数据量）。

## 11. 已知限制

详情见 `docs/known_limitations.md`（英文）。简要概括：

- 基于 `UserData` 的 provider（部分 RDP/任务计划/Defender 事件）会被存储并支持全文检索，但目前尚未像基于
  `EventData` 的 provider 那样做字段级映射以支持 Sigma 狩猎。
- 极少数记录可能出现 `channel` 为 `NULL` 的情况（属于部分源文件本身的数据质量问题，已做妥善处理，不会导致崩溃）。
- Sigma 日志来源类别会被路由到其对应的 **Sysmon** 等价事件，而非原生 Security
  通道的等价事件（例如进程创建 -> Sysmon 事件 ID 1，而非 Security 4688）。
- 不支持区分大小写的 Sigma 匹配、数值比较修饰符，以及关联规则（correlation rules）。
- 除 Sysmon 外的其他 Sysinternals 工具（Procmon、Autoruns 等）在 v1 中尚未支持导入。
- 非 EVTX 格式的判定基于内容而非绝对保证——不规范的日志头部可能被误判为无法识别（会被报告，绝不会静默丢弃）。
- 不支持旧版二进制格式的计划任务（`.job`，Vista 之前使用），仅支持现代 Task Scheduler 2.0 的 XML 格式。
- 在 `web_logs` 中，仅凭日志行本身无法可靠区分 nginx、Apache、Tomcat（三者的
  Common/Combined 日志格式字节完全一致）；该标签是路径/文件名启发式结果。（在
  `web_error_logs` 中，引擎标签是真正的检测结果——错误日志格式本身就是引擎特有的。）
- `web_error_logs` 只能识别各 Web 应用的默认/标准错误日志格式；自定义格式，或混入
  Tomcat `catalina.out` 中的原始未结构化标准输出，会被报告为解析错误，而不是被错误解析。单条
  Tomcat 记录附带的堆栈跟踪最多保留 200 行续行。
- FREB（IIS 基于 XML 的单请求诊断跟踪）以及 Apache 的 `mod_rewrite`/SSL 请求日志在
  v1 中尚未支持导入——只覆盖标准的访问日志与错误日志两大类别。
- 只有 Exchange 邮件跟踪日志拥有一等列；其他所有 Exchange CSV 日志类型都进入通用的
  `exchange_logs` 兜底表，字段被保留但未提升为真正的列。
- 目前没有针对磁盘上计划任务定义、Web 应用错误日志（`web_error_logs`）或 Exchange
  日志的 Sigma 日志来源类别，因此狩猎功能不覆盖这些表。
- `.query()`/`.table()`/`.web_logs()` 等方法会把完整结果物化成一个 DataFrame；对于尚未过滤/聚合到较小规模的场景，请改用对应的
  `_chunks` 方法（见第 5/9 节）。
- 非 EVTX 日志类别（计划任务/IIS/Web/Exchange）的导入流程尚未做到与 EVTX
  导入以及查询/取回环节同等程度的有界内存：单次导入运行会在整个批次范围内把某张表的所有已解析行都保存在内存中，之后才写入
  Parquet。以目前实际验证过的规模而言没有问题；但如果单次导入的文件多到在一个批次内就达到 TB
  级别，即便之后生成的数据湖能正常查询，导入过程本身也可能耗尽内存。

## 12. 许可证与规则来源

seclogx 自身代码采用 MIT 许可证（见 `LICENSE`）。内置于
`data/sigma_rules/` 下的 Sigma 规则均未经修改地复制自
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)，采用 Detection Rule License 1.1
授权（见 `data/sigma_rules/LICENSE-DRL-1.1.txt`）；每条规则确切的上游来源与提交（commit）记录在
`data/sigma_rules/SOURCES.md` 中，且每一条匹配结果都会展示原始规则的作者信息。
