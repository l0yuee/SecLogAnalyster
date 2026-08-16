# seclogx 用户指南

**语言：[English](user_guide.md) | 中文**

本指南面向使用 seclogx 进行 Windows 事件日志分析与威胁狩猎的分析师，提供从安装到日常取证工作流的完整说明。内部设计细节请参阅同目录下的
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
- 你得到的是原生 `pandas.DataFrame` 接口（命令行表格/CSV 导出，或在 notebook 中使用的 Python `Case` 对象），并内置基于 Sigma 规则的威胁狩猎能力，自动打上 MITRE ATT&CK 标签。
- 每一个解析错误和每一条不支持的规则都会被明确报告，绝不会被静默丢弃。

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
  staging/<host>/*.ndjson       # 中间解析结果（默认保留）
  logs/ingest_<batch_id>.log    # 每次导入的核对报告
  lake/host=<h>/channel=<c>/*.parquet   # 归一化后可查询的数据
```

你只需创建一次案例（`seclogx case init`），之后可以对它执行任意多次 `ingest`（导入）——来自不同的来源路径、不同的主机，甚至相隔数周也没问题。每次导入都是增量追加，并记录在 `case.json` 中。

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

解析并归一化 `.evtx` 文件，导入到案例中。这是核心命令。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--source PATH[:HOST]` | 必填，可重复 | 要递归扫描 `.evtx` 文件的文件或目录。可选地用 `PATH:HOST` 语法显式指定主机标签；若省略，则使用来源目录本身的名称作为主机标签。 |
| `--workers N` | CPU 核心数 | 并行处理文件的工作进程数。各文件相互独立解析，因此该参数随核心数线性扩展效果明显。 |
| `--keep-raw` | 关闭 | 同时将每条记录的原始 XML 一并写入数据湖（`raw_xml` 列），适用于需要完整证据保真度的场景。会使被应用文件的导入耗时与内存占用大致翻倍。 |
| `--keep-staging` / `--no-keep-staging` | 保留 | 是否在归一化完成后保留 `staging/` 下的中间 NDJSON 文件。保留可以在后续调整时低成本重新处理；删除则节省磁盘空间。 |
| `--case-root` | `./cases` | 案例工作区所在位置。 |

如果 `<case>` 尚不存在，`ingest` 会自动创建它。

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

### `seclogx query <case> "<SQL>"`

对案例的 `events` 视图（即整个归一化数据湖）执行任意 SQL，并打印或导出结果。

| 参数 | 含义 |
|---|---|
| `--out FILE.csv` | 将完整结果写入 CSV，而不是打印表格 |
| `--limit N` | 限制返回行数 |

```bash
seclogx query incident42 "
  SELECT time_created, computer, (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
  FROM events
  WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  ORDER BY time_created
" --out process_creations.csv
```

### `seclogx summary <case>`

按 `(host, channel, event_id)` 分组统计，每组一行，附带计数与首次/最后一次出现时间——是快速了解案例中实际包含哪些内容的最快方式。

### `seclogx channels <case>`

列出案例中出现的所有不同通道（用于确认实际采集到了哪些日志来源，例如确认 Sysmon 当时确实在运行）。

### `seclogx hunt <case>`

对案例执行 Sigma 检测规则，报告匹配结果并附带 MITRE ATT&CK 标签。

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

跨主机、按时间排序、可过滤的视图——即经典 DFIR 中的“超级时间线（supertimeline）”，聚焦于你当前真正关心的范围。

| 参数 | 含义 |
|---|---|
| `--start` / `--end` | ISO 时间戳边界 |
| `--host` | 限定单个主机 |
| `--channel` | 限定单个通道 |
| `--event-id` | 限定一个或多个事件 ID（可重复） |
| `--out FILE.csv` | 导出完整时间线 |

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
report.to_dataframe()                  # 每个文件的暂存详情，以 DataFrame 形式返回

# 探索
c.summary()
c.channels()
c.hosts()

# 任意 SQL -> DataFrame
df = c.query("""
    SELECT time_created, computer, (event_data ->> 'Image') AS image
    FROM events
    WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
""")

# CaseDB 的便捷方法可通过 c.db 访问
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # 对 event_data/provider/computer 做全文检索

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

## 8. 扩展检测能力：自定义规则与字段映射

`--rules` / `rules_dir=` 可以指向任意包含标准 Sigma YAML 规则的目录——不必局限于内置规则集。在正式依赖一套新规则之前，先运行：

```bash
seclogx rules validate --rules /path/to/your/rules
```

它会逐条报告每条规则是否成功转换。规则无法直接转换成功的常见原因：

- **使用了 seclogx 尚未映射的 Sigma 字段。** 在
  `src/seclogx/detect/pipeline.py` 的 `FIELD_MAPPING` 中添加对应条目（具体写法参见
  `docs/sigma_backend.md`——字段表达式必须加括号）。
- **针对的日志来源类别（logsource category）尚未被路由。** 在同一文件的
  `LOGSOURCE_ROUTES` 中添加对应条目。
- **使用了尚不支持的 Sigma 特性**（区分大小写的 `|cased` 匹配、数值比较修饰符、关联规则/correlation
  rules）——v1 版本暂不支持，详见 `docs/known_limitations.md`。

修改映射之后，重新运行 `rules validate`，再对一个预期会命中的、含真实数据的案例执行
`hunt`，端到端确认效果。

## 9. 性能与规模说明

- 面向单台工作站上、远低于 100GB 的现实案例规模设计与测试，不提供分布式/集群模式。
- 导入并行度（`--workers`）随 CPU 核心数扩展——各文件在独立进程中互不依赖地解析。
- 查询与狩猎都直接通过 DuckDB 针对按 Hive 方式分区的 Parquet 数据湖执行
  （`lake/host=.../channel=.../*.parquet`），具备惰性、核外（out-of-core）执行能力与谓词下推：一个限定了主机/通道/时间范围的查询，只会读取实际需要的
  Parquet 行组，而不会把整个数据湖都载入内存。
- `--keep-raw` 会使被应用文件的导入耗时与峰值内存大致翻倍——建议只在需要完整 XML
  保真度的特定证据上选择性使用，而不要对整个大型案例默认开启。

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

## 11. 已知限制

详情见 `docs/known_limitations.md`（英文）。简要概括：

- 基于 `UserData` 的 provider（部分 RDP/任务计划/Defender 事件）会被存储并支持全文检索，但目前尚未像基于
  `EventData` 的 provider 那样做字段级映射以支持 Sigma 狩猎。
- 极少数记录可能出现 `channel` 为 `NULL` 的情况（属于部分源文件本身的数据质量问题，已做妥善处理，不会导致崩溃）。
- Sigma 日志来源类别会被路由到其对应的 **Sysmon** 等价事件，而非原生 Security
  通道的等价事件（例如进程创建 -> Sysmon 事件 ID 1，而非 Security 4688）。
- 不支持区分大小写的 Sigma 匹配、数值比较修饰符，以及关联规则（correlation rules）。
- 除 Sysmon 外的其他 Sysinternals 工具（Procmon、Autoruns 等）在 v1 中尚未支持导入。

## 12. 许可证与规则来源

seclogx 自身代码采用 MIT 许可证（见 `LICENSE`）。内置于
`data/sigma_rules/` 下的 Sigma 规则均未经修改地复制自
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)，采用 Detection Rule License 1.1
授权（见 `data/sigma_rules/LICENSE-DRL-1.1.txt`）；每条规则确切的上游来源与提交（commit）记录在
`data/sigma_rules/SOURCES.md` 中，且每一条匹配结果都会展示原始规则的作者信息。
