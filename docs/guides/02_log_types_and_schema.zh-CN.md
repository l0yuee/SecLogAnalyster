# 2. 日志类型与模式

**语言：[English](02_log_types_and_schema.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | 2. 日志类型与模式 | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md)

---

本指南回答的问题是：seclogx 归一化的六大日志家族里，每张表分别存放什么，以及应该先看什么。逐列的精确参考（类型、可空性、分区键）见
`docs/schema.md`；每种格式具体是怎么导入的见 `docs/architecture.md`。

## 归一化事件模式（Normalized event schema）

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

## `event_data` 字段

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
`seclogx query ... event_data::VARCHAR ILIKE '%...%'` 对其做全文检索（见[《7. 常用查询》](07_recipes.zh-CN.md)），或继续往下看
`seclogx fields`——它能直接从你的数据里列出真实字段名。

## 其他表：`web_logs`、`web_error_logs`、`scheduled_tasks`、`exchange_message_tracking`、`exchange_logs`

Windows 事件日志并不是 `ingest` 唯一会归一化的数据。以下每一类数据的形态都与事件日志本质不同，因此各自拥有独立的表，而不是硬塞进
`events` 里——完整列参考见 `docs/schema.md`。其中每一张表也都有对应的 `Case`
访问器，直接返回 `pandas.DataFrame`（`c.web_logs()`、`c.scheduled_tasks()` 等），与
`events` 通过 `summary()`/`hosts()`/`channels()` 获得的一等待遇完全相同——见[《6. Python API》](06_python_api.zh-CN.md)。

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
- 常用查询见[《7. 常用查询》](07_recipes.zh-CN.md)，完整的取舍决定见 `docs/known_limitations.md`。

## 速查表：如何分析每一类日志

无论下表中的表是否拥有专属接口，都始终可以用完全通用的方式访问：命令行的
`seclogx query <case> "<SQL>"` / `seclogx table <case> <name>`，以及 Python 中的
`Case.query()`/`Case.db.table(name)`（连同它们的 `_chunks`
同名方法）——如果你完全不想写 SQL，还可以用 `seclogx search <case> <table>` /
`Case.search()`（纯字段/取值条件：精确匹配、模糊匹配或正则匹配——见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)）。下表列出的是每张表在此基础之上*额外*拥有的专属接口。

| 日志类型 | 表 | 专属命令行 | 专属 Python（一次性 / 分块） | Sigma 狩猎 |
|---|---|---|---|---|
| Windows 事件日志 | `events` | `summary`、`channels`、`timeline`、`hunt` | `summary()`/`channels()`/`hosts()`，`events()` / `events_chunks()`，`timeline()` / `timeline_chunks()` | 支持——大多数内置规则类别 |
| Web 访问日志（IIS/nginx/Apache/Tomcat/Exchange-HttpProxy） | `web_logs` | 无——用 `table web_logs` / `query` | `web_logs(log_type=)` / `web_logs_chunks(log_type=)` | 支持——`category: webserver`（需自备规则，v1 默认不内置） |
| Web 错误日志（nginx/Apache/Tomcat/IIS HTTPERR） | `web_error_logs` | 无——用 `table web_error_logs` / `query` | `web_error_logs(log_type=)` / `web_error_logs_chunks(log_type=)` | 不支持——直接查询 |
| 计划任务 | `scheduled_tasks` | `tasks [--suspicious]` | `scheduled_tasks()` / `scheduled_tasks_chunks()`，`suspicious_tasks()`（启发式规则） | 不支持——用 `suspicious_tasks()` 或直接查询 |
| Exchange 邮件跟踪（邮件流转） | `exchange_message_tracking` | 无——用 `table exchange_message_tracking` / `query` | `exchange_message_tracking()` / `exchange_message_tracking_chunks()` | 不支持——直接查询 |
| 其他 Exchange 日志（HttpProxy、EWS、EAS 等） | `exchange_logs` | 无——用 `table exchange_logs` / `query` | `exchange_logs(log_type=)` / `exchange_logs_chunks(log_type=)` | 不支持——直接查询 |

`seclogx sources <case>`并不针对某一张具体的表——它是在使用上述任何一种接口之前，最值得先运行的一个命令：给出每张表的行数统计，让你在决定具体查哪张表之前，先了解案例里实际有什么。

每一类日志具体该看什么（完整常用查询见[《7. 常用查询》](07_recipes.zh-CN.md)）：

- **`events`**——日常 DFIR 的核心：进程创建（父子进程链、LOLBin）、按类型划分的登录活动、PowerShell
  脚本块、注册表/文件变更。先用 `summary()`/`channels()`
  看看实际采集到了什么（Sysmon 当时是否在运行？），再用 `hunt()` 做第一轮排查。
- **`web_logs`**——异常状态码、不常见扩展名却返回 200（可能是 webshell）、可疑的
  User-Agent、某个客户端 IP 占据了绝大多数流量。
- **`web_error_logs`**——与 `web_logs` 中同一时间点的异常相互印证的错误高峰；IIS
  HTTPERR 专门捕获 HTTP.sys 自身在请求到达 IIS 工作进程*之前*就拒绝的请求，因此能发现完全不会出现在
  `web_logs` 中的利用尝试。
- **`scheduled_tasks`**——持久化排查：被隐藏或没有作者信息的任务、动作中调用了
  LOLBin、动作路径位于 Temp/AppData/Public 之下。`suspicious_tasks()` 会自动帮你跑这套启发式规则。
- **`exchange_message_tracking`**——钓鱼与邮件类数据泄露：按发件人/收件人/主题排查、异常的对外邮件流转、发件人域名与其声称身份不符的情况。
- **`exchange_logs`**——Exchange 基于 HTTP 的入侵（例如 ProxyShell 类攻击），此时相关活动体现在
  HttpProxy/OWA/ECP 的访问模式中，而不是邮件流转记录里——在不清楚具体字段结构时，可按内容对
  `fields` 做全文排查。

## 我能查询哪些字段？

写任何搜索之前，有两个问题要先弄清楚：*这张表到底有哪些字段*，以及*要找到我想要的结果，该查哪一个字段*。`seclogx
fields <case> <table>` / `Case.fields()` 直接从这个案例真实的、已导入的数据中回答第一个问题（不是一份静态列表——`web_logs`
的字段有哪些，取决于这个站点的 IIS 管理员选择记录了什么；`event_data`
里有哪些 key 则完全由 provider 决定，因此不存在一份对所有案例都准确的固定列表）：

```bash
seclogx fields incident42 events
```
```
                    Fields in events (sampled)
  field          where              seen_in_sample  example
  channel        column             102451          Microsoft-Windows-Sysmon/Operational
  event_id       column             102451          1
  host           column             102451          WKS01
  ...
  Image          inside event_data  41200           C:\Windows\System32\cmd.exe
  CommandLine    inside event_data  41200           cmd.exe /c whoami
  TargetUserName inside event_data  8310            alice
  ...
```

每一行都是一个可以传给 `eq=`/`contains=`/`regex=` 的字段名，同时给出它来自哪里（真正的列，还是
`event_data` 这类 JSON 兜底字段里的某个 key）、在采样中出现了多少次，以及一个真实的示例值——这样你在针对它写条件之前，就能先看清数据的实际形态（`CommandLine`
是不是带引号？`status` 是字符串还是数字？）。这是基于一个有界样本计算的（`--sample-size`，默认
5000 行），绝不是全表扫描，因此无论表有多大都能安全运行；代价是一个真正罕见的字段，如果在少于大约
1/`sample-size` 的行中才出现，偶尔可能会被漏掉。

```python
c.fields("events")     # -> Image、CommandLine、TargetUserName 等（来自 event_data）
c.fields("web_logs")   # -> status、uri_stem、client_ip 等（真实列）
```

至于第二个问题——到底该查哪个字段才能找到你想要的结果——这里是一份起步用的速查表（在你自己的案例上运行
`seclogx fields` 可以拿到完整、真实的列表；provider/站点特有的字段尤其会有差异）：

| 表 | 优先尝试这些字段 |
|---|---|
| `events`（进程创建，Sysmon 事件 ID 1） | `Image`、`CommandLine`、`ParentImage`、`ParentCommandLine`、`User`、`Hashes` |
| `events`（网络连接，Sysmon 事件 ID 3） | `Image`、`DestinationIp`、`DestinationPort`、`DestinationHostname` |
| `events`（文件/注册表，Sysmon 事件 ID 11/13） | `Image`、`TargetFilename` / `TargetObject`、`Details` |
| `events`（PowerShell，事件 ID 4104） | `ScriptBlockText` |
| `events`（登录，Security 事件 ID 4624/4625） | `TargetUserName`、`LogonType`、`IpAddress` |
| `events`（任意通道都有） | `channel`、`event_id`、`host`、`computer`、`time_created`、`user_sid` |
| `web_logs` | `uri_stem`、`uri_query`、`status`、`method`、`client_ip`、`user_agent`、`referer`、`log_type` |
| `web_error_logs` | `severity`、`message`、`client_ip`；仅 IIS HTTPERR 有：`method`、`uri`、`status` |
| `scheduled_tasks` | `author`、`hidden`、`enabled`、`actions`、`triggers`、`task_path`、`principal_user_id` |
| `exchange_message_tracking` | `sender_address`、`recipient_address`、`message_subject`、`recipient_status`、`event_id` |
| `exchange_logs` | 先看 `log_type`（弄清楚这具体是哪一种 Exchange 日志），再用 `seclogx fields` 查该日志类型的真实字段名 |

特别是对 `events` 而言，注意有哪些字段存在取决于具体的*通道（channel）*——`Image`/`CommandLine`
是 Sysmon 的字段，不会出现在 Security 通道的登录事件里，反过来
`TargetUserName`/`LogonType` 也不会出现在 Sysmon 事件里。`seclogx fields`
是对整张表采样的，如果你想看某一个具体通道的字段，请先做过滤（见[《7. 常用查询》](07_recipes.zh-CN.md)，其中大多数都是从 `channel = '...'` 开始的）。

下一步：[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)，看如何把这些字段名真正用到查询里，无论写不写 SQL。
