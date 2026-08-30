# 1. 快速上手

**语言：[English](01_getting_started.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- 1. 快速上手 | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md)

---

## seclogx 是做什么的

取证采集获得的 Windows 事件日志（`.evtx`）文件很难直接分析：它是二进制格式，导出后是冗长的 XML，而且写入该日志的数百种提供程序（provider）字段极不统一。为了一次性的案例分析而把这些数据导入 ELK 之类的 SIEM，往往更糟——脆弱的索引映射（mapping）会在你毫无察觉的情况下丢弃你需要的字段。

seclogx 的目标就是让排查的最初几个小时变得高效：

- 指向一个或多个取证采集目录（它们不需要在同一个父目录下，也可以来自不同的主机）。
- 它会**通用地**解析每一个 `.evtx` 通道（channel）——Security、System、Application、Sysmon Operational、PowerShell Operational、WMI-Activity 等等——统一归一化为一张可查询的表。
- 同一次导入过程中，它还会发现并归一化：磁盘上的**计划任务**定义（一种持久化痕迹）、**IIS/nginx/Apache/Tomcat**
  的访问日志*以及*错误/诊断日志（Web 应用会产生的两大日志类别都覆盖，包括 IIS 的
  HTTP.sys/HTTPERR），以及 **Exchange** CSV 日志（邮件跟踪日志拥有一等列，其余 Exchange
  日志类型进入一个不丢弃任何数据的兜底表）。每种格式都是根据内容而非文件名判断的，因此被重命名或迁移过的证据文件同样能被正确识别。完整的六张表全貌见[《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)。
- 你得到的是从头到尾原生的 `pandas.DataFrame` 接口（命令行表格/CSV 导出，或在 notebook
  中使用的 Python `Case` 对象），并内置基于 Sigma 规则的威胁狩猎能力，自动打上 MITRE
  ATT&CK 标签，覆盖 Windows 事件日志与 Web 访问日志两类数据。**同样不需要写 SQL**：
  `seclogx search` / `Case.search()` 可以用纯字段/取值条件——精确、模糊或正则匹配——过滤任意一张表。
- 每一个解析错误、每一个无法识别的文件、以及每一条不支持的规则都会被明确报告，绝不会被静默丢弃。
- **凡是直接面向分析师的环节，内存占用都是有界的。** Web 访问/错误日志尤其可能在整个案例范围内达到 TB
  级别——每一个返回 DataFrame 的方法都有对应的分块/流式替代方案，`search()`
  还会在真正取回结果之前主动检查结果规模是否超出机器可用内存，超出就拒绝执行，而不是冒着让机器崩溃的风险（见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)与[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)）。

seclogx 面向单台工作站设计，不是为集群准备的——不需要分布式部署，也不依赖外部服务。在此前提下，不同日志类别的现实规模差异很大：EVTX
案例通常远低于 100GB（DuckDB + Parquet 惰性、核外执行本身就能轻松应对），而 Web
访问/错误日志现实中可以达到 TB 级别——上面提到的有界内存交付机制，正是为此而设计的。

## 安装

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

## 案例工作区（Case workspace）

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

## 快速上手示例

```bash
seclogx case init incident42
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01
seclogx sources incident42
seclogx fields incident42 events
seclogx search incident42 events --contains Image=mimikatz --eq host=WKS01
seclogx hunt incident42
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv
```

接下来可以看：

- **[2. 日志类型与模式](02_log_types_and_schema.zh-CN.md)** -- 六张表各自存放什么，该看什么。
- **[3. 查询与搜索](03_querying_and_search.zh-CN.md)** -- SQL、免 SQL 的 `search()` 接口，以及有界内存交付。
- **[4. 威胁狩猎](04_threat_hunting.zh-CN.md)** -- Sigma 规则与 ATT&CK 标签。
- **[5. 命令行参考](05_cli_reference.zh-CN.md)** / **[6. Python API](06_python_api.zh-CN.md)** -- 完整的命令/方法参考。
- **[7. 常用查询](07_recipes.zh-CN.md)** -- 可直接复制使用的起点。

## 许可证与规则来源

seclogx 自身代码采用 MIT 许可证（见 `LICENSE`）。内置于
`data/sigma_rules/` 下的 Sigma 规则均未经修改地复制自
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)，采用 Detection Rule License 1.1
授权（见 `data/sigma_rules/LICENSE-DRL-1.1.txt`）；每条规则确切的上游来源与提交（commit）记录在
`data/sigma_rules/SOURCES.md` 中，且每一条匹配结果都会展示原始规则的作者信息。完整许可证文本见仓库根目录的
`README.md`。
