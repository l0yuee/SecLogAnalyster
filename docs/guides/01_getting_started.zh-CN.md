# 1. 快速上手

**语言：[English](01_getting_started.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- 1. 快速上手 | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

## seclogx 是做什么的

取证采集获得的 Windows 事件日志（`.evtx`）文件很难直接分析：它是二进制格式，导出后是冗长的 XML，而且写入该日志的数百种提供程序（provider）字段极不统一。为了一次性的案例分析而把这些数据导入 ELK 之类的 SIEM，往往更糟——脆弱的索引映射（mapping）会在你毫无察觉的情况下丢弃你需要的字段。

seclogx 的目标就是让排查的最初几个小时变得高效：

- 指向一个或多个取证采集目录（它们不需要在同一个父目录下，也可以来自不同的主机）。
- 它会**通用地**解析每一个 `.evtx` 通道（channel）——Security、System、Application、Sysmon Operational、PowerShell Operational、WMI-Activity 等等——统一归一化为一张可查询的表。
- 同一次导入过程中，它还会发现并归一化：磁盘上的**计划任务**定义（一种持久化痕迹）、**IIS/nginx/Apache/Tomcat**
  的访问日志*以及*错误/诊断日志（Web 应用会产生的两大日志类别都覆盖，包括 IIS 的
  HTTP.sys/HTTPERR）、**Exchange** CSV 日志（邮件跟踪日志拥有一等列，其余 Exchange
  已识别的 CSV 日志类型将字段保留在通用表中）、**Linux** syslog（BSD/RFC-3164 与 RFC
  5424，含 `auth.log`/`secure` 的内容）、Linux 审计框架（auditd）与 systemd journal
  导出日志、**数据库**日志（MySQL/MariaDB 错误/通用查询/慢查询日志、PostgreSQL、
  MSSQL、Oracle 告警日志）、**腾讯云主机安全**客户端文本日志（YDService、HIDS/YDLive、
  漏洞/基线扫描器、YDFlame/YDUtils/YDQuaraV2、YDEyes），以及 **Windows 注册表**配置单元（SYSTEM/SOFTWARE/SAM/
  SECURITY/DEFAULT，以及每个用户的 NTUSER.DAT/UsrClass.dat）。EVTX 通过 `.evtx` 后缀发现；辅助来源候选文件通过有限大小的内容前缀分类，同时受后缀排除规则和部分格式的文件名/路径提示影响，因此重命名可能影响识别。完整的十二张表全貌见[《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)。
- Python `Case` 对象提供 DataFrame 与分块迭代器，命令行提供预览和 CSV 导出，并内置基于 Sigma 规则的威胁狩猎能力，自动打上 MITRE
  ATT&CK 标签，覆盖 Windows 事件日志与 Web 访问日志两类数据。**同样不需要写 SQL**：
  `seclogx search` / `Case.search()` 可以用纯字段/取值条件——精确、模糊或正则匹配——过滤任意一张表。
- 核对报告会指出已发现文件中的部分恢复、解析失败与无法分类情况；不支持的规则也会报告。已知无关后缀和空的辅助文件会被过滤，无权访问的路径可能被跳过，因此它不是完整的采集清单。
- **大日志表支持分块访问。** 日志表访问器、SQL 查询、搜索与时间线都有流式替代方案；`search()` 会在取回结果前估算规模。普通 DataFrame 方法及派生分析仍可能耗尽内存，应逐块处理并释放结果，避免将所有分块再次聚合（见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)与[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)）。

seclogx 默认面向单台工作站设计，不依赖外部服务。导入耗时及磁盘、内存需求取决于日志格式、记录宽度、并行度与存储性能；分块交付避免整体取回查询结果，但不能限制每个操作的内存。此外还提供一种可选启用、通过环境变量配置的分布式模式，适用于大批量导入、大规模
Sigma 规则集，或多名分析师需要共同使用同一个案例的场景——见[《10.
分布式部署》](10_distributed_deployment.zh-CN.md)；只要不主动开启，上述一切都不会有任何变化。

## 安装

包本身要求 Python 3.10 及以上版本。本项目的开发与分析统一使用独立于 `base` 的 conda **`python314`** 环境。

```bash
cd SecLogAnalyster
conda activate python314
python -m pip install -e .
```

请在本仓库的检出目录内以可编辑模式（editable install）运行 `seclogx`，因为内置的 Sigma 规则集位于仓库根目录下的 `data/sigma_rules/`，程序在运行时会基于此相对路径查找。

测试和脚本也使用该环境；不能激活环境的非交互式场合，使用 `conda run --no-capture-output -n python314 python ...`。在该环境安装 JupyterLab 与 `ipykernel` 后，通过 `python -m jupyterlab` 启动，选择 `python314` 内核，并在单元格内用 `sys.executable` 确认解释器。如果尚未注册内核，可执行 `python -m ipykernel install --user --name python314 --display-name "Python (python314)"`。

验证安装：

```bash
seclogx version
seclogx --help
```

## 案例工作区（Case workspace）

一切都围绕**案例（case）**展开——它是位于 `./cases/<name>/` 下的一个命名工作区（`case init/list/info` 用 `--dir` 覆盖路径，导入/查询命令用 `--case-root`），其中包含：

```
cases/<name>/
  case.json                     # 已导入的主机列表、导入运行历史
  staging/<batch_id>/<host>/*.ndjson.gz       # EVTX 暂存分片，默认保留
  staging_aux/<batch_id>/<host>/*.{ndjson.gz,arrow}  # 辅助来源暂存分片，默认保留
  logs/ingest_<batch_id>.log      # EVTX 核对报告
  jobs/<job_id>.json             # 后台状态快照
  jobs/<job_id>.log              # 后台标准输出/错误及核对报告
  lake/
    events/host=<h>/channel=<c>/*.parquet                       # Windows 事件日志
    web_logs/host=<h>/log_type=<t>/*.parquet                    # IIS/nginx/Apache/Tomcat 访问日志
    web_error_logs/host=<h>/log_type=<t>/*.parquet               # nginx/Apache/Tomcat/IIS HTTPERR 错误日志
    scheduled_tasks/host=<h>/*.parquet                           # 计划任务定义
    exchange_message_tracking/host=<h>/*.parquet                 # Exchange 邮件流转
    exchange_logs/host=<h>/log_type=<t>/*.parquet                # 其他 Exchange CSV 日志
    syslog/host=<h>/*.parquet                                    # 通用 syslog，含 auth.log/secure
    auditd_logs/host=<h>/record_type=<r>/*.parquet                # Linux 审计框架
    journal_logs/host=<h>/*.parquet                              # systemd journal 导出
    db_logs/host=<h>/log_type=<t>/*.parquet                       # MySQL/PostgreSQL/MSSQL/Oracle 日志
    qcloud_logs/host=<h>/log_type=<t>/*.parquet                   # 腾讯云主机安全客户端日志
    registry/host=<h>/hive_type=<t>/*.parquet                     # Windows 注册表配置单元
```

`lake/` 可以存放在 S3 兼容的对象存储上，而不局限于本地磁盘（`SECLOGX_STORAGE_BACKEND=s3`
——可选启用，见[《10. 分布式部署》](10_distributed_deployment.zh-CN.md)）；`case.json`、`staging/`、
`staging_aux/`、`logs/` 与 `jobs/` 无论在哪种模式下都始终保留在本地/NFS。

你只需创建一次案例（`seclogx case init`），之后可以对它执行任意多次 `ingest`（导入）——来自不同的来源路径、不同的主机，甚至相隔数周也没问题。每次导入都是增量追加，并记录在
`case.json` 中。一次 `ingest` 会在来源路径下一次性发现并导入所有支持的格式——不需要对每种日志类型分别导入。案例只会暴露它实际拥有数据的表；可用
`seclogx sources <case>` / `Case.table_counts()` 查看。

当前没有跨批次去重或断点续跑。同一次扫描会对重叠来源路径去重，但重复运行同一次导入会追加重复行。各通路先完成本批暂存再转换；保留暂存不是可恢复检查点，转换后删除暂存也不能消除磁盘峰值。后台执行不保证在文件尚未写完时查询的一致性；应等导入结束、检查报告，再重新打开 Case 做分析。

辅助暂存默认采用 `auto`：单个来源达到 16 MiB 时使用 Arrow IPC / ZSTD level 1，较小来源使用 gzip NDJSON；EVTX 始终使用 NDJSON。CLI 参数为 `--staging-format auto|arrow|ndjson`，Python 对应 `IngestOptions(staging_format="auto")`。辅助来源的 Parquet 使用 ZSTD level 1。内存、线程预算和批次大小见[命令行参考](05_cli_reference.zh-CN.md)与[Notebook API](06_python_api.zh-CN.md)。

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

- **[2. 日志类型与模式](02_log_types_and_schema.zh-CN.md)** -- 十二张表各自存放什么，该看什么。
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
