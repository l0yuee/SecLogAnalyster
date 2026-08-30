# 6. Python / Notebook API

**语言：[English](06_python_api.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | 6. Python API | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md)

---

命令行能做的一切，都有对应的 Python API，且全程返回 `pandas.DataFrame` 对象——可以直接嵌入到你日常使用的 Jupyter notebook 与 pandas 分析流程中。下面用到的有界内存（`_chunks`）与
`search()` 内存安全机制，完整讲解见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)。

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

# 不确定某张表里到底有什么字段，或者该查哪一个？fields() 能从这个案例的真实数据中给出答案——
# 每一行是一个字段（真实列，或者 event_data 这类 JSON 兜底字段里找到的某个 key），
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

# CaseDB 的便捷方法可通过 c.db 访问
c.db.by_event_id([4624, 4625])
c.db.by_host("WKS01")
c.db.search("mimikatz")                # 对 event_data/provider/computer 做全文检索
c.db.tables                            # list[str]：该案例实际拥有的表
c.db.table("web_error_logs")           # 通用兜底方法：按名称取任意表，返回 DataFrame

# 计划任务排查（启发式规则，非 Sigma——见第 4 节）
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

# 干净地关闭 DuckDB 连接
with Case.open("incident42") as c:
    df = c.summary()
```

## 方法一览

| 分类 | 方法 |
|---|---|
| 生命周期 | `Case.create(name, case_root=)`、`Case.open(name, case_root=)`、`Case.list_cases(case_root=)`、`c.info()` |
| 导入 | `c.ingest(sources, workers=, keep_raw=, keep_staging=)` -> `IngestReport` |
| 探索 | `c.summary()`、`c.channels()`、`c.hosts()`、`c.table_counts()` |
| 字段发现 / 免 SQL 搜索 | `c.fields(table, sample_size=)`、`c.search(table, eq=, contains=, regex=, match=, case_sensitive=)`、`c.search_chunks(...)`、`c.search_to_csv(table, path, ...)` |
| 原生 SQL | `c.query(sql)`、`c.query_chunks(sql, chunksize=)`、`c.db.table(name)`、`c.db.table_chunks(name, chunksize=)` |
| 各日志家族的专属访问器 | `c.events()` / `c.events_chunks()`，`c.web_logs(log_type=)` / `_chunks`，`c.web_error_logs(log_type=)` / `_chunks`，`c.scheduled_tasks()` / `_chunks`，`c.exchange_message_tracking()` / `_chunks`，`c.exchange_logs(log_type=)` / `_chunks` |
| 计划任务排查 | `c.suspicious_tasks()` |
| 检测 | `c.hunt(rules_dir=, min_level=)` -> `HuntResults` |
| 时间线 | `c.timeline(start=, end=, host=, channel=, event_id=)` / `c.timeline_chunks(...)` |
| `CaseDB`（`c.db`） | `.tables`、`.table(name)` / `.table_chunks(name)`、`.sql(query)` / `.sql_chunks(query)`、`.by_event_id(ids)`、`.by_host(host)`、`.search(text)`、`.estimate(query)` -> `ResultSizeEstimate` |

下一步：[《7. 常用查询》](07_recipes.zh-CN.md)，用这套 API（以及对应的 `seclogx search` 免 SQL 写法）给出的实际可用的例子。
