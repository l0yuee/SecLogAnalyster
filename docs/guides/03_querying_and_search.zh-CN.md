# 3. 查询与搜索

**语言：[English](03_querying_and_search.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | 3. 查询与搜索 | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

每张表（见[《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)）都有三种访问方式：原生 SQL、免 SQL 的
`search()` 接口，或者通用的整表/整查询取回。三种方式都有对应的有界内存版本。本指南覆盖全部内容——该用哪种接口，以及底层的内存安全机制是怎么工作的。

## 原生 SQL

`seclogx query <case> "<SQL>"` / `Case.query()` 对案例中的任意一张表执行任意 SQL：

```sql
SELECT time_created, computer, (event_data ->> 'Image') AS image, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
ORDER BY time_created
```

`Case.db.table(name)` / `seclogx table <case> <name>` 无需任何 `WHERE`
子句即可取回一张表的完整内容。完整的参数/方法列表见[《5. 命令行参考》](05_cli_reference.zh-CN.md)与[《6. Python API》](06_python_api.zh-CN.md)。

## 不写 SQL 也能查询

如果你不熟悉 SQL，本项目中的每一个 SQL 示例都有对应的免 SQL 写法：命令行用
`seclogx search <case> <table>`，Python 用 `Case.search()`。条件就是普通的字段/取值对，分三种：

| 条件 | 含义 | 命令行参数 | Python |
|---|---|---|---|
| 精确匹配 | 字段与某个值完全相等 | `--eq FIELD=VALUE` | `eq={"field": "value"}` |
| 模糊匹配 | 字段包含某个值（子串） | `--contains FIELD=VALUE` | `contains={"field": "value"}` |
| 正则匹配 | 字段匹配某个正则表达式 | `--regex FIELD=PATTERN` | `regex={"field": "pattern"}` |

```bash
# 查找疑似 webshell：uri_stem 中含 "shell"，状态码恰好是 200
seclogx search incident42 web_logs --contains uri_stem=shell --eq status=200
```
```python
from seclogx import Case
c = Case.open("incident42")
c.search("web_logs", contains={"uri_stem": "shell"}, eq={"status": 200})
```

有几点让它不只是"多敲几个字的 LIKE"：

- **默认大小写不敏感**（用 `--case-sensitive` / `case_sensitive=True` 切换为区分大小写的精确匹配）。
- **同一条件里的多个取值按 OR 组合**：`--eq status=404,500`（命令行，逗号分隔）或
  `eq={"status": ["404", "500"]}`（Python）表示匹配其中任意一个值。
- **不同条件之间默认按 AND 组合**（必须每个条件都满足），加上 `--match-any` /
  `match="any"` 则改为按 OR 组合（满足其中任意一个条件即可）。
- **字段名无论是不是"真正的"列都能用。** 只要不是该表自身的列（`status`、`uri_stem`
  等），就会自动到该表特定 provider 的 JSON 兜底字段中按 key 查找（`events` 对应
  `event_data`，`web_logs`/`web_error_logs` 对应 `extra`，`exchange_logs` 对应
  `fields`）——`Image`、`CommandLine`、`TargetUserName`，不管底层 provider 实际怎么命名，直接用就行：

  ```bash
  seclogx search incident42 events --contains Image=mimikatz --eq channel="Microsoft-Windows-Sysmon/Operational"
  seclogx search incident42 events --regex CommandLine=".*-enc.*"
  ```

  如果一个字段名既不是真正的列，也无法在任何 JSON 兜底字段中找到（`scheduled_tasks`
  就是这种情况，它没有任何 JSON 对象兜底字段），会得到一个清晰的提示，列出该表实际拥有的列，而不是数据库层面难以理解的报错。不确定一张表有哪些字段？见[《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)中的“我能查询哪些字段？”。
- **`--regex` 使用正则表达式**（DuckDB 基于 RE2 的正则引擎——和大多数日志分析工具用的语法一样，不支持前瞻/后顾断言，而日志匹配场景基本用不到这些）。`--contains`
  永远是字面子串匹配，绝不是通配符模式——需要真正的模式匹配时请用 `--regex`。
- **内存安全是设计使然。** `search()` 会在真正取回结果之前先估算结果规模，如果估算结果太大就会拒绝执行——并直接告诉你该用哪种替代方案——而不是冒着让机器耗尽内存的风险硬取。完整机制见下文“内存安全检查”。

## 大表的有界内存访问

每一个返回 DataFrame 的访问器——`.query()`、`.table()`、
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
在 `--out` 时会将分块直接流式写入 CSV，控制台预览也只会拉取足够填满表格的行数（绝不会拉取完整结果）——见[《5. 命令行参考》](05_cli_reference.zh-CN.md)。你不需要任何 `--chunks` 之类的参数；这就是这些命令本来的工作方式。

## 内存安全检查

`.search()` 比上面的 `_chunks` 模式更进一步：它会在真正取回结果*之前*先估算结果规模（精确的
`count(*)`，乘以一个从小样本得出的单行字节数），并与机器当前实际可用的内存做比较。如果把整个结果物化成一个
DataFrame 会用掉超过四分之一的可用内存，它就会拒绝执行——抛出
`ResultTooLargeError`——而不是硬取一把、冒着耗尽内存崩溃的风险：

```python
from seclogx.errors import ResultTooLargeError

try:
    df = c.search("web_logs", contains={"uri_stem": "shell"})
except ResultTooLargeError as e:
    print(e)
    # "this search matches an estimated 8,400,000 rows (~1200 MB) -- too
    #  large to safely hold in memory as one DataFrame. Use search_chunks()
    #  ... or search_to_csv() ..."

# 它提示的两种替代方案，无论结果多大都是内存安全的：
for chunk in c.search_chunks("web_logs", contains={"uri_stem": "shell"}):
    ...                                                          # 逐块迭代
c.search_to_csv("web_logs", "hits.csv", contains={"uri_stem": "shell"})  # 或流式写入文件
```

`query()`/`table()` 等方法本身并不做这种"先估算再决定"的检查（只有
`.search()` 会做）——对于那些方法，只要你不确定结果大小，就自己主动改用
`_chunks` 同名方法。如果你已经知道某个 `.search()` 查询的结果很小（比如条件已经收得很窄），也不需要做任何特殊处理——这个检查只会拦截真正被估算为过大的取回操作；能装得下的结果会像上面的一次性方法一样，正常返回一个
DataFrame。

在命令行中这永远不会变成一个错误——`seclogx search`
总是会展示一个有界大小的预览，并告诉你估算的行数/大小；`--out`
则始终会把所有匹配行流式导出到 CSV，无论结果有多大。

这个估算本身是怎么工作的，以及它的注意事项（采样带来的误差、尽力而为的可用内存检测），见[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)。

`Case` 支持上下文管理器协议，便于干净地关闭其 DuckDB 连接：

```python
with Case.open("incident42") as c:
    df = c.summary()
```

下一步：[《4. 威胁狩猎》](04_threat_hunting.zh-CN.md)，在这些同样的表之上做基于 Sigma 规则的检测。
