# 7. 分析师工作流 / 常用查询

**语言：[English](07_recipes.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | 7. 常用查询 | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

以下是一些具体、可直接复制使用的起点。它们既可以通过
`seclogx query <case> "<SQL>"`，也可以在 Python 中通过 `c.query("<SQL>")` 以完全相同的方式运行。如果你不想写
SQL，前两个查询同时给出了 `seclogx search` / `Case.search()` 的对应写法——下面每一个查询都可以照这个模式（用条件字典代替
`WHERE` 子句）改写，不限于 `events` 表。

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

不写 SQL 的等价写法：

```bash
seclogx search incident42 events --eq channel="Microsoft-Windows-Sysmon/Operational" --eq event_id=1 --contains Image=rundll32.exe
```
```python
c.search("events", eq={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1"}, contains={"Image": "rundll32.exe"})
```

**编码后的 PowerShell 命令：**

```sql
SELECT time_created, host, computer, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND ((event_data ->> 'CommandLine') ILIKE '%-enc%' OR (event_data ->> 'CommandLine') ILIKE '%-encodedcommand%')
ORDER BY time_created
```

不写 SQL 的等价写法（一个 `regex` 条件同时覆盖 `-enc` 和 `-encodedcommand`）：

```bash
seclogx search incident42 events --eq channel="Microsoft-Windows-Sysmon/Operational" --eq event_id=1 --regex CommandLine="-enc(odedcommand)?"
```
```python
c.search("events", eq={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1"}, regex={"CommandLine": "-enc(odedcommand)?"})
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

**计划任务：找出所有作者不明、被隐藏、调用了 LOLBin，或伪装成已知微软任务的任务——与
`--suspicious` 使用的是同一套启发式规则，`suspicion_reasons` 会说明每一行具体是因为什么被标记的：**

```python
from seclogx import Case
c = Case.open("incident42")
c.suspicious_tasks()[["host", "task_path", "author", "hidden", "action_command", "suspicion_reasons"]]
```

**按来源 IP 统计所有主机上的 SSH 失败登录（排查暴力破解来源），再反查该
IP 是否有成功登录：**

```python
from seclogx import Case
c = Case.open("incident42")
auth = c.auth_events()
auth[auth["event_type"] == "ssh_failed"]["source_ip"].value_counts()
auth[(auth["event_type"] == "ssh_accepted") & (auth["source_ip"] == "203.0.113.7")]
```

也可以直接用 SQL 查询 `syslog`（当你还想看原始行，或某台主机还没跑过
`auth_events()` 时很有用）：

```sql
SELECT host, time_created, message
FROM syslog
WHERE app_name = 'sshd' AND message ILIKE 'Failed password%'
ORDER BY time_created
```

**某个用户的 sudo 命令历史：**

```python
auth = c.auth_events()
auth[(auth["event_type"] == "sudo_command") & (auth["user"] == "alice")][["time_created", "host", "command"]]
```

**auditd：某条已知规则（`key`）触发的所有记录，再按 `audit_serial`
取出某一次具体事件完整的 SYSCALL/EXECVE/CWD/PATH 全貌：**

```sql
SELECT time_created, host, record_type, exe, comm, pid, ppid
FROM auditd_logs
WHERE key = 'privilege_escalation'
ORDER BY time_created

-- 针对某一次具体事件：
SELECT * FROM auditd_logs WHERE audit_serial = 12345 ORDER BY record_type
```

**systemd journal：当分析人员导出的是 `journalctl -o json` 而非转发的
syslog 文件时，查看某个服务记录的所有 warning 及以上级别的内容：**

```sql
SELECT time_created, unit, priority, message
FROM journal_logs
WHERE unit = 'sshd.service' AND CAST(priority AS INTEGER) <= 4
ORDER BY time_created
```

下一步：[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)，看看这些查询在真实规模的案例上表现如何。
