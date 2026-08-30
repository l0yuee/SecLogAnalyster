# 7. Analyst workflows / recipes

**Language: English | [中文](07_recipes.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | 07. Recipes | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md)

---

A handful of concrete, copy-pasteable starting points. All of these work
identically via `seclogx query <case> "<SQL>"` or `c.query("<SQL>")` in
Python. If you'd rather not write SQL at all, the first two are also
shown as `seclogx search` / `Case.search()` equivalents -- the same
pattern (condition dicts instead of a `WHERE` clause) applies to every
recipe below, and to every table, not just `events`.

**Find LOLBin abuse (process spawned by an unusual parent):**

```sql
SELECT time_created, host, computer,
       (event_data ->> 'ParentImage') AS parent, (event_data ->> 'Image') AS image,
       (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND (event_data ->> 'Image') ILIKE '%\rundll32.exe'
ORDER BY time_created
```

No-SQL equivalent:

```bash
seclogx search incident42 events --eq channel="Microsoft-Windows-Sysmon/Operational" --eq event_id=1 --contains Image=rundll32.exe
```
```python
c.search("events", eq={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1"}, contains={"Image": "rundll32.exe"})
```

**Encoded PowerShell:**

```sql
SELECT time_created, host, computer, (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND ((event_data ->> 'CommandLine') ILIKE '%-enc%' OR (event_data ->> 'CommandLine') ILIKE '%-encodedcommand%')
ORDER BY time_created
```

No-SQL equivalent (`regex` covers both `-enc` and `-encodedcommand` in one condition):

```bash
seclogx search incident42 events --eq channel="Microsoft-Windows-Sysmon/Operational" --eq event_id=1 --regex CommandLine="-enc(odedcommand)?"
```
```python
c.search("events", eq={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1"}, regex={"CommandLine": "-enc(odedcommand)?"})
```

**Successful logons by type, across all hosts (spot RDP/network logons of interest):**

```sql
SELECT time_created, host, computer,
       (event_data ->> 'TargetUserName') AS user,
       (event_data ->> 'LogonType') AS logon_type,
       (event_data ->> 'IpAddress') AS src_ip
FROM events
WHERE channel = 'Security' AND event_id = 4624
ORDER BY time_created
```

**Sweep every ingested host for a known-bad indicator (hash, IP, domain, filename)
without knowing which field it'll be in:**

```bash
seclogx query incident42 "SELECT * FROM events WHERE event_data::VARCHAR ILIKE '%<indicator>%'"
```

or in Python: `c.db.search("<indicator>")`.

**Cross-host process-creation count, to spot an outlier host:**

```sql
SELECT host, count(*) AS n
FROM events
WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
GROUP BY host ORDER BY n DESC
```

**Build a parent/child process chain around a specific process on one host:**

```sql
SELECT time_created, event_id,
       (event_data ->> 'ParentImage') AS parent, (event_data ->> 'Image') AS image,
       (event_data ->> 'CommandLine') AS cmdline
FROM events
WHERE host = 'WKS01' AND channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
  AND time_created BETWEEN TIMESTAMP '2026-01-14 02:10:00' AND TIMESTAMP '2026-01-14 02:20:00'
ORDER BY time_created
```

**Run the bundled Sigma hunt, then drop straight into pandas for further
triage of just the high-severity hits:**

```python
from seclogx import Case
c = Case.open("incident42")
r = c.hunt(min_level="high")
r.matches[["time_created", "host", "sigma_rule_title", "sigma_attack_ids"]].sort_values("time_created")
```

**Web access log 4xx/5xx sweep, across IIS/nginx/Apache/Tomcat at once:**

```sql
SELECT host, log_type, time_created, client_ip, method, uri_stem, status
FROM web_logs
WHERE status >= 400
ORDER BY time_created
```

**Possible webshell activity (uncommon extension hit with a 200, or a
suspicious query string) in IIS/web logs:**

```sql
SELECT host, log_type, time_created, client_ip, uri_stem, uri_query, status
FROM web_logs
WHERE status = 200
  AND ((uri_stem) ILIKE '%.aspx' OR (uri_stem) ILIKE '%.jsp' OR (uri_stem) ILIKE '%.php')
  AND ((uri_query) ILIKE '%cmd=%' OR (uri_query) ILIKE '%eval%' OR (uri_query) ILIKE '%whoami%')
ORDER BY time_created
```

**High-severity entries across every web application's error log at once
(nginx `error`, Apache `error`, Tomcat `SEVERE`, ...):**

```sql
SELECT host, log_type, time_created, severity, message
FROM web_error_logs
WHERE severity IN ('error', 'SEVERE', 'crit', 'alert', 'emerg')
ORDER BY time_created
```

**IIS HTTP.sys (HTTPERR) rejections -- requests HTTP.sys itself refused
before they ever reached an IIS worker process (malformed requests,
queue limits, app pool issues); these never show up in `web_logs` at
all, which is exactly why `web_error_logs` is worth checking separately:**

```sql
SELECT host, time_created, client_ip, client_port, method, uri, status, message AS reason
FROM web_error_logs
WHERE log_type = 'iis_httperr'
ORDER BY time_created
```

**Exchange mail flow: everything sent by or to a suspect address:**

```sql
SELECT time_created, sender_address, recipient_address, message_subject, recipient_status
FROM exchange_message_tracking
WHERE (sender_address) ILIKE '%<suspect-domain-or-address>%'
   OR (recipient_address) ILIKE '%<suspect-domain-or-address>%'
ORDER BY time_created
```

**Any other Exchange log type (HttpProxy, EWS, ActiveSync, ...), swept by
field content without knowing the exact schema:**

```sql
SELECT host, log_type, time_created, fields
FROM exchange_logs
WHERE CAST(fields AS VARCHAR) ILIKE '%<indicator>%'
ORDER BY time_created
```

**Scheduled Tasks: everything not authored by a recognized account, or
hidden, or invoking a LOLBin -- the same heuristic `--suspicious` uses:**

```python
from seclogx import Case
c = Case.open("incident42")
c.suspicious_tasks()[["host", "task_path", "author", "hidden", "actions"]]
```

Next: [08. Performance & scale](08_performance_and_scale.md) for how
these queries behave at real-world case volumes.
