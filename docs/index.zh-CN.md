# seclogx 文档

**语言：[English](index.md) | 中文**

面向取证日志采集的、pandas 原生的快速威胁狩猎与分析工具：Windows 事件日志、计划任务、
IIS/nginx/Apache/Tomcat Web 访问与错误日志、Exchange 日志，以及 Linux syslog/auditd/systemd
journal 日志。

## 指南

1. **[快速上手](guides/01_getting_started.zh-CN.md)** -- seclogx 是做什么的、如何安装、案例工作区，以及快速上手示例。
2. **[日志类型与模式](guides/02_log_types_and_schema.zh-CN.md)** -- 十张表分别存放什么、该看什么、该查哪些字段。
3. **[查询与搜索](guides/03_querying_and_search.zh-CN.md)** -- 原生 SQL、免 SQL 的 `search()` 接口，以及有界内存交付。
4. **[威胁狩猎](guides/04_threat_hunting.zh-CN.md)** -- Sigma 规则、ATT&CK 标签，以及扩展检测能力。
5. **[命令行参考](guides/05_cli_reference.zh-CN.md)** -- 每一个 `seclogx` 子命令。
6. **[Python / Notebook API](guides/06_python_api.zh-CN.md)** -- `Case` / `CaseDB` 的完整接口。
7. **[常用查询](guides/07_recipes.zh-CN.md)** -- 可直接复制使用的分析师工作流。
8. **[性能与规模](guides/08_performance_and_scale.zh-CN.md)** -- 在真实规模的案例上会遇到什么。
9. **[故障排查、常见问题与已知限制](guides/09_faq_and_limitations.zh-CN.md)** -- 常见报错解释，以及完整已知限制列表的入口。
10. **[分布式部署](guides/10_distributed_deployment.zh-CN.md)** -- 可选启用的任务队列/共享存储集群模式：它分布了什么（导入、Sigma
    狩猎）、没有分布什么（查询执行仍在单机 DuckDB 上完成），以及如何运行它。

## 内部设计参考（目前为英文）

- **[architecture.md](architecture.md)** -- 两条导入流水线（EVTX 与非
  EVTX）、Parquet 数据湖，以及查询/搜索/检测各层是如何拼接在一起的。
- **[schema.md](schema.md)** -- 每张表逐列的精确参考。
- **[sigma_backend.md](sigma_backend.md)** -- 自定义的 DuckDB Sigma 后端是怎么工作的，以及如何扩展字段映射。
- **[known_limitations.md](known_limitations.md)** -- 完整、最新的 v1 范围决策与边界情况列表。这是权威来源；上面的各指南只链接到它，不重复其内容。

30 秒装好并跑起来的说明，以及一份精简的命令行/API 速查表，见仓库根目录的 `README.md`。
