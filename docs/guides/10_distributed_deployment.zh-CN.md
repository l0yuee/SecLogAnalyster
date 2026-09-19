# 10. 分布式部署

**语言：[English](10_distributed_deployment.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | 10. 分布式部署

---

seclogx 默认以单机方式运行，无需任何额外配置——本文档其余部分的所有内容，无论你是否读过这一页，行为都完全不变。本指南介绍的是**可选启用**的集群模式：一套任务队列，把导入（ingest）和 Sigma
狩猎的工作分发到若干 `seclogx worker` 进程（可以在一台机器上，也可以分布在多台机器上）；再加上一个存储后端，让 Parquet 数据湖可以存放在
S3 兼容的对象存储上，而不必局限于本地磁盘。

## 集群模式究竟分布了什么——以及没有分布什么

开启集群模式改变的是两件事：

1. **导入（ingest）。** 两条导入通路（`.evtx`，以及非 EVTX
   的各个日志族——计划任务/Web 日志/Exchange/syslog/auditd/journal/数据库/QCloud/注册表）都会把各自的单文件解析任务交给一个任务队列去分发，而不是像本地模式那样交给本地进程池。在本地模式下，这个队列的行为其实就是
   `ProcessPoolExecutor`。一旦配置了 broker，同样的任务就会被放入队列，供任意数量的 `seclogx worker`
   进程认领执行，前提是这些进程能够访问来源和暂存路径。worker 解析并写出暂存分片；
   协调端收到清单后读取分片，执行有界的 DuckDB 到 Parquet 转换。
2. **Sigma 狩猎。** `seclogx hunt` 会用同样的方式把互不依赖的规则分发到各个 worker
   上执行，再把匹配结果合并回来。每条规则本身的查询早已与其他规则互不依赖，所以这只是一次纯粹的并行映射（map）——并不是为顺序执行路径之外另外实现了一套规则求值逻辑。

**没有改变的是：seclogx 没有引入分布式 SQL 查询引擎。** DuckDB
仍然是唯一的查询引擎，任何单条查询或单条 Sigma 规则依然只在一个进程内针对
Parquet 数据湖执行，行为与[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)和
`docs/architecture.md` 中描述的完全一致。这里所说的"分布式"指的是**任务级**并行——多个独立的
DuckDB 进程/查询同时针对同一个共享数据湖运行——而不是单条查询内部的分布式执行。集群模式不会让某一次
`seclogx query`/`seclogx search` 调用本身变得更快；它带来的是：更多互不依赖的导入文件或狩猎规则可以同时处理，以及多名分析师的机器可以同时针对同一个共享数据湖发起查询。

因此，集群模式在以下场景中有用：一批导入任务文件足够多，把解析工作分摊到多台机器上确实能节省总耗时；Sigma
规则集足够大，逐条规则在单机上求值本身成了瓶颈；或者多名分析师希望共用同一个案例的数据湖，而不必各自在本地保留一份完整拷贝。它对单条较慢的查询或单个较小的案例没有帮助——那种场景仍然走的是这个项目一贯采用的单机
DuckDB 路径。

## 安装

每台从本仓库源码安装的机器都应先按[安装指南](01_getting_started.zh-CN.md#安装)
一次性准备构建工具。主包已包含原生扩展，cluster 额外依赖仅增加分布式组件。

```bash
conda activate python314
python -m pip install -e ".[cluster]"
```

本地 Python、CLI 和 Notebook 使用这个专用环境。仓库提供的 Linux 容器镜像有自己的解释器和依赖；
协调端与 worker 应运行一致的 seclogx 版本。

这会安装 `redis`、`rq`（任务队列）以及 `boto3`（用于 S3 元数据操作）——普通单机使用完全不需要它们，也不会导入它们。针对
S3 的 Parquet 实际读写走的是 DuckDB 自带的 `httpfs`
扩展（DuckDB 会在建立连接时自动安装它），而不是额外的 Python 依赖。

## 如何开启：环境变量

集群模式通过环境变量激活。运行 CLI 或创建、打开 `Case` 之前设置变量；`Case` 会保存解析后的配置，
修改环境不会重新配置一个已经打开的对象。

| 变量 | 默认值 | 含义 |
|---|---|---|
| `SECLOGX_BROKER_URL` | 未设置 | 一个 `redis://...` URL。它是否存在，决定了导入/狩猎任务是否会分布式派发——未设置时，一切都和以前一样在本地运行。 |
| `SECLOGX_STORAGE_BACKEND` | `local` | `local`（案例的 `lake/` 目录仍在本地磁盘，和一直以来一样）或 `s3`（数据湖改为存放在 S3 兼容的对象存储上）。 |
| `SECLOGX_S3_BUCKET` | 未设置 | 当 `SECLOGX_STORAGE_BACKEND=s3` 时必填。数据湖存放在 `s3://<bucket>/<案例名>/lake/...` 下——按案例名分区，因此一个桶（bucket）可以容纳多个案例。 |
| `SECLOGX_S3_ENDPOINT_URL` | 未设置 | 用于指向 MinIO 或其他 S3 兼容端点，而不是真正的 AWS S3。 |
| `SECLOGX_S3_REGION` | 未设置 | 同时透传给 boto3 与 DuckDB 的 `httpfs`。 |

S3 凭据走 boto3 的标准凭据链（`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、实例角色、
`~/.aws/credentials` 等）。`ClusterConfig` 不保存 AWS 凭据；存储后端通过 boto3 解析凭据，
并将其配置到 DuckDB 连接供 S3 访问使用。

存储与任务队列是两个相互独立的开关——你可以只启用 S3（单机导入、供多名分析师共享读取权限）而不配置
broker，也可以只配置 broker，并将文件系统数据湖以相同路径挂载给所有狩猎 worker。
S3 只共享 Parquet 数据湖，不负责传输来源或暂存分片，也不会把转换工作分发给 worker。

无论哪种模式下，`case.json`、`staging/` 和 `staging_aux/` 都保留在 `--case-root` 下。
**协调端与导入 worker 必须以相同绝对路径共享来源和可写暂存目录。** 队列传递文件描述、路径和选项，
不会通过 Redis 上传证据或返回文件内容。只在协调端容器挂载路径是不够的。跨平台路径表示也必须一致，
因此 Linux 容器 worker 通常配合 Linux 容器协调端更容易配置。

分布式与对象存储配置会自动选择暂存路径。暂存保存解析后的数据集，体积可能很大。每条导入通路先完成暂存，再分组转换，没有磁盘背压。
辅助来源默认 `auto`：达到 16 MiB 的来源文件使用 Arrow IPC/ZSTD，较小来源用 gzip NDJSON；
EVTX 保持 NDJSON。默认 `keep_staging=False` 也要为共享暂存、Parquet 和临时文件预留空间，
因为删除发生在转换成功之后。`keep_staging=True` 用于诊断保留，不影响原始证据。
分布式狩猎还要求 worker 能够访问任务中指定的案例和自定义规则路径。

## `seclogx worker`

在任何应该处理分布式导入/狩猎任务的机器（或容器）上运行：

```bash
export SECLOGX_BROKER_URL=redis://<broker-host>:6379/0
export SECLOGX_STORAGE_BACKEND=s3
export SECLOGX_S3_BUCKET=my-seclogx-cases
export SECLOGX_S3_ENDPOINT_URL=http://<minio-或-s3-端点>
export SECLOGX_S3_REGION=us-east-1
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

seclogx worker
```

它会阻塞并持续监听导入与狩猎两个队列，直到停止（也可以加
`--burst`，处理完当前队列中已有的任务后立即退出——适合脚本化/CI
场景下的验证）。进程和机器数量需要受内存、共享存储与 broker 能力约束，并使用一致的
broker、存储配置和必要文件系统挂载。RQ worker 可使用仓库提供的 Linux 容器部署；
本地 Windows 多进程支持不代表原生 Windows RQ worker 也受支持。

## 协调端：`seclogx ingest` / `seclogx hunt` / `seclogx cluster status`

并不存在一个单独的"协调端（coordinator）"程序——它就是你一直在用的同一个
`seclogx` 命令行工具，在分析师平时工作的任意位置运行（笔记本电脑、跳板机、CI
任务），配置相同环境变量并挂载所需共享路径。设置 `SECLOGX_BROKER_URL` 后，单文件解析和
狩猎任务进入 Redis/RQ；导入协调端等待暂存结束后仍要完成转换，需要自身的 CPU、内存和 I/O 资源。

```bash
seclogx case init incident42 --case-root /shared/cases
seclogx ingest incident42 --case-root /shared/cases \
  --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01 \
  --memory-limit 2GB --duckdb-threads 2 --staging-format auto
seclogx hunt incident42 --case-root /shared/cases
```

上述来源必须对每个导入 worker 可读，案例路径必须提供共享可写暂存。
`--staging-chunk-bytes` 控制 worker 的分片目标；`--flatten-batch-bytes`、`--memory-limit`
和 `--duckdb-threads` 控制协调端转换。`--workers` 是本地进程池预算，不限制 Redis worker 副本数。
DuckDB 内存参数不是整个进程树的上限，`CONVERSION_LOCK` 也只串行化同一协调进程内的转换。

当前 RQ 适配器提交任务时没有显式设置每个任务的超时或重试策略，使用已安装 RQ 的默认值；
seclogx CLI 没有分布式任务超时覆盖参数。派发耗时较长的文件前需核对这一约束。
任务失败会被报告，不会自动续跑。本地待执行任务数量的限制也不适用于 Redis 队列，后者当前一次性提交任务列表。

另外两个命令是集群模式特有的：

- **`seclogx cluster config`** —— 打印当前解析出的配置（`ClusterConfig` 不包含 AWS 凭据，
  但 broker URL 本身可能包含凭据）。可用于确认某台机器是否读取了预期环境变量。
- **`seclogx cluster status`** —— 在配置了 broker
  的情况下，报告当前有多少个 `seclogx worker`
  进程在线，以及两个队列各自排队中的任务数。如果没有配置 broker，它会明确说明这一点并正常退出（没有集群可供报告）。

## Docker Compose 与 Kubernetes

`deploy/docker-compose.yml` 提供单机集群服务演示（Redis
+ MinIO + 一个可伸缩的 `worker` 服务）——完整操作步骤见
`deploy/README.md`，导入前须按其中说明补齐共享挂载。`deploy/k8s/worker-deployment.yaml` 是面向 worker
集群的 Kubernetes `Deployment`（有意只覆盖 worker
本身——Redis 与 S3 兼容存储需要自行提供，这与大多数真实部署环境本来就已经具备这两项服务的情况是一致的）。二者的完整说明都在
`deploy/README.md` 中；本指南是它们的叙述性说明，不重复其中的内容。

## 加锁与并发写入

`case.json` 更新使用本地文件锁；配置 broker 后改用 Redis 锁。它只保护元数据的读取、修改和写入，
不覆盖整个导入操作，也不提供跨次去重、回滚、数据湖原子发布或一致查询快照。
应协调同一 Case 同时只有一个导入写入方，完成后再分析。不同协调端和后台任务不共享
`CONVERSION_LOCK`，增加 broker 也不会让并发写入成为事务。Redis 锁的标识包含解析后的案例路径，
因此不同机器的挂载路径也需要一致。

## 实现原理（供感兴趣的读者，或排查问题时参考）

- `src/seclogx/distributed/config.py` —— `ClusterConfig`，从上面这些环境变量解析而来。
- `src/seclogx/distributed/storage.py` —— `StorageBackend`
  （`LocalStorageBackend`/`S3StorageBackend`），被 `CaseDB`
  以及两条导入通路 flatten 步骤中每一个涉及 `lake/` 的操作所使用。
- `src/seclogx/distributed/queue.py` —— `JobQueue`
  （`LocalJobQueue`/`RQJobQueue`），被两条导入通路的编排逻辑，以及
  `detect/hunt.py` 中的分布式扇出路径所使用。
- `src/seclogx/distributed/locking.py` —— 上文提到的 `case.json` 锁。
- `src/seclogx/cli/worker_cmd.py` / `src/seclogx/cli/cluster_cmds.py` ——
  `seclogx worker` / `seclogx cluster status` / `seclogx cluster config`
  的实现所在。

设计思路见 `docs/architecture.md` 中"Why not Dask / a distributed
engine"一节；当前这一功能确切、最新的能力边界见
`docs/known_limitations.md` 中的"Scale"一节。

下一步：回到[《1. 快速上手》](01_getting_started.zh-CN.md)，或查看[《9.
常见问题与已知限制》](09_faq_and_limitations.zh-CN.md)获取完整已知限制列表的入口。
