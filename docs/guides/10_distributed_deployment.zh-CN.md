# 10. 分布式部署

**语言：[English](10_distributed_deployment.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- [1. 快速上手](01_getting_started.zh-CN.md) | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | 10. 分布式部署

---

seclogx 默认以单机方式运行，无需任何额外配置——本文档其余部分的所有内容，无论你是否读过这一页，行为都完全不变。本指南介绍的是**可选启用**的集群模式：一套任务队列，把导入（ingest）和 Sigma
狩猎的工作分发到若干 `seclogx worker` 进程（可以在一台机器上，也可以分布在多台机器上）；再加上一个存储后端，让 Parquet 数据湖可以存放在
S3 兼容的对象存储上，而不必局限于本地磁盘。

## 集群模式究竟分布了什么——以及没有分布什么

开启集群模式改变的是两件事：

1. **导入（ingest）。** 两条导入流水线（`.evtx`，以及非 EVTX
   的各个日志族——计划任务/Web 日志/Exchange/syslog/auditd/journal）都会把各自的单文件解析任务交给一个任务队列去分发，而不是像本地模式那样交给本地进程池。在本地模式下，这个队列的行为其实就是今天的
   `ProcessPoolExecutor`。一旦配置了 broker，同样的任务就会被放入队列，供任意数量的 `seclogx worker`
   进程（在任何位置）去认领执行。
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

```bash
pip install -e ".[cluster]"
```

这会安装 `redis`、`rq`（任务队列）以及 `boto3`（用于 S3 元数据操作）——普通单机使用完全不需要它们，也不会导入它们。针对
S3 的 Parquet 实际读写走的是 DuckDB 自带的 `httpfs`
扩展（DuckDB 会在建立连接时自动安装它），而不是额外的 Python 依赖。

## 如何开启：环境变量

集群模式完全通过环境变量激活——不存在任何新增的命令行参数。每一次运行
`seclogx` 命令（以及以库方式调用 `Case`
的每个方法）都会在运行时从环境变量中解析配置，因此导出下面这些变量，就是"如何开启集群模式"的全部内容：

| 变量 | 默认值 | 含义 |
|---|---|---|
| `SECLOGX_BROKER_URL` | 未设置 | 一个 `redis://...` URL。它是否存在，决定了导入/狩猎任务是否会分布式派发——未设置时，一切都和以前一样在本地运行。 |
| `SECLOGX_STORAGE_BACKEND` | `local` | `local`（案例的 `lake/` 目录仍在本地磁盘，和一直以来一样）或 `s3`（数据湖改为存放在 S3 兼容的对象存储上）。 |
| `SECLOGX_S3_BUCKET` | 未设置 | 当 `SECLOGX_STORAGE_BACKEND=s3` 时必填。数据湖存放在 `s3://<bucket>/<案例名>/lake/...` 下——按案例名分区，因此一个桶（bucket）可以容纳多个案例。 |
| `SECLOGX_S3_ENDPOINT_URL` | 未设置 | 用于指向 MinIO 或其他 S3 兼容端点，而不是真正的 AWS S3。 |
| `SECLOGX_S3_REGION` | 未设置 | 同时透传给 boto3 与 DuckDB 的 `httpfs`。 |

S3 的**凭据永远不会被 seclogx 自身的配置读取**——它们走的是 boto3
的标准凭据链（`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_DEFAULT_REGION`
环境变量、实例角色（instance profile）、`~/.aws/credentials` 等），与任何基于
boto3 的工具完全一样。seclogx 自身绝不会读取、保存或记录任何凭据信息。

存储与任务队列是两个相互独立的开关——你可以只启用 S3（单机导入、供多名分析师共享读取权限）而不配置
broker，也可以只配置 broker（分布式导入/狩猎、查询仍在单机、数据湖仍在本地）。大多数真实的集群部署会同时使用两者，因为只有这样才能让多台
worker 机器真正并发写入同一个数据湖。

无论哪种模式下，`case.json` 和 `staging/`
都会有意保留在案例 `--case-root` 所指向的本地/NFS
挂载目录中。它们体积小，只是协调端（coordinator）用于导入记账的信息——不是需要扩展的部分，分布式
worker 也不需要直接访问它们（原因见下文"实现原理"一节）。

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

它会阻塞并持续监听导入与狩猎两个队列，直到被杀死为止（也可以加
`--burst`，处理完当前队列中已有的任务后立即退出——适合脚本化/CI
场景下的验证）。想运行多少个就运行多少个，想放在多少台机器上就放多少台，只要都指向同一个
broker 与同一份存储即可。

## 协调端：`seclogx ingest` / `seclogx hunt` / `seclogx cluster status`

并不存在一个单独的"协调端（coordinator）"程序——它就是你一直在用的同一个
`seclogx` 命令行工具，在分析师平时工作的任意位置运行（笔记本电脑、跳板机、CI
任务），只需导出和 worker 相同的环境变量即可。一旦设置了
`SECLOGX_BROKER_URL`，`seclogx ingest`/`seclogx hunt`
就会改为把工作放入队列，而不是在本地启动进程池，并等待结果返回。

```bash
seclogx case init incident42 --case-root /shared/cases   # 或者数据湖直接建在 S3 上，见上文
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01
seclogx hunt incident42
```

另外两个命令是集群模式特有的：

- **`seclogx cluster config`** —— 打印当前解析出的配置（其中不含任何凭据信息，因为凭据本来就不会经过
  `ClusterConfig`）。可用于确认某台机器是否真的读取到了你期望它读取的环境变量。
- **`seclogx cluster status`** —— 在配置了 broker
  的情况下，报告当前有多少个 `seclogx worker`
  进程在线，以及两个队列各自排队中的任务数。如果没有配置 broker，它会明确说明这一点并正常退出（没有集群可供报告）。

## Docker Compose 与 Kubernetes

`deploy/docker-compose.yml` 是一个可以直接在单机上跑起来的集群演示环境（Redis
+ MinIO + 一个可伸缩的 `worker` 服务）——完整操作步骤见
`deploy/README.md`。`deploy/k8s/worker-deployment.yaml` 是面向 worker
集群的 Kubernetes `Deployment`（有意只覆盖 worker
本身——Redis 与 S3 兼容存储需要自行提供，这与大多数真实部署环境本来就已经具备这两项服务的情况是一致的）。二者的完整说明都在
`deploy/README.md` 中；本指南是它们的叙述性说明，不重复其中的内容。

## 加锁：为什么 S3 存储/多机场景即便只关心存储，也建议配置 broker

`case.json` 的读取-修改-写入过程（导入记账：已见过的主机、历次运行记录）现在始终受锁保护——这修复的是一个真实存在、且在集群模式出现之前就已存在的问题（两次针对同一案例的
`seclogx ingest` 运行发生竞争时，曾经可能悄悄丢失其中一次运行的记账信息），而不仅仅是集群模式才需要关心的问题。在单机上，或者案例目录位于普通本地磁盘时，这里用的是一个纯本地、不依赖额外第三方库的文件锁。一旦配置了
broker，则改用基于 Redis
的锁——通过网络文件系统实现的 POSIX
文件锁并不足以可靠地协调真正相互独立的多台机器，而分布式部署本来就需要
Redis 来支撑任务队列，用它顺带提供跨机器锁，不需要额外的基础设施成本。**如果会有多台机器针对同一个案例并发运行
`seclogx ingest`——即便你只关心共享的 S3
存储，并不关心分布式解析——也请同时配置 `SECLOGX_BROKER_URL`**，这样这里的加锁机制才能真正做到跨机器安全。

## 实现原理（供感兴趣的读者，或排查问题时参考）

- `src/seclogx/distributed/config.py` —— `ClusterConfig`，从上面这些环境变量解析而来。
- `src/seclogx/distributed/storage.py` —— `StorageBackend`
  （`LocalStorageBackend`/`S3StorageBackend`），被 `CaseDB`
  以及两条导入流水线 flatten 步骤中每一个涉及 `lake/` 的操作所使用。
- `src/seclogx/distributed/queue.py` —— `JobQueue`
  （`LocalJobQueue`/`RQJobQueue`），被两条导入流水线的编排逻辑，以及
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
