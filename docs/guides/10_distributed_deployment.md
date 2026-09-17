# 10. Distributed deployment

**Language: English | [中文](10_distributed_deployment.zh-CN.md)**

**[Guide index](../index.md)** -- [01. Getting started](01_getting_started.md) | [02. Log types & schema](02_log_types_and_schema.md) | [03. Querying & search](03_querying_and_search.md) | [04. Threat hunting](04_threat_hunting.md) | [05. CLI reference](05_cli_reference.md) | [06. Python API](06_python_api.md) | [07. Recipes](07_recipes.md) | [08. Performance & scale](08_performance_and_scale.md) | [09. FAQ & limitations](09_faq_and_limitations.md) | 10. Distributed deployment

---

seclogx runs single-machine by default, with zero setup -- everything in
the rest of this documentation applies unchanged whether or not you ever
read this page. This guide covers the **opt-in** cluster mode: a job
queue that fans ingest and Sigma-hunt work out across `seclogx worker`
processes (on one machine or many), plus a storage backend that lets the
Parquet lake live on S3-compatible object storage instead of local disk.

## What cluster mode actually distributes -- and what it doesn't

Turning cluster mode on changes two things:

1. **Ingest.** Both ingest paths (`.evtx`, and the non-EVTX families --
   Scheduled Tasks/web logs/Exchange/syslog/auditd/journal/database/QCloud/registry) dispatch their
   per-file parsing tasks through a job queue instead of a local process
   pool. Locally, that queue is just today's `ProcessPoolExecutor`
   behavior. Once a broker is configured, the same tasks are enqueued for
   `seclogx worker` processes with access to the source and staging paths.
   Workers parse and write staging shards; the coordinator reads their
   manifests and performs the bounded DuckDB-to-Parquet conversions.
2. **Sigma hunting.** `seclogx hunt` fans independent rules out across
   workers the same way, then merges the matches back. Every rule's query
   is already independent of every other rule's, so this is a pure
   parallel map -- not a different implementation of rule evaluation than
   the sequential path uses.

**What does *not* change: there is no distributed SQL query engine.**
DuckDB is still the query engine, and any single query or Sigma rule
still executes on exactly one process, against the Parquet lake, exactly
as described in [03. Querying & search](03_querying_and_search.md) and
`docs/architecture.md`. "Distributed" here means *job-level* parallelism
-- many independent DuckDB processes/queries running concurrently against
one shared lake -- never intra-query distributed execution. Cluster mode
doesn't make one `seclogx query`/`seclogx search` call faster; it lets
more independent ingest files or hunt rules run at once, and lets more
than one analyst's machine query the same shared lake concurrently.

So cluster mode helps when: an ingest batch has enough files that
spreading the parsing across several machines actually saves wall-clock
time; a Sigma rule set is large enough that evaluating it rule-by-rule on
one machine is the bottleneck; or multiple analysts want to work against
one case's lake without each needing their own local copy of it. It
doesn't help a single slow query or a single small case -- that's still
exactly the single-machine DuckDB path this project has always used.

## Installing it

```bash
conda activate python314
python -m pip install -e ".[cluster]"
```

Use this environment for local Python, CLI and Notebook work. The supplied
Linux container image has its own interpreter and dependencies; run matching
seclogx versions on the coordinator and workers.

This installs `redis`, `rq` (the job queue), and `boto3` (S3 metadata
operations) -- none of which are required, or imported, for ordinary
single-machine use. The Parquet read/write against S3 itself goes through
DuckDB's own `httpfs` extension (installed automatically by DuckDB at
connection time), not a separate Python dependency.

## Turning it on: environment variables

Cluster activation uses environment variables. Set them before running the
CLI or creating/opening a `Case`; a `Case` keeps its resolved configuration.
Changing the environment does not reconfigure an already-open object.

| Variable | Default | Meaning |
|---|---|---|
| `SECLOGX_BROKER_URL` | unset | A `redis://...` URL. Its mere presence is what turns on distributed ingest/hunt dispatch -- unset, everything runs exactly as it always has, locally. |
| `SECLOGX_STORAGE_BACKEND` | `local` | `local` (the case's `lake/` directory on disk, as always) or `s3` (the lake lives on S3-compatible object storage instead). |
| `SECLOGX_S3_BUCKET` | unset | Required when `SECLOGX_STORAGE_BACKEND=s3`. The lake is stored under `s3://<bucket>/<case name>/lake/...` -- keyed by case name, so one bucket can hold many cases. |
| `SECLOGX_S3_ENDPOINT_URL` | unset | For MinIO or another S3-compatible endpoint instead of real AWS S3. |
| `SECLOGX_S3_REGION` | unset | Passed through to both boto3 and DuckDB's `httpfs`. |

S3 credentials use boto3's standard credential chain (`AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, instance profiles, `~/.aws/credentials`, etc.).
`ClusterConfig` does not store AWS credentials; the storage backend resolves
them through boto3 and applies them to the DuckDB connection for S3 access.

Storage and the job queue are independent switches -- you can point at S3
without a broker (single-machine ingest, shared read access for multiple
analysts), or use a broker with a filesystem lake that all hunt workers can
read at the same path. S3 shares the Parquet lake; it does not transport
source files or staging shards, and it does not distribute conversion work.

`case.json`, `staging/` and `staging_aux/` remain under `--case-root` in
every mode. **Source paths and writable staging paths must be shared at
identical absolute paths between the coordinator and ingest workers.**
Jobs carry file/path descriptions and options; they do not upload evidence
or return file contents through Redis. Mounting a path only in the
coordinator container is insufficient. Cross-platform path spellings also
need to match, so a Linux container coordinator is usually simpler when
the workers are Linux containers.

Staging holds the parsed dataset and can be large. Each ingest path finishes
staging before converting groups, with no disk-space backpressure. Auxiliary
`auto` staging chooses Arrow IPC/ZSTD for source files at least 16 MiB and
gzip NDJSON for smaller ones; EVTX retains NDJSON. Budget shared staging,
Parquet and temporary space, even when `keep_staging=False`: deletion occurs
after successful conversion. Distributed hunts also need the configured
case path and custom rule files accessible at the paths sent in their jobs.

## `seclogx worker`

Run this on any machine (or in any container) that should process
distributed ingest/hunt tasks:

```bash
export SECLOGX_BROKER_URL=redis://<broker-host>:6379/0
export SECLOGX_STORAGE_BACKEND=s3
export SECLOGX_S3_BUCKET=my-seclogx-cases
export SECLOGX_S3_ENDPOINT_URL=http://<minio-or-s3-endpoint>
export SECLOGX_S3_REGION=us-east-1
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

seclogx worker
```

It blocks, listening on the ingest and hunt queues, until stopped (or use
`--burst` to drain whatever's queued right now and exit -- useful for
scripted/CI verification). Run as many of these as you want, on as many
machines as your memory, shared storage and broker can support. All must
use the same broker/storage configuration and required filesystem mounts.
Use the provided Linux container deployment for these RQ workers; local
Windows multiprocessing support does not establish native Windows RQ support.

## The coordinator: `seclogx ingest` / `seclogx hunt` / `seclogx cluster status`

There's no separate "coordinator" binary -- it's the same `seclogx` CLI
you always run, from wherever an analyst normally works (a laptop, a jump
host, a CI job), with the same environment variables exported as the
workers, with the required shared paths mounted. Once `SECLOGX_BROKER_URL`
is set, per-file parsing and hunt tasks use Redis/RQ. The ingest coordinator
waits for staging and then converts it; it still needs CPU, memory and I/O.

```bash
seclogx case init incident42 --case-root /shared/cases
seclogx ingest incident42 --case-root /shared/cases \
  --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01 \
  --memory-limit 2GB --duckdb-threads 2 --staging-format auto
seclogx hunt incident42 --case-root /shared/cases
```

The source paths above must be readable by every ingest worker; the case
path must provide shared writable staging. `--staging-chunk-bytes` controls
worker shard targets, while `--flatten-batch-bytes`, `--memory-limit` and
`--duckdb-threads` control conversion on the coordinator. `--workers` is a
local process-pool budget, not a limit on Redis worker replicas. DuckDB's
memory limit is not a process-tree cap. `CONVERSION_LOCK` serializes only
conversions in one coordinator process.

The RQ adapter currently enqueues without explicit per-job timeout or retry
settings, relying on the installed RQ defaults. The seclogx CLI does not
expose a distributed-job timeout override. Check this constraint before
dispatching long-running files; failed jobs are reported, not automatically
resumed. Local pending-task bounds do not apply to the Redis queue, which
currently submits the whole task list.

Two more commands are cluster-mode-specific:

- **`seclogx cluster config`** -- prints the resolved configuration
  (AWS credentials are not part of `ClusterConfig`; a broker URL may itself
  contain credentials). Useful for confirming a machine actually
  picked up the environment variables you meant it to.
- **`seclogx cluster status`** -- with a broker configured, reports how
  many `seclogx worker` processes are currently online and how many jobs
  are queued on each of the two queues. Without a broker configured, it
  says so and exits cleanly (there's no cluster to report on).

## Docker Compose and Kubernetes

`deploy/docker-compose.yml` provides a single-machine cluster service demo
(Redis + MinIO + a scalable `worker` service) -- see `deploy/README.md`
for the required shared-mount setup before ingest. `deploy/k8s/worker-deployment.yaml` is a Kubernetes
`Deployment` for the worker fleet (deliberately scoped to just the
workers -- bring your own managed Redis and S3-compatible bucket, the
same way most real deployments already have one). Both are described in
full in `deploy/README.md`; this guide is the narrative companion, not a
duplicate of that reference.

## Locking and concurrent writers

Updates to `case.json` use a local file lock, or a Redis lock when a broker
is configured. This protects metadata read-modify-write, not the full
ingest operation. It does not provide cross-run deduplication, rollback,
atomic lake publication or consistent query snapshots. Coordinate one
ingest writer per case and wait for completion before analysis. Separate
coordinators and background jobs do not share `CONVERSION_LOCK`; adding a
broker does not make their writes transactional. Redis lock identity also
depends on the resolved case path, reinforcing the need for consistent mounts.

## How it actually works (for the curious, or when something needs debugging)

- `src/seclogx/distributed/config.py` -- `ClusterConfig`, resolved from
  the environment variables above.
- `src/seclogx/distributed/storage.py` -- `StorageBackend`
  (`LocalStorageBackend`/`S3StorageBackend`), used by `CaseDB` and by the
  flatten step of both ingest paths for every operation that touches
  `lake/`.
- `src/seclogx/distributed/queue.py` -- `JobQueue`
  (`LocalJobQueue`/`RQJobQueue`), used by both ingest orchestrators and by
  `detect/hunt.py`'s distributed-fan-out path.
- `src/seclogx/distributed/locking.py` -- the `case.json` lock described
  above.
- `src/seclogx/cli/worker_cmd.py` / `src/seclogx/cli/cluster_cmds.py` --
  `seclogx worker` / `seclogx cluster status` / `seclogx cluster config`.

See `docs/architecture.md`'s "Why not Dask / a distributed engine"
section for the design reasoning, and `docs/known_limitations.md`'s
"Scale" section for the precise, current boundaries of what this does and
doesn't cover.

Next: back to [01. Getting started](01_getting_started.md), or
[09. FAQ & limitations](09_faq_and_limitations.md) for the full
known-limitations pointer.
