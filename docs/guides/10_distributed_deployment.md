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

1. **Ingest.** Both ingest pipelines (`.evtx`, and the non-EVTX families --
   Scheduled Tasks/web logs/Exchange/syslog/auditd/journal) dispatch their
   per-file parsing tasks through a job queue instead of a local process
   pool. Locally, that queue is just today's `ProcessPoolExecutor`
   behavior. Once a broker is configured, the same tasks are enqueued for
   any number of `seclogx worker` processes -- anywhere -- to pick up.
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
pip install -e ".[cluster]"
```

This installs `redis`, `rq` (the job queue), and `boto3` (S3 metadata
operations) -- none of which are required, or imported, for ordinary
single-machine use. The Parquet read/write against S3 itself goes through
DuckDB's own `httpfs` extension (installed automatically by DuckDB at
connection time), not a separate Python dependency.

## Turning it on: environment variables

Activation is purely environment-variable driven -- there are no new CLI
flags on any existing command. Every `seclogx` command (and every `Case`
method, for library use) resolves its configuration from the environment
each time it runs, so exporting these variables is the entire "how do I
turn cluster mode on" story:

| Variable | Default | Meaning |
|---|---|---|
| `SECLOGX_BROKER_URL` | unset | A `redis://...` URL. Its mere presence is what turns on distributed ingest/hunt dispatch -- unset, everything runs exactly as it always has, locally. |
| `SECLOGX_STORAGE_BACKEND` | `local` | `local` (the case's `lake/` directory on disk, as always) or `s3` (the lake lives on S3-compatible object storage instead). |
| `SECLOGX_S3_BUCKET` | unset | Required when `SECLOGX_STORAGE_BACKEND=s3`. The lake is stored under `s3://<bucket>/<case name>/lake/...` -- keyed by case name, so one bucket can hold many cases. |
| `SECLOGX_S3_ENDPOINT_URL` | unset | For MinIO or another S3-compatible endpoint instead of real AWS S3. |
| `SECLOGX_S3_REGION` | unset | Passed through to both boto3 and DuckDB's `httpfs`. |

S3 **credentials are never read by seclogx's own configuration** --
they go through boto3's standard credential chain (`AWS_ACCESS_KEY_ID`
/ `AWS_SECRET_ACCESS_KEY` / `AWS_DEFAULT_REGION` env vars, an instance
profile, `~/.aws/credentials`, ...), exactly like any other boto3-based
tool. Nothing secret is ever read, stored, or logged by seclogx itself.

Storage and the job queue are independent switches -- you can point at S3
without a broker (single-machine ingest, shared read access for multiple
analysts), or use a broker with the default local lake (distributed
ingest/hunt, single-machine query). Most real cluster deployments use
both together, since that's what actually lets multiple worker machines
write into the same lake concurrently.

`case.json` and `staging/` deliberately stay on whatever local/NFS-mounted
directory the case's `--case-root` points at, in every mode. They're
small, coordinator-only ingest bookkeeping -- not the thing that needs to
scale, or that distributed workers need direct access to (see "How it
actually works" below for why).

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

It blocks, listening on the ingest and hunt queues, until killed (or use
`--burst` to drain whatever's queued right now and exit -- useful for
scripted/CI verification). Run as many of these as you want, on as many
machines as you want, all pointed at the same broker and storage.

## The coordinator: `seclogx ingest` / `seclogx hunt` / `seclogx cluster status`

There's no separate "coordinator" binary -- it's the same `seclogx` CLI
you always run, from wherever an analyst normally works (a laptop, a jump
host, a CI job), with the same environment variables exported as the
workers. Once `SECLOGX_BROKER_URL` is set, `seclogx ingest`/`seclogx hunt`
enqueue their work instead of running a local process pool, and wait for
the results.

```bash
seclogx case init incident42 --case-root /shared/cases   # or an S3-backed lake, see above
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01
seclogx hunt incident42
```

Two more commands are cluster-mode-specific:

- **`seclogx cluster config`** -- prints the resolved configuration
  (nothing secret in it, since credentials never pass through
  `ClusterConfig` to begin with). Useful for confirming a machine actually
  picked up the environment variables you meant it to.
- **`seclogx cluster status`** -- with a broker configured, reports how
  many `seclogx worker` processes are currently online and how many jobs
  are queued on each of the two queues. Without a broker configured, it
  says so and exits cleanly (there's no cluster to report on).

## Docker Compose and Kubernetes

`deploy/docker-compose.yml` is a runnable single-machine cluster demo
(Redis + MinIO + a scalable `worker` service) -- see `deploy/README.md`
for the walkthrough. `deploy/k8s/worker-deployment.yaml` is a Kubernetes
`Deployment` for the worker fleet (deliberately scoped to just the
workers -- bring your own managed Redis and S3-compatible bucket, the
same way most real deployments already have one). Both are described in
full in `deploy/README.md`; this guide is the narrative companion, not a
duplicate of that reference.

## Locking: why S3-backed/multi-machine setups want a broker even for storage alone

`case.json`'s read-modify-write (ingest bookkeeping: hosts seen, run
history) is always lock-protected now -- this closes a real, pre-existing
gap (two `seclogx ingest` runs racing against the same case used to be
able to silently lose one run's bookkeeping), not just a cluster-mode
concern. On a single machine, or a case directory on ordinary local disk,
this uses a plain, dependency-free file lock. Once a broker is
configured, a Redis-based lock is used instead -- a POSIX file lock over
a network filesystem is not a reliable way to coordinate genuinely
separate machines, whereas the same Redis a distributed setup already
needs for its job queue gives a proper cross-machine lock at no extra
infrastructure cost. **If multiple machines will run `seclogx ingest`
against the same case concurrently -- even if you only care about shared
S3 storage, not distributed parsing -- configure `SECLOGX_BROKER_URL`
too**, so this locking is actually cross-machine-safe.

## How it actually works (for the curious, or when something needs debugging)

- `src/seclogx/distributed/config.py` -- `ClusterConfig`, resolved from
  the environment variables above.
- `src/seclogx/distributed/storage.py` -- `StorageBackend`
  (`LocalStorageBackend`/`S3StorageBackend`), used by `CaseDB` and by the
  flatten step of both ingest pipelines for every operation that touches
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
