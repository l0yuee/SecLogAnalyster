# Deploying seclogx in cluster mode

This directory holds the deployment artifacts for seclogx's distributed
mode: a Docker Compose stack for a runnable single-machine demo, and a
Kubernetes Deployment for running the worker fleet on a real cluster. For
the fuller narrative guide (design, env var reference, what's distributed
and what isn't), see
[`docs/guides/10_distributed_deployment.md`](../docs/guides/10_distributed_deployment.md).
This README is the deploy-artifact-specific companion to that guide.

## What actually gets distributed

Cluster mode fans out two things across `seclogx worker` processes:

- **Ingest parsing** -- one task per supported source file (EVTX and
  auxiliary log/artifact parsing), enqueued
  onto a Redis-backed job queue instead of a local process pool.
- **Sigma hunting** -- the bundled/custom rule set is split into chunks,
  each evaluated by a worker against the case's shared Parquet lake.

**What is deliberately not distributed: query execution itself.** DuckDB
remains the query engine, and every query or Sigma rule still runs on
exactly one process. "Distributed" here means job-level fan-out over a
Parquet lake that lives on shared object storage and that every
worker/coordinator can reach -- not a distributed SQL query planner. A
single `seclogx search`/`seclogx query` call always executes on whichever
one machine issues it.

Ingest workers write staging shards to a shared filesystem. The coordinator
waits for staging, then reads bounded groups and performs the Parquet
conversion itself. S3 shares the lake; it does not share evidence or staging
and does not provide a parse/convert pipeline with disk-space backpressure.
The source paths must be readable, and staging paths writable, at the same
absolute locations in the coordinator and every ingest worker.

Single-machine use (the default -- no env vars set) is completely
unaffected: no broker, no S3, no extra dependencies required.

## Docker Compose quickstart

The root `.dockerignore` excludes local data and generated artifacts from
the build context. Supply evidence and case directories through volumes;
they are not baked into the image.

The base Compose file starts services but declares no evidence or case
mounts. Add them before ingest. Create a local
`deploy/docker-compose.shared.yml` override such as:

```yaml
services:
  worker:
    volumes:
      - type: bind
        source: ${SECLOGX_EVIDENCE_DIR}
        target: /evidence
        read_only: true
      - type: bind
        source: ${SECLOGX_CASES_DIR}
        target: /shared/cases
```

Use existing absolute host directories. From a Bash shell at the repo root:

```bash
export SECLOGX_EVIDENCE_DIR=/absolute/host/evidence
export SECLOGX_CASES_DIR=/absolute/host/cases
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.shared.yml up --build
```

This starts Redis (the broker), MinIO (S3-compatible object storage
standing in for a real bucket, with a `seclogx-cases` bucket created
automatically), and two `seclogx worker` replicas.

Scale the worker fleet:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.shared.yml up --scale worker=4
```

Use the same service image as a coordinator so the environment and mount
paths match. It inherits the service's broker/S3 settings and both mounts:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.shared.yml run --rm \
  worker case init incident42 --case-root /shared/cases

docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.shared.yml run --rm \
  worker ingest incident42 --case-root /shared/cases --source /evidence:HOST01 \
  --memory-limit 2GB --duckdb-threads 2 --staging-format auto

docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.shared.yml run --rm \
  worker cluster status

docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.shared.yml run --rm \
  worker hunt incident42 --case-root /shared/cases
```

Here `case init`, `ingest`, `cluster status` and `hunt` override the image's
default worker command. They do not start an extra queue consumer. Mount
custom hunt rules at identical paths too; workers load rule files locally.
Use consistent host labels when assigning evidence to `--source`.

A host-side coordinator additionally needs the same absolute source and
staging paths as the containers and host-reachable endpoints (for this demo,
`localhost:6379` and `http://localhost:9000`, rather than Compose service
names). A Windows host path does not automatically become `/evidence` inside
a Linux worker. For local Python/CLI work, activate `python314`; the supplied
Linux image uses the interpreter declared in `deploy/Dockerfile`.

Every credential in `docker-compose.yml` is a demo-only placeholder --
see the comments in that file.

## Kubernetes

```bash
kubectl apply -f deploy/k8s/worker-deployment.yaml
```

This deploys **only** the `seclogx worker` fleet. Bring your own managed
Redis (e.g. ElastiCache) and S3-compatible bucket -- this manifest
intentionally does not include Redis/MinIO manifests. Before applying:

1. Build `deploy/Dockerfile` and push it to a registry your cluster can
   pull from; update the Deployment's `image:` field.
2. Fill in `seclogx-cluster-config` (bucket, region, endpoint) with real,
   non-secret values.
3. Replace `seclogx-cluster-secrets`' placeholder values with real ones,
   ideally generated via your cluster's actual secret-management tooling
   (sealed-secrets, external-secrets, Vault, your cloud provider's
   secret manager, ...) rather than editing the manifest directly.
4. Add evidence and writable shared case/staging volumes to every worker
   pod and the coordinator. Use a storage class and access mode that permit
   the required multi-pod access, with identical mount paths. The supplied
   manifest has no volumes and is not sufficient for distributed ingest by
   itself. Mount any custom rule directory used for hunts as well.
5. Size pod requests/limits and coordinator resources for the actual formats
   and concurrency. The sample worker limit is 1 GiB; it is a deployment
   placeholder, not a guarantee that every parser or hunt fits that budget.

Scale with `kubectl scale deployment/seclogx-worker --replicas=N` or by
editing `replicas:` in the manifest.

A coordinator needs network access to the broker/bucket, matching filesystem
mounts and enough resources for local Parquet conversion. Environment
variables alone are insufficient.

## Resource and failure boundaries

- Keep coordinator and worker package versions aligned. Auxiliary staging
  defaults to `auto`: Arrow IPC/ZSTD for source files at least 16 MiB and
  gzip NDJSON for smaller files. `--staging-format arrow|ndjson` forces a
  format; EVTX still uses NDJSON.
- `--staging-chunk-bytes` reaches parsing workers. `--flatten-batch-bytes`,
  `--memory-limit` and `--duckdb-threads` govern coordinator conversions.
  `--workers` controls local multiprocessing, not RQ worker replica count.
  DuckDB's limit is not an overall RSS or pod-memory limit.
- Source, shared staging, final Parquet and temporary files all need space.
  Staging is removed after successful conversion by default; `--keep-staging`
  retains intermediates for diagnosis. Neither mode removes peak staging
  usage. Source evidence is never deleted. Automatic direct output is local
  only; distributed and object-storage configurations select staging.
- The RQ adapter submits all task descriptions and does not set explicit
  job timeout/retry options. It relies on installed RQ defaults, and seclogx
  exposes no distributed timeout override. Check long-file suitability
  before dispatch. Failed tasks raise errors; automatic resume is absent.
- Use one ingest writer per case. The metadata lock protects `case.json`,
  while conversion locking is local to one coordinator process. Neither
  makes lake writes transactional or queries atomic snapshots. Retrying a
  source can duplicate records; failed conversions can leave partial lake
  output. Use a fresh case when rebuilding the same evidence.
- Linux containers are the supplied RQ deployment path. Local Windows
  ingest support does not imply native Windows RQ worker compatibility.

## Environment variable reference

| Variable | Used by | Default | Meaning |
|---|---|---|---|
| `SECLOGX_STORAGE_BACKEND` | coordinator + worker | `local` | `local` (default, no cluster storage) or `s3` (Parquet lake lives on shared object storage). |
| `SECLOGX_S3_BUCKET` | coordinator + worker | none | Bucket holding every case's lake, when `SECLOGX_STORAGE_BACKEND=s3`. |
| `SECLOGX_S3_ENDPOINT_URL` | coordinator + worker | none (real AWS S3) | Set for MinIO or any other S3-compatible endpoint; leave unset for real AWS S3. |
| `SECLOGX_S3_REGION` | coordinator + worker | none | S3 region. |
| `SECLOGX_BROKER_URL` | coordinator + worker | none | A `redis://...` URL. Its presence is what turns on distributed ingest/hunt fan-out -- unset means every command runs exactly as it does on a single machine. |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_DEFAULT_REGION` | coordinator + worker | none | Standard boto3 credential chain -- seclogx never reads S3 credentials through a `SECLOGX_*` variable of its own. |

The coordinator (wherever `seclogx ingest`/`seclogx hunt`/`seclogx
search`/etc. is run) and every `seclogx worker` process must be pointed
at the *same* broker and bucket to participate in the same cluster --
there is no separate coordinator-specific configuration.
