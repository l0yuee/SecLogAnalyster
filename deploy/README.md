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

- **Ingest parsing** -- one task per discovered file (EVTX staging,
  Scheduled Task/web/Exchange/syslog/auditd/journal parsing), enqueued
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

Single-machine use (the default -- no env vars set) is completely
unaffected: no broker, no S3, no extra dependencies required.

## Docker Compose quickstart

From the repo root:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

This starts Redis (the broker), MinIO (S3-compatible object storage
standing in for a real bucket, with a `seclogx-cases` bucket created
automatically), and two `seclogx worker` replicas.

Scale the worker fleet:

```bash
docker compose -f deploy/docker-compose.yml up --scale worker=4
```

To act as the coordinator against this stack, export the same env vars
the `worker` service uses (see the table below) and run `seclogx`
normally from the host -- or run it inside the stack's network via:

```bash
docker compose -f deploy/docker-compose.yml run --rm \
  -e SECLOGX_BROKER_URL=redis://redis:6379/0 \
  -e SECLOGX_STORAGE_BACKEND=s3 \
  -e SECLOGX_S3_BUCKET=seclogx-cases \
  -e SECLOGX_S3_ENDPOINT_URL=http://minio:9000 \
  -e SECLOGX_S3_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=seclogx-demo \
  -e AWS_SECRET_ACCESS_KEY=seclogx-demo-secret \
  worker case init incident42

docker compose -f deploy/docker-compose.yml run --rm \
  -e SECLOGX_BROKER_URL=redis://redis:6379/0 \
  -e SECLOGX_STORAGE_BACKEND=s3 \
  -e SECLOGX_S3_BUCKET=seclogx-cases \
  -e SECLOGX_S3_ENDPOINT_URL=http://minio:9000 \
  -e SECLOGX_S3_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=seclogx-demo \
  -e AWS_SECRET_ACCESS_KEY=seclogx-demo-secret \
  worker ingest incident42 --source /path/to/evidence:HOST01

docker compose -f deploy/docker-compose.yml run --rm \
  -e SECLOGX_BROKER_URL=redis://redis:6379/0 \
  worker cluster status

docker compose -f deploy/docker-compose.yml run --rm \
  -e SECLOGX_BROKER_URL=redis://redis:6379/0 \
  -e SECLOGX_STORAGE_BACKEND=s3 \
  -e SECLOGX_S3_BUCKET=seclogx-cases \
  -e SECLOGX_S3_ENDPOINT_URL=http://minio:9000 \
  -e SECLOGX_S3_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=seclogx-demo \
  -e AWS_SECRET_ACCESS_KEY=seclogx-demo-secret \
  worker hunt incident42
```

(The `worker` service's image is reused here purely because it already
has `seclogx` installed -- the command overrides its default `worker`
role. Mounting your actual evidence directory into the container is left
to you, e.g. via `-v /host/evidence:/evidence:ro` and pointing `--source`
at `/evidence:HOST01`.)

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

Scale with `kubectl scale deployment/seclogx-worker --replicas=N` or by
editing `replicas:` in the manifest.

A coordinator can be anywhere with network access to the same broker and
bucket -- a laptop, a CI job, a jump host -- by exporting the same env
vars as the worker Deployment and running `seclogx` normally.

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
