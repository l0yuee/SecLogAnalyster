from __future__ import annotations

import typer

from ..distributed.config import ClusterConfig
from ..distributed.queue import HUNT_QUEUE_NAME, INGEST_QUEUE_NAME
from ..errors import ClusterConfigError
from ._render import console

cluster_app = typer.Typer(help="Distributed/cluster-mode configuration and status")


@cluster_app.command("config")
def config() -> None:
    """Print the cluster configuration resolved from the environment
    (SECLOGX_STORAGE_BACKEND/SECLOGX_S3_*/SECLOGX_BROKER_URL) -- useful
    for confirming a worker/coordinator picked up the settings you meant
    it to. Never prints credentials -- those never pass through
    ClusterConfig to begin with; see its docstring."""
    console.print_json(data=ClusterConfig.from_env().redacted())


@cluster_app.command("status")
def status() -> None:
    """Queue depth and live `seclogx worker` processes for the configured
    broker. Requires SECLOGX_BROKER_URL -- with no broker configured,
    there's no cluster to report on (ingest/hunt just run locally)."""
    cluster_config = ClusterConfig.from_env()
    if not cluster_config.is_distributed:
        console.print("[yellow]no SECLOGX_BROKER_URL configured -- ingest/hunt run locally, not distributed[/yellow]")
        return

    try:
        import redis
        from rq import Queue, Worker
    except ImportError as e:
        raise ClusterConfigError("`seclogx cluster status` requires the 'cluster' extra: pip install 'seclogx[cluster]'") from e

    conn = redis.from_url(cluster_config.broker_url)
    workers = Worker.all(connection=conn)
    console.print(f"broker: {cluster_config.broker_url}")
    console.print(f"workers online: {len(workers)}")
    for w in workers:
        console.print(f"  {w.name} -- state={w.get_state()}, queues={[q.name for q in w.queues]}")
    for name in (INGEST_QUEUE_NAME, HUNT_QUEUE_NAME):
        q = Queue(name, connection=conn)
        console.print(f"queue '{name}': {len(q)} pending job(s)")
