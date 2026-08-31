from __future__ import annotations

import typer

from ..distributed.config import ClusterConfig
from ..distributed.queue import HUNT_QUEUE_NAME, INGEST_QUEUE_NAME
from ..errors import ClusterConfigError
from ._render import console


def worker_command(
    burst: bool = typer.Option(
        False, "--burst", help="Process whatever's queued right now, then exit (useful for testing/CI)"
    ),
) -> None:
    """Run a distributed-ingest/hunt worker, consuming tasks enqueued by
    `seclogx ingest`/`seclogx hunt` when SECLOGX_BROKER_URL is set. One or
    more of these, on one or more machines, is what a cluster deployment
    actually is -- see docs/guides/10_distributed_deployment.md."""
    cluster_config = ClusterConfig.from_env()
    if not cluster_config.is_distributed:
        console.print(
            "[red]SECLOGX_BROKER_URL is not set -- nothing to consume. "
            "`seclogx worker` only makes sense once cluster mode is configured; "
            "see docs/guides/10_distributed_deployment.md.[/red]"
        )
        raise typer.Exit(1)

    try:
        import redis
        from rq import Worker
    except ImportError as e:
        raise ClusterConfigError("`seclogx worker` requires the 'cluster' extra: pip install 'seclogx[cluster]'") from e

    conn = redis.from_url(cluster_config.broker_url)
    console.print(
        f"[green]seclogx worker listening on '{INGEST_QUEUE_NAME}', '{HUNT_QUEUE_NAME}' "
        f"({cluster_config.broker_url})[/green]"
    )
    worker = Worker([INGEST_QUEUE_NAME, HUNT_QUEUE_NAME], connection=conn)
    worker.work(burst=burst)
