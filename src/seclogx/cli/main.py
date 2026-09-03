from __future__ import annotations

import sys

import typer

from .. import __version__
from .auth_cmd import auth_command
from .case_cmds import case_app
from .cluster_cmds import cluster_app
from .hunt_cmd import hunt_command
from .ingest_cmd import ingest_command
from .query_cmd import channels_command, query_command, sources_command, summary_command, table_command
from .registry_cmd import registry_command
from .rules_cmd import rules_app
from .search_cmd import fields_command, search_command
from .tasks_cmd import tasks_command
from .timeline_cmd import timeline_command
from .worker_cmd import worker_command


def _force_utf8_streams() -> None:
    """Force UTF-8 on stdout/stderr, with a can't-fail fallback for
    anything still unencodable. Without this, output encoding follows
    the OS locale (e.g. GBK/cp936 on Chinese-locale Windows), and
    printing forensic content containing characters outside that
    codepage -- rule titles, matched field values, anything sourced from
    evidence rather than typed by us -- raises UnicodeEncodeError and
    kills the command outright. Mirrors the same "never crash on
    unexpected encoding" guarantee ingest already provides on the read
    side (see ingest/logsources/sniff.py)."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


_force_utf8_streams()

app = typer.Typer(
    help="seclogx -- fast, pandas-friendly threat hunting over Windows Event Log, Scheduled Tasks, "
    "IIS/nginx/Apache/Tomcat access & error logs, Exchange logs, and Linux syslog/auditd/systemd "
    "journal logs. No SQL required -- see `search`. Runs single-machine by default; set "
    "SECLOGX_BROKER_URL for distributed ingest/hunt -- see `cluster`/`worker`.",
    no_args_is_help=True,
)
app.add_typer(case_app, name="case")
app.add_typer(rules_app, name="rules")
app.add_typer(cluster_app, name="cluster")
app.command("ingest")(ingest_command)
app.command("query")(query_command)
app.command("summary")(summary_command)
app.command("channels")(channels_command)
app.command("sources")(sources_command)
app.command("table")(table_command)
app.command("search")(search_command)
app.command("fields")(fields_command)
app.command("hunt")(hunt_command)
app.command("timeline")(timeline_command)
app.command("tasks")(tasks_command)
app.command("auth")(auth_command)
app.command("registry")(registry_command)
app.command("worker")(worker_command)


@app.command("version")
def version() -> None:
    typer.echo(__version__)


if __name__ == "__main__":
    app()
