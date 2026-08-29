from __future__ import annotations

import typer

from .. import __version__
from .case_cmds import case_app
from .hunt_cmd import hunt_command
from .ingest_cmd import ingest_command
from .query_cmd import channels_command, query_command, sources_command, summary_command, table_command
from .rules_cmd import rules_app
from .search_cmd import fields_command, search_command
from .tasks_cmd import tasks_command
from .timeline_cmd import timeline_command

app = typer.Typer(
    help="seclogx -- fast, pandas-friendly threat hunting over Windows Event Log, Scheduled Tasks, "
    "IIS/nginx/Apache/Tomcat access & error logs, and Exchange logs. No SQL required -- see `search`.",
    no_args_is_help=True,
)
app.add_typer(case_app, name="case")
app.add_typer(rules_app, name="rules")
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


@app.command("version")
def version() -> None:
    typer.echo(__version__)


if __name__ == "__main__":
    app()
