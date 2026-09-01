"""The `Case` class -- the main entry point for both the CLI and library use.

    from seclogx import Case
    c = Case.open("incident42")
    c.hunt().matches
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pandas as pd

from .config import DEFAULT_CASE_ROOT
from .distributed.config import ClusterConfig
from .distributed.locking import get_case_lock
from .distributed.storage import get_storage_backend
from .errors import CaseAlreadyExistsError, CaseNotFoundError, NoSourcesFoundError
from .detect import HuntResults, run_hunt
from .ingest import run_ingest, run_aux_ingest
from .ingest.common import parse_source_arg
from .ingest.evtx.manifest import IngestReport
from .ingest.logsources.parsers.scheduled_tasks import SUSPICIOUS_ACTION_PATH_HINTS, SUSPICIOUS_COMMAND_HINTS
from .ingest.logsources.parsers.task_baseline import classify_against_baseline
from .ingest.logsources.parsers.syslog import extract_auth_events
from .query import DEFAULT_CHUNKSIZE, CaseDB
from .search import Match, conditions_from_dicts, discover_fields
from .search import search as _search
from .search import search_chunks as _search_chunks
from .search import search_to_csv as _search_to_csv
from .timeline import build_timeline, build_timeline_chunks


def _hosts_from_lake(case_dir: Path, cluster_config: ClusterConfig | None = None) -> set[str]:
    """Hosts present in the Parquet lake, read directly off the Hive
    `host=<value>` partition folder names (percent-decoded) -- covers every
    table (events, web_logs, scheduled_tasks, ...) without needing a DB
    connection. Goes through the configured StorageBackend so this works
    whether the lake is local or on shared object storage (see
    distributed/storage.py)."""
    backend = get_storage_backend(cluster_config or ClusterConfig.from_env())
    lake_location = backend.lake_location(case_dir)
    hosts: set[str] = set()
    if not backend.exists(lake_location):
        return hosts
    for table_name in backend.table_dirs(lake_location):
        table_location = backend.join(lake_location, table_name)
        hosts.update(backend.host_partitions(table_location))
    return hosts


class Case:
    def __init__(self, name: str, case_dir: Path, cluster_config: ClusterConfig | None = None):
        self.name = name
        self.case_dir = Path(case_dir)
        self.cluster_config = cluster_config or ClusterConfig.from_env()
        self._db: CaseDB | None = None

    # -- lifecycle --------------------------------------------------------
    @classmethod
    def create(
        cls, name: str, case_root: Path = DEFAULT_CASE_ROOT, cluster_config: ClusterConfig | None = None
    ) -> "Case":
        case_dir = Path(case_root) / name
        if case_dir.exists():
            raise CaseAlreadyExistsError(f"case '{name}' already exists at {case_dir}")
        case_dir.mkdir(parents=True)
        meta = {
            "case_id": str(uuid.uuid4()),
            "name": name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hosts": [],
            "ingest_runs": [],
        }
        (case_dir / "case.json").write_text(json.dumps(meta, indent=2))
        return cls(name, case_dir, cluster_config=cluster_config)

    @classmethod
    def open(
        cls, name: str, case_root: Path = DEFAULT_CASE_ROOT, cluster_config: ClusterConfig | None = None
    ) -> "Case":
        case_dir = Path(case_root) / name
        if not (case_dir / "case.json").exists():
            raise CaseNotFoundError(f"case '{name}' not found under {case_root}")
        return cls(name, case_dir, cluster_config=cluster_config)

    @classmethod
    def list_cases(cls, case_root: Path = DEFAULT_CASE_ROOT) -> list[str]:
        root = Path(case_root)
        if not root.exists():
            return []
        return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "case.json").exists())

    # -- metadata -----------------------------------------------------------
    def _load_meta(self) -> dict:
        return json.loads((self.case_dir / "case.json").read_text())

    def _save_meta(self, meta: dict) -> None:
        (self.case_dir / "case.json").write_text(json.dumps(meta, indent=2))

    def info(self) -> dict:
        return self._load_meta()

    # -- ingest ---------------------------------------------------------------
    def ingest(
        self,
        sources: list[str],
        workers: int | None = None,
        keep_raw: bool = False,
        keep_staging: bool = True,
    ) -> IngestReport:
        specs = [parse_source_arg(s) if isinstance(s, str) else s for s in sources]

        try:
            report = run_ingest(
                case_dir=self.case_dir,
                case_name=self.name,
                sources=specs,
                workers=workers,
                keep_raw=keep_raw,
                keep_staging=keep_staging,
                cluster_config=self.cluster_config,
            )
        except NoSourcesFoundError:
            # No .evtx under these sources -- not fatal on its own, the aux
            # pipeline (Scheduled Tasks / IIS / web / Exchange logs) below
            # may still find something. Only an error if *both* find nothing.
            now = datetime.now(timezone.utc).isoformat()
            report = IngestReport(
                batch_id=str(uuid.uuid4()),
                case_name=self.name,
                started_at=now,
                finished_at=now,
                files_discovered=0,
                files_ok=0,
                files_partial=0,
                files_failed=0,
                records_staged=0,
                records_flattened=0,
            )

        report.aux = run_aux_ingest(
            self.case_dir, specs, workers=workers, keep_staging=keep_staging, cluster_config=self.cluster_config
        )

        if report.files_discovered == 0 and report.aux.files_discovered == 0:
            raise NoSourcesFoundError(
                "no supported log files (.evtx, Scheduled Task definitions, IIS/web access logs, "
                "Exchange CSV logs, syslog/auth logs, auditd logs, systemd journal export) "
                "found under the given source path(s)"
            )

        # Locked so two concurrent `ingest()` runs against the same case
        # (two analysts, or two distributed coordinators) can't clobber
        # each other's ingest_runs/hosts bookkeeping -- see distributed/locking.py.
        with get_case_lock(self.case_dir, self.cluster_config):
            meta = self._load_meta()
            meta.setdefault("ingest_runs", []).append(
                {
                    "batch_id": report.batch_id,
                    "started_at": report.started_at,
                    "finished_at": report.finished_at,
                    "files_discovered": report.files_discovered,
                    "files_ok": report.files_ok,
                    "files_partial": report.files_partial,
                    "files_failed": report.files_failed,
                    "records_flattened": report.records_flattened,
                    "aux_files_discovered": report.aux.files_discovered,
                    "aux_rows_written": report.aux.rows_written,
                }
            )
            hosts = set(meta.get("hosts", []))
            hosts.update(f.host for f in report.staged_files)
            hosts.update(_hosts_from_lake(self.case_dir, self.cluster_config))
            meta["hosts"] = sorted(hosts)
            self._save_meta(meta)

        # Reset cached DB handle so a fresh view picks up newly written data.
        if self._db is not None:
            self._db.close()
            self._db = None

        return report

    # -- query --------------------------------------------------------------
    @property
    def db(self) -> CaseDB:
        if self._db is None:
            self._db = CaseDB(self.case_dir, cluster_config=self.cluster_config)
        return self._db

    def query(self, sql: str) -> pd.DataFrame:
        return self.db.sql(sql)

    # -- plain-language search (no SQL required) ---------------------------------
    def fields(self, table: str, sample_size: int = 5000) -> pd.DataFrame:
        """What can I search on, and what does the data actually look
        like? One row per field this case's ingested data actually has
        for `table` -- real columns plus every key found inside its JSON
        catchall (`event_data`/`extra`/`fields`), each with a popularity
        count and a real example value, computed from a bounded sample
        (never a full table scan) so this is safe to run on a table of
        any size. Run this before `search()` when you're not sure what to
        search on, or when a field name you tried came back with no
        matches and you want to check whether it's really absent or you
        just got the name wrong.

            c.fields("events")     # -> Image, CommandLine, TargetUserName, ... (from event_data)
            c.fields("web_logs")   # -> status, uri_stem, client_ip, ... (real columns)
        """
        return discover_fields(self.db, table, sample_size=sample_size)

    def search(
        self,
        table: str,
        eq: dict | None = None,
        contains: dict | None = None,
        regex: dict | None = None,
        match: Match = "all",
        case_sensitive: bool = False,
    ) -> pd.DataFrame:
        """Query any table without writing SQL: `eq`/`contains`/`regex` are
        `{field: value}` (or `{field: [value1, value2, ...]}` for "this
        field is any of these values") dicts for exact, fuzzy/substring,
        and regular-expression matching respectively. Different fields
        combine with AND by default (`match="any"` for OR); values within
        one field's condition always combine with OR. Matching is
        case-insensitive by default.

            c.search("web_logs", contains={"uri_stem": "admin"}, eq={"status": [401, 403]})

        Refuses (raising ResultTooLargeError) rather than risking an
        out-of-memory crash if the estimated result is too large for the
        machine's available memory -- see `.search_chunks()`/
        `.search_to_csv()` for the alternatives it points you at."""
        conditions = conditions_from_dicts(eq, contains, regex, case_sensitive)
        return _search(self.db, table, conditions, match=match)

    def search_chunks(
        self,
        table: str,
        eq: dict | None = None,
        contains: dict | None = None,
        regex: dict | None = None,
        match: Match = "all",
        case_sensitive: bool = False,
        chunksize: int = DEFAULT_CHUNKSIZE,
    ) -> Iterator[pd.DataFrame]:
        """Bounded-memory alternative to `.search()` -- same arguments,
        yields an Iterator[pd.DataFrame] instead of one DataFrame, safe at
        any result size."""
        conditions = conditions_from_dicts(eq, contains, regex, case_sensitive)
        return _search_chunks(self.db, table, conditions, match=match, chunksize=chunksize)

    def search_to_csv(
        self,
        table: str,
        path,
        eq: dict | None = None,
        contains: dict | None = None,
        regex: dict | None = None,
        match: Match = "all",
        case_sensitive: bool = False,
        chunksize: int = DEFAULT_CHUNKSIZE,
    ) -> int:
        """The other bounded-memory alternative to `.search()`: streams
        every matching row straight to a CSV file. Returns the row count
        written."""
        conditions = conditions_from_dicts(eq, contains, regex, case_sensitive)
        return _search_to_csv(self.db, table, conditions, path, match=match, chunksize=chunksize)

    def query_chunks(self, sql: str, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        """Bounded-memory alternative to `.query()` -- yields the result as
        a series of DataFrames instead of one, so an unfiltered or lightly
        filtered query against a table that's grown to real-world log
        volume (web access/error logs especially can reach terabyte scale)
        doesn't require the whole result to fit in memory at once. See
        query.py's module docstring for why this matters and what it costs
        in practice (empirically: ~190MB bounded vs. multiple GB and
        climbing for `fetchdf()` on the same 5M-row query)."""
        return self.db.sql_chunks(sql, chunksize=chunksize)

    def summary(self) -> pd.DataFrame:
        return self.db.summary()

    def hosts(self) -> list[str]:
        return self.db.hosts()

    def channels(self) -> list[str]:
        return self.db.channels()

    def table_counts(self) -> pd.DataFrame:
        return self.db.table_counts()

    # -- non-EVTX log tables ----------------------------------------------------
    # Every log family -- events included -- gets both an eager,
    # DataFrame-returning accessor (same treatment `events` gets via
    # summary()/hosts()/channels()) AND a "_chunks" sibling returning an
    # Iterator[pd.DataFrame] instead, for tables too large to materialize
    # as one DataFrame. Both return an empty DataFrame / empty iterator
    # (never an error) if the case has no data for that table yet.
    def events(self) -> pd.DataFrame:
        """The full normalized Windows Event Log table. Prefer `.query()`
        with a filter, or `.events_chunks()`, over this for a case of any
        real size -- this is a full unfiltered dump."""
        return self.db.table("events", order_by="time_created")

    def events_chunks(self, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        return self.db.table_chunks("events", order_by="time_created", chunksize=chunksize)

    def web_logs(self, log_type: str | None = None) -> pd.DataFrame:
        """IIS / nginx / Apache / Tomcat / Exchange-HttpProxy access logs."""
        return self._log_type_table("web_logs", log_type)

    def web_logs_chunks(self, log_type: str | None = None, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        return self._log_type_chunks("web_logs", log_type, chunksize)

    def web_error_logs(self, log_type: str | None = None) -> pd.DataFrame:
        """nginx / Apache / Tomcat / IIS HTTP.sys (HTTPERR) error logs --
        the other major web-application log category besides access logs."""
        return self._log_type_table("web_error_logs", log_type)

    def web_error_logs_chunks(
        self, log_type: str | None = None, chunksize: int = DEFAULT_CHUNKSIZE
    ) -> Iterator[pd.DataFrame]:
        return self._log_type_chunks("web_error_logs", log_type, chunksize)

    def scheduled_tasks(self) -> pd.DataFrame:
        """On-disk Task Scheduler task definitions."""
        return self.db.table("scheduled_tasks", order_by="task_path")

    def scheduled_tasks_chunks(self, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        return self.db.table_chunks("scheduled_tasks", order_by="task_path", chunksize=chunksize)

    def exchange_message_tracking(self) -> pd.DataFrame:
        """Exchange mail flow (Message Tracking) logs."""
        return self.db.table("exchange_message_tracking", order_by="time_created")

    def exchange_message_tracking_chunks(self, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        return self.db.table_chunks("exchange_message_tracking", order_by="time_created", chunksize=chunksize)

    def exchange_logs(self, log_type: str | None = None) -> pd.DataFrame:
        """Every other Exchange CSV log type (HttpProxy, EAS, EWS, ...)."""
        return self._log_type_table("exchange_logs", log_type)

    def exchange_logs_chunks(
        self, log_type: str | None = None, chunksize: int = DEFAULT_CHUNKSIZE
    ) -> Iterator[pd.DataFrame]:
        return self._log_type_chunks("exchange_logs", log_type, chunksize)

    def syslog(self) -> pd.DataFrame:
        """Generic syslog (BSD/RFC-3164 and RFC 5424) -- `/var/log/syslog`,
        `messages`, `kern.log`, `auth.log`/`secure`, and everything else
        sharing that line format. See `auth_events()` for a curated,
        structured view over the SSH/sudo/PAM subset of this table."""
        return self.db.table("syslog", order_by="time_created")

    def syslog_chunks(self, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        return self.db.table_chunks("syslog", order_by="time_created", chunksize=chunksize)

    def auditd_logs(self) -> pd.DataFrame:
        """Linux Audit Framework (auditd) records, one row per line. Use
        `audit_serial` to correlate related lines (e.g. SYSCALL + EXECVE +
        CWD) belonging to the same audit event -- not stitched together
        automatically, see docs/known_limitations.md."""
        return self.db.table("auditd_logs", order_by="time_created")

    def auditd_logs_chunks(self, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        return self.db.table_chunks("auditd_logs", order_by="time_created", chunksize=chunksize)

    def journal_logs(self) -> pd.DataFrame:
        """systemd journal export format (`journalctl -o json`) entries."""
        return self.db.table("journal_logs", order_by="time_created")

    def journal_logs_chunks(self, chunksize: int = DEFAULT_CHUNKSIZE) -> Iterator[pd.DataFrame]:
        return self.db.table_chunks("journal_logs", order_by="time_created", chunksize=chunksize)

    def auth_events(self) -> pd.DataFrame:
        """Derived heuristic triage over `syslog`: recognizes SSH
        (accepted/failed/invalid-user/disconnected), sudo command
        execution, PAM session open/close, and account-management
        (useradd/userdel/usermod/...) message shapes, structuring them
        into `event_type`/`user`/`source_ip`/... columns. Not a separate
        ingest table -- computed from already-ingested `syslog` rows, the
        same way `suspicious_tasks()` derives from `scheduled_tasks`."""
        return extract_auth_events(self.syslog())

    def _log_type_table(self, table: str, log_type: str | None) -> pd.DataFrame:
        if log_type is None:
            return self.db.table(table, order_by="time_created")
        if table not in self.db.tables:
            return pd.DataFrame()
        return self.db.sql(f"SELECT * FROM {table} WHERE log_type = ? ORDER BY time_created", [log_type])

    def _log_type_chunks(self, table: str, log_type: str | None, chunksize: int) -> Iterator[pd.DataFrame]:
        if log_type is None:
            return self.db.table_chunks(table, order_by="time_created", chunksize=chunksize)
        if table not in self.db.tables:
            return iter(())
        return self.db.sql_chunks(
            f"SELECT * FROM {table} WHERE log_type = ? ORDER BY time_created", [log_type], chunksize=chunksize
        )

    def suspicious_tasks(self) -> pd.DataFrame:
        """Lightweight heuristic triage over `scheduled_tasks` -- flags tasks
        whose action executable lives under a user-writable/temp-like path,
        whose action invokes a common LOLBin (powershell/cmd/wscript/...),
        that have no author, that are hidden, or that reuse a well-known
        Microsoft task path (`data/scheduled_tasks/known_microsoft_tasks.json`)
        while pointing their action at an unexpected executable location --
        the way a legitimate task getting hijacked/modified for persistence
        (MITRE ATT&CK T1053.005) usually looks. Not a Sigma rule (Sigma has
        no logsource for on-disk task definitions); a lower-effort
        convenience for a first pass. Adds a `suspicion_reasons` column
        (list[str]) to the returned rows explaining *why* each was flagged,
        rather than a bare filter -- see `.scheduled_tasks()` for the full,
        unfiltered table."""
        df = self.scheduled_tasks()
        if df.empty:
            return df

        def _hint_reasons(actions_json: str | None) -> list[str]:
            if not actions_json:
                return []
            haystack = actions_json.lower()
            reasons = []
            if any(h in haystack for h in SUSPICIOUS_ACTION_PATH_HINTS):
                reasons.append("action executable under a user-writable/temp-like path")
            if any(h in haystack for h in SUSPICIOUS_COMMAND_HINTS):
                reasons.append("action invokes a common LOLBin")
            return reasons

        def _reasons(row) -> list[str]:
            reasons = _hint_reasons(row["actions"])
            if pd.isna(row["author"]):
                reasons.append("no author recorded")
            if row["hidden"] == True:  # noqa: E712
                reasons.append("task is hidden")
            action_command = row.get("action_command")
            action_command = None if pd.isna(action_command) else action_command
            baseline_reason = classify_against_baseline(row["task_path"], action_command)
            if baseline_reason:
                reasons.append(baseline_reason)
            return reasons

        reasons_col = df.apply(_reasons, axis=1)
        mask = reasons_col.apply(bool)
        out = df[mask].copy()
        out["suspicion_reasons"] = reasons_col[mask]
        return out

    # -- detection ------------------------------------------------------------
    def hunt(self, rules_dir: Path | None = None, min_level: str | None = None) -> HuntResults:
        return run_hunt(self.case_dir, rules_dir=rules_dir, min_level=min_level, cluster_config=self.cluster_config)

    # -- timeline ---------------------------------------------------------------
    def timeline(
        self,
        start=None,
        end=None,
        host: str | None = None,
        channel: str | None = None,
        event_id: int | list[int] | None = None,
    ) -> pd.DataFrame:
        return build_timeline(self.db, start=start, end=end, host=host, channel=channel, event_id=event_id)

    def timeline_chunks(
        self,
        start=None,
        end=None,
        host: str | None = None,
        channel: str | None = None,
        event_id: int | list[int] | None = None,
        chunksize: int = DEFAULT_CHUNKSIZE,
    ) -> Iterator[pd.DataFrame]:
        """Bounded-memory alternative to `.timeline()` -- an unfiltered or
        lightly-filtered cross-host timeline over a large case can still
        exceed comfortable in-memory size."""
        return build_timeline_chunks(
            self.db, start=start, end=end, host=host, channel=channel, event_id=event_id, chunksize=chunksize
        )

    def __enter__(self) -> "Case":
        return self

    def __exit__(self, *exc) -> None:
        if self._db is not None:
            self._db.close()
