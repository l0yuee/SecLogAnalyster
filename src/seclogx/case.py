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
from urllib.parse import unquote

import pandas as pd

from .config import DEFAULT_CASE_ROOT
from .discovery import parse_source_arg
from .errors import CaseAlreadyExistsError, CaseNotFoundError, NoSourcesFoundError
from .detect import HuntResults, run_hunt
from .ingest import run_ingest
from .ingest.manifest import IngestReport
from .logsources import run_aux_ingest
from .logsources.scheduled_tasks import SUSPICIOUS_ACTION_PATH_HINTS, SUSPICIOUS_COMMAND_HINTS
from .query import CaseDB
from .timeline import build_timeline


def _hosts_from_lake(case_dir: Path) -> set[str]:
    """Hosts present in the Parquet lake, read directly off the Hive
    `host=<value>` partition folder names (percent-decoded) -- covers every
    table (events, web_logs, scheduled_tasks, ...) without needing a DB
    connection."""
    hosts: set[str] = set()
    lake_dir = case_dir / "lake"
    if not lake_dir.exists():
        return hosts
    for table_dir in lake_dir.iterdir():
        if not table_dir.is_dir():
            continue
        for p in table_dir.glob("host=*"):
            if p.is_dir():
                hosts.add(unquote(p.name[len("host=") :]))
    return hosts


class Case:
    def __init__(self, name: str, case_dir: Path):
        self.name = name
        self.case_dir = Path(case_dir)
        self._db: CaseDB | None = None

    # -- lifecycle --------------------------------------------------------
    @classmethod
    def create(cls, name: str, case_root: Path = DEFAULT_CASE_ROOT) -> "Case":
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
        return cls(name, case_dir)

    @classmethod
    def open(cls, name: str, case_root: Path = DEFAULT_CASE_ROOT) -> "Case":
        case_dir = Path(case_root) / name
        if not (case_dir / "case.json").exists():
            raise CaseNotFoundError(f"case '{name}' not found under {case_root}")
        return cls(name, case_dir)

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

        report.aux = run_aux_ingest(self.case_dir, specs, workers=workers)

        if report.files_discovered == 0 and report.aux.files_discovered == 0:
            raise NoSourcesFoundError(
                "no supported log files (.evtx, Scheduled Task definitions, IIS/web access logs, "
                "Exchange CSV logs) found under the given source path(s)"
            )

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
        hosts.update(_hosts_from_lake(self.case_dir))
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
            self._db = CaseDB(self.case_dir)
        return self._db

    def query(self, sql: str) -> pd.DataFrame:
        return self.db.sql(sql)

    def summary(self) -> pd.DataFrame:
        return self.db.summary()

    def hosts(self) -> list[str]:
        return self.db.hosts()

    def channels(self) -> list[str]:
        return self.db.channels()

    def table_counts(self) -> pd.DataFrame:
        return self.db.table_counts()

    def suspicious_tasks(self) -> pd.DataFrame:
        """Lightweight heuristic triage over `scheduled_tasks` -- flags tasks
        whose action executable lives under a user-writable/temp-like path,
        or whose action invokes a common LOLBin (powershell/cmd/wscript/...).
        Not a Sigma rule (Sigma has no logsource for on-disk task
        definitions); a lower-effort convenience for a first pass."""
        if "scheduled_tasks" not in self.db.tables:
            return pd.DataFrame()
        df = self.db.sql("SELECT * FROM scheduled_tasks")
        if df.empty:
            return df

        def _is_suspicious(actions_json: str | None) -> bool:
            if not actions_json:
                return False
            haystack = actions_json.lower()
            return any(h in haystack for h in SUSPICIOUS_ACTION_PATH_HINTS) or any(
                h in haystack for h in SUSPICIOUS_COMMAND_HINTS
            )

        mask = df["actions"].apply(_is_suspicious) | df["author"].isna() | (df["hidden"] == True)  # noqa: E712
        return df[mask]

    # -- detection ------------------------------------------------------------
    def hunt(self, rules_dir: Path | None = None, min_level: str | None = None) -> HuntResults:
        return run_hunt(self.case_dir, rules_dir=rules_dir, min_level=min_level)

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

    def __enter__(self) -> "Case":
        return self

    def __exit__(self, *exc) -> None:
        if self._db is not None:
            self._db.close()
