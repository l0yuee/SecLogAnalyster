"""Staging manifest and ingest report.

The manifest is the record of what happened during staging (one row per
source .evtx file): how many records were recovered, whether the file
parsed cleanly, partially, or not at all, and why. This is the direct
answer to "ELK silently drops records on import" -- nothing here is silent.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from ..logsources.manifest import AuxIngestReport


class StageStatus:
    OK = "ok"
    PARTIAL = "partial"  # some records recovered, then a parse error stopped the rest
    FAILED = "failed"  # zero records recovered (e.g. corrupt/unreadable header)


@dataclass
class StagedFile:
    source_path: str
    source_file: str
    host: str
    file_sha256: str
    size_bytes: int
    status: str
    record_count: int
    error_count: int
    error_message: str | None
    ndjson_path: str | None
    staged_at: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class IngestReport:
    batch_id: str
    case_name: str
    started_at: str
    finished_at: str
    files_discovered: int
    files_ok: int
    files_partial: int
    files_failed: int
    records_staged: int
    records_flattened: int
    staged_files: list[StagedFile] = field(default_factory=list)
    aux: "AuxIngestReport | None" = None

    def to_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame([dataclasses.asdict(f) for f in self.staged_files])

    def save(self, path: str | Path) -> None:
        self.to_dataframe().to_csv(path, index=False)

    def summary_text(self) -> str:
        lines = [
            f"Ingest batch {self.batch_id} for case '{self.case_name}'",
            f"  files discovered : {self.files_discovered}",
            f"  files ok         : {self.files_ok}",
            f"  files partial    : {self.files_partial}"
            + ("  <-- some records lost mid-file, see per-file errors" if self.files_partial else ""),
            f"  files failed     : {self.files_failed}"
            + ("  <-- zero records recovered, see per-file errors" if self.files_failed else ""),
            f"  records staged   : {self.records_staged}",
            f"  records in lake  : {self.records_flattened}",
        ]
        if self.records_staged != self.records_flattened:
            lines.append(
                f"  WARNING: staged record count ({self.records_staged}) != "
                f"flattened row count ({self.records_flattened})"
            )
        problems = [f for f in self.staged_files if f.status != StageStatus.OK]
        if problems:
            lines.append("  files with issues:")
            for f in problems:
                lines.append(f"    [{f.status}] {f.source_path} -- {f.error_message} ({f.record_count} recovered)")
        if self.aux is not None:
            lines.append("")
            lines.append(self.aux.summary_text())
        return "\n".join(lines)
