"""Per-source recovery, decoding metadata, and conversion counts.

Parser errors and header discrepancies are reported explicitly. Header
counts remain consistency evidence, not proof that every damaged record
was recoverable or that all upstream parser errors were exposed.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

from ..common import StageStatus, now_iso  # noqa: F401 (now_iso re-exported for existing importers)
from ..staging import StagedChunk

if TYPE_CHECKING:
    from ..logsources.manifest import AuxIngestReport


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
    chunks: list[StagedChunk] = field(default_factory=list)
    ansi_codec: str = "windows-1252"
    ansi_codec_source: str = "default"
    staging_format: str = "ndjson"
    header_record_count: int | None = None


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
    already_imported: list[dict] = field(default_factory=list)

    def to_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame([dataclasses.asdict(f) for f in self.staged_files])

    def save(self, path: str | Path) -> None:
        self.to_dataframe().to_csv(path, index=False)

    def summary_text(self) -> str:
        lines = [
            f"Ingest batch {self.batch_id} for case '{self.case_name}'",
            f"  files discovered : {self.files_discovered}",
            f"  already imported : {len(self.already_imported)}",
            f"  files ok         : {self.files_ok}",
            f"  files partial    : {self.files_partial}"
            + ("  <-- recovery warnings, see per-file errors" if self.files_partial else ""),
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
