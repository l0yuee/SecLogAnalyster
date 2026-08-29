"""Staging result + ingest report for the non-EVTX log families. Mirrors
`ingest/manifest.py`'s "never silently drop data" philosophy: every file is
accounted for as ok/partial/failed/unrecognized, with a reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


class StageStatus:
    OK = "ok"
    PARTIAL = "partial"  # some rows parsed, some lines rejected
    FAILED = "failed"  # zero rows recovered
    UNKNOWN = "unknown"  # content didn't match any supported format


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuxStagedFile:
    source_path: str
    source_file: str
    host: str
    file_sha256: str
    size_bytes: int
    kind: str | None
    table: str | None
    status: str
    record_count: int
    error_count: int
    error_message: str | None
    rows: list[dict] = field(default_factory=list, repr=False)
    staged_at: str = ""


@dataclass
class AuxIngestReport:
    batch_id: str
    files_discovered: int
    files_ok: int
    files_partial: int
    files_failed: int
    files_unknown: int
    unknown_samples: list[str]
    rows_written: dict[str, int]
    problem_files: list[tuple[str, str, str]]  # (path, status, error_message)

    def summary_text(self) -> str:
        lines = [
            "Auxiliary log ingest (Scheduled Tasks / IIS / web access / Exchange):",
            f"  files discovered : {self.files_discovered}",
            f"  files ok         : {self.files_ok}",
            f"  files partial    : {self.files_partial}"
            + ("  <-- some rows rejected mid-file, see per-file errors" if self.files_partial else ""),
            f"  files failed     : {self.files_failed}"
            + ("  <-- zero rows recovered, see per-file errors" if self.files_failed else ""),
            f"  files unrecognized: {self.files_unknown}"
            + ("  <-- content didn't match any supported format, not ingested" if self.files_unknown else ""),
        ]
        if self.rows_written:
            lines.append("  rows written per table:")
            for table, count in sorted(self.rows_written.items()):
                lines.append(f"    {table}: {count}")
        if self.unknown_samples:
            lines.append("  sample unrecognized files:")
            for p in self.unknown_samples[:10]:
                lines.append(f"    {p}")
        if self.problem_files:
            lines.append("  files with issues:")
            for path, status, msg in self.problem_files:
                lines.append(f"    [{status}] {path} -- {msg}")
        return "\n".join(lines)
