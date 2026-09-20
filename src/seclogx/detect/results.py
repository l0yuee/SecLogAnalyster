"""Complete hunt output, with small-DataFrame compatibility and bounded reads."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator
from uuid import uuid4
import json

import duckdb
import pandas as pd
import pyarrow.parquet as pq

from ..paths import duckdb_path

_EAGER_BYTES = 64 * 1024 * 1024
_EAGER_ROWS = 100_000
_PREVIEW_BYTES = 8 * 1024 * 1024
_READ_BATCH_ROWS = 256
_READ_BATCH_BYTES = 8 * 1024 * 1024


@dataclass
class RuleFailure:
    rule_id: str
    title: str
    reason: str


@dataclass
class HuntResults:
    """Matches remain complete on disk, even when too large for one DataFrame.

    Small hunts retain ``matches``/``to_dataframe()`` compatibility. Large
    hunts require ``preview()``, ``iter_chunks()`` or ``save()``; no implicit
    truncation occurs. Files under ``result_dir`` survive closing the Case.
    """
    rule_summary: pd.DataFrame
    result_dir: Path
    files: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    failures: list[RuleFailure] = field(default_factory=list)
    _matches: pd.DataFrame | None = field(default=None, repr=False)
    _columns: list[str] = field(default_factory=list, repr=False)

    @property
    def total_matches(self) -> int:
        return int(self.rule_summary["matches"].sum()) if not self.rule_summary.empty else 0

    @property
    def is_spilled(self) -> bool:
        return self._matches is None and self.total_matches > 0

    @property
    def matches(self) -> pd.DataFrame:
        if self.is_spilled:
            raise MemoryError(
                f"Hunt has {self.total_matches:,} complete matches saved in {self.result_dir}. "
                "Use preview() for a labelled preview, iter_chunks() to read every row, "
                "or save(path) to export all matches without loading them together."
            )
        return self._matches if self._matches is not None else pd.DataFrame(columns=self._columns)

    def to_dataframe(self) -> pd.DataFrame:
        """Return every match only when the automatic memory budget permits."""
        return self.matches

    @classmethod
    def open(cls, result_dir: str | Path) -> "HuntResults":
        """Reopen complete results after restarting Jupyter or copying a Case."""
        root = Path(result_dir).resolve()
        manifest = json.loads((root / "results.json").read_text(encoding="utf-8"))
        if manifest.get("version") != 1:
            raise ValueError("unsupported hunt result format")
        files = []
        actual_count = 0
        for name in manifest["files"]:
            path = (root / name).resolve()
            if not path.is_relative_to(root) or path.suffix != ".parquet":
                raise ValueError("hunt result index contains an invalid file path")
            with pq.ParquetFile(duckdb_path(path)) as parquet:
                actual_count += parquet.metadata.num_rows
            files.append(str(path))
        result = cls(rule_summary=pd.DataFrame(manifest["rule_summary"]), result_dir=root,
                     files=files, skipped=[tuple(item) for item in manifest["skipped"]],
                     failures=[RuleFailure(**item) for item in manifest["failures"]])
        if actual_count != result.total_matches or actual_count != manifest["total_matches"]:
            raise ValueError("hunt result files do not match the recorded match count")
        result._load_small()
        return result

    def _load_small(self) -> None:
        columns = []
        for path in self.files:
            with pq.ParquetFile(duckdb_path(path)) as parquet:
                columns.extend(parquet.schema_arrow.names)
        self._columns = list(dict.fromkeys(columns))
        if self.total_matches > _EAGER_ROWS:
            return
        frames: list[pd.DataFrame] = []
        used = 0
        for frame in self.iter_chunks():
            used += int(frame.memory_usage(index=True, deep=True).sum())
            if used > _EAGER_BYTES:
                return
            frames.append(frame)
        self._matches = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=self._columns)

    def iter_chunks(self, chunksize: int = _READ_BATCH_ROWS) -> Iterator[pd.DataFrame]:
        """Read all matches in chunks no larger than ``chunksize`` rows.

        Discard each chunk after processing. Parquet metadata guides Arrow
        batch sizes; a decoded row group/dictionary or one exceptionally wide
        record can exceed the byte target. This is not a hard RSS ceiling.
        """
        if not isinstance(chunksize, int) or chunksize <= 0:
            raise ValueError("chunksize must be a positive integer")
        for path in self.files:
            with pq.ParquetFile(duckdb_path(path)) as parquet:
                for group_index in range(parquet.num_row_groups):
                    group = parquet.metadata.row_group(group_index)
                    average = max(1, group.total_byte_size // max(1, group.num_rows))
                    batch_rows = max(1, min(chunksize, _READ_BATCH_ROWS, _READ_BATCH_BYTES // average))
                    for batch in parquet.iter_batches(batch_size=batch_rows, row_groups=[group_index]):
                        offset = 0
                        while offset < batch.num_rows:
                            remaining = batch.slice(offset)
                            rows = remaining.num_rows
                            if remaining.nbytes > _READ_BATCH_BYTES:
                                # Split unusually wide Arrow batches before
                                # converting their strings to Python. Binary
                                # search works on array offsets, not row dicts.
                                low, high = 1, rows
                                while low < high:
                                    middle = (low + high + 1) // 2
                                    if remaining.slice(0, middle).nbytes <= _READ_BATCH_BYTES:
                                        low = middle
                                    else:
                                        high = middle - 1
                                rows = low  # one indivisible record is allowed
                            chunk = remaining.slice(0, rows)
                            yield chunk.to_pandas().reindex(columns=self._columns or chunk.schema.names)
                            offset += rows

    def preview(self, rows: int = 100) -> pd.DataFrame:
        """Return a bounded preview labelled with counts in DataFrame.attrs."""
        if not isinstance(rows, int) or rows < 0:
            raise ValueError("rows must be a nonnegative integer")
        frames: list[pd.DataFrame] = []
        count = used = 0
        if rows:
            for frame in self.iter_chunks(min(rows, _READ_BATCH_ROWS)):
                frame = frame.iloc[:rows - count]
                size = int(frame.memory_usage(index=True, deep=True).sum())
                if used + size > _PREVIEW_BYTES:
                    for index in range(len(frame)):
                        row = frame.iloc[index:index + 1]
                        size = int(row.memory_usage(index=True, deep=True).sum())
                        if used + size > _PREVIEW_BYTES:
                            break
                        frames.append(row)
                        used += size
                        count += 1
                    break
                frames.append(frame)
                used += size
                count += len(frame)
                if count >= rows:
                    break
        result = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=self._columns)
        result.attrs.update(total_matches=self.total_matches, preview_rows=len(result),
                            complete=len(result) == self.total_matches, result_dir=str(self.result_dir))
        return result

    def save(self, path: str | Path) -> None:
        """Stream every match to CSV; replace the destination only on success."""
        path = Path(path).resolve()
        partial = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            if self.files:
                # Export stays in DuckDB; large CSVs do not round-trip through
                # millions of Python rows. No rule SQL is executed here.
                with duckdb.connect() as con:
                    con.execute("SET memory_limit = '512MB'")
                    con.execute("SET threads = 2")
                    con.execute("SET allowed_paths = ?", [[duckdb_path(path) for path in [*self.files, partial]]])
                    con.execute("SET autoinstall_known_extensions = false")
                    con.execute("SET autoload_known_extensions = false")
                    con.execute("SET enable_external_access = false")
                    con.execute("SET lock_configuration = true")
                    destination = duckdb_path(partial).replace("'", "''")
                    count = con.execute(
                        "COPY (SELECT * FROM read_parquet(?, union_by_name=true, hive_partitioning=false)) "
                        f"TO '{destination}' (FORMAT CSV, HEADER true)", [[duckdb_path(path) for path in self.files]],
                    ).fetchone()[0]
                    if count != self.total_matches:
                        raise ValueError("hunt result files do not match the recorded match count")
            else:
                pd.DataFrame(columns=self._columns).to_csv(partial, index=False, encoding="utf-8")
            Path(duckdb_path(partial)).replace(duckdb_path(path))
        finally:
            Path(duckdb_path(partial)).unlink(missing_ok=True)

    def summary_text(self) -> str:
        lines = [f"Hunt: {len(self.rule_summary)} rules evaluated, {self.total_matches} total matches",
                 f"  rules skipped (unsupported logsource): {len(self.skipped)}",
                 f"  rules failed (conversion/execution error): {len(self.failures)}"]
        if self.is_spilled:
            lines.extend([f"  complete results saved: {self.result_dir}",
                          "  use preview(), iter_chunks() or save(path); matches is too large for one DataFrame"])
        if not self.rule_summary.empty:
            hits = self.rule_summary[self.rule_summary["matches"] > 0].sort_values("matches", ascending=False)
            if not hits.empty:
                lines.append("  rules with matches:")
                for _, row in hits.iterrows():
                    lines.append(f"    [{row['level']}] {row['title']} -- {row['matches']} matches "
                                 f"(ATT&CK: {row['attack_tags'] or '-'})")
        if self.failures:
            lines.append("  failed rules:")
            for failure in self.failures:
                lines.append(f"    {failure.title} ({failure.rule_id}) -- {failure.reason}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return self.summary_text()
