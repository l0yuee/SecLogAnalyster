These MIT-licensed, project-owned synthetic samples contain no real evidence.
Each supported file preserves its header and 16 complete source records, covering
Nginx Combined, IIS W3C, RFC 5424 syslog, journal JSON, MySQL error logs, and
Exchange message tracking. The records include multiple statuses and severities.

The unrelated files preserve source prefixes: ELF, PE, PDF, arbitrary binary,
and complete lines of unrelated text. Binary prefixes are intentionally incomplete
containers; they exercise classification and extension exclusion, not executable
loading or document rendering. Tests never execute them.

`manifest.json` records each fixture's size, SHA-256, sampling method, expected
classification, destination table, and record count. Tests verify these values
and compare complete normalized rows across automatic, Python, and Arrow staging
paths. Other product tests generate minimal malformed input, encoding boundaries,
failure injection, and large result sets at runtime. This corpus checks semantics;
it does not claim exhaustive format or large-volume performance coverage.
