class SeclogxError(Exception):
    """Base class for seclogx errors."""


class CaseNotFoundError(SeclogxError):
    pass


class CaseAlreadyExistsError(SeclogxError):
    pass


class NoSourcesFoundError(SeclogxError):
    pass


class UnknownFieldError(SeclogxError):
    pass


class ResultTooLargeError(SeclogxError):
    """Raised by an eager (whole-result-as-one-DataFrame) fetch when the
    estimated result size is judged unsafe for the analyst's available
    memory. Never raised by a chunked/streamed alternative -- those are
    memory-safe at any result size, which is exactly the alternative this
    error's message points the caller at."""

    pass


class UnguardedMainError(SeclogxError):
    """Raised when parallel staging can't start because the calling script
    runs `Case.ingest()` at import time without an
    `if __name__ == "__main__":` guard.

    Worker processes are started with the 'spawn' method (see
    distributed/queue.py for why), which re-imports the caller's `__main__`
    module in each child. Without the guard, that re-import re-runs the
    ingest itself, and Python aborts the pool with a bare
    `BrokenProcessPool` that says nothing about the actual cause. This
    error replaces it with the fix."""

    pass


class ClusterConfigError(SeclogxError):
    """Raised when distributed/cluster-mode configuration is missing or
    inconsistent for the operation being attempted (e.g. a cluster
    dependency -- redis/rq/boto3 -- isn't installed)."""

    pass
