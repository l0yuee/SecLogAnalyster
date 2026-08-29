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
