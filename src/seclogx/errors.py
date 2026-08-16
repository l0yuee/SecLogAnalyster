class SeclogxError(Exception):
    """Base class for seclogx errors."""


class CaseNotFoundError(SeclogxError):
    pass


class CaseAlreadyExistsError(SeclogxError):
    pass


class NoSourcesFoundError(SeclogxError):
    pass
