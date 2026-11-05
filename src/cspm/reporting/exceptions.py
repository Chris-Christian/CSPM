"""Exceptions raised by report preparation and generation."""


class ReportError(RuntimeError):
    """Base exception for report generation failures."""


class ReportDataError(ReportError):
    """The persisted scan data cannot be represented accurately in a report."""


class ReportNotFoundError(ReportError):
    """The requested scan does not exist in the repository."""


class ReportRenderError(ReportError):
    """A report renderer could not serialize its input."""


class ReportFormatError(ReportError, ValueError):
    """A report format was not supported by the writer."""


class ReportWriteError(ReportError):
    """A report could not be written safely to its destination."""
