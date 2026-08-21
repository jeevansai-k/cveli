class AppError(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


class ValidationError(AppError):
    def __init__(
        self, field: str, value: str | None = None, message: str | None = None
    ) -> None:
        self.field = field
        self.value = value
        super().__init__(message or f"invalid {field}: {value}", code=400)


class NetworkError(AppError):
    def __init__(
        self, endpoint: str | None = None, status: int = 0, message: str | None = None
    ) -> None:
        self.endpoint = endpoint
        self.status = status
        super().__init__(message or f"{endpoint or 'network'} request failed", code=503)


class DatabaseError(AppError):
    def __init__(
        self, operation: str | None = None, error: Exception | None = None
    ) -> None:
        self.operation = operation
        super().__init__(
            f"{operation or 'database'} failed: {error}" if error else "database error",
            code=500,
        )


class SyncError(AppError):
    def __init__(self, source: str | None = None, operation: str | None = None) -> None:
        self.source = source
        self.operation = operation
        super().__init__(
            f"sync failed for {source or 'source'} ({operation or 'unknown'})", code=502
        )


class FormatError(AppError):
    def __init__(
        self, format_type: str | None = None, error: Exception | None = None
    ) -> None:
        self.format_type = format_type or "unknown"
        super().__init__(
            f"{self.format_type} error: {error}"
            if error
            else f"{self.format_type} error",
            code=400,
        )
