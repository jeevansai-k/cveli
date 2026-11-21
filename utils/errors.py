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


class RateLimitError(AppError):
    def __init__(self, message: str = "rate limit exceeded", retry_after: float = 0):
        self.retry_after = retry_after
        super().__init__(message, code=429)


class PolicyError(AppError):
    """Raised when a request violates a CVELI safety policy."""

    def __init__(self, reason: str, rule: str | None = None) -> None:
        self.reason = reason
        self.rule = rule
        super().__init__(reason, code=403)


class AuthorizationRequiredError(AppError):
    """Raised when an action needs an explicit authorized-use attestation."""

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "Confirm you have written authorization or a lawful research purpose.",
            code=401,
        )


class FeatureDisabledError(AppError):
    def __init__(self, feature: str) -> None:
        self.feature = feature
        super().__init__(
            f"The '{feature}' feature is disabled "
            f"(set CVELI_FEATURE_{feature.upper()}=1 to enable).",
            code=403,
        )
