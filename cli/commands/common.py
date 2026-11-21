"""Helpers shared by CLI commands (JSON output, error handling, flags)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import typer
from rich.markup import escape

from cli.console import get_console
from config.settings import get_settings
from utils.errors import AppError, FeatureDisabledError

console = get_console()


def emit_json(payload: Any) -> None:
    """Print machine-readable JSON to stdout (no Rich formatting)."""
    print(json.dumps(payload, indent=2, default=str))


def require_feature(name: str) -> None:
    if not getattr(get_settings(), f"feature_{name}", True):
        error = FeatureDisabledError(name)
        console.print(f"[warning]{escape(str(error))}[/warning]")
        raise typer.Exit(code=3)


def guard[T](func: Callable[[], T], exit_code: int = 2) -> T:
    """Run ``func``; turn AppErrors into a clean message + exit code."""
    try:
        return func()
    except AppError as error:
        console.print(f"[danger]✗ {escape(str(error))}[/danger]")
        raise typer.Exit(code=exit_code) from error


def check_format(value: str, allowed: tuple[str, ...]) -> str:
    fmt = value.lower().strip()
    if fmt not in allowed:
        raise typer.BadParameter(
            f"Use one of: {', '.join(allowed)}", param_hint="--format"
        )
    return fmt
