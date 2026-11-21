"""Backward-compatible entry point: ``MainApp`` is now the CVELI shell."""

from cli.tui.app import CveliApp

MainApp = CveliApp

__all__ = ["CveliApp", "MainApp"]

if __name__ == "__main__":  # pragma: no cover
    CveliApp().run()
