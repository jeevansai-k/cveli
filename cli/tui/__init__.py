"""
TUI (Terminal User Interface) Module.

Purpose: Provide the interactive terminal UI using Textual framework.
Inputs: User keyboard input, data from core/search module.
Outputs: Rich text output to terminal (tables, panels).
Responsibilities: Handle UI rendering and user interaction.
Dependencies: textual for TUI framework, rich for formatting/colors.

Functions/Classes:
    - main.py: Main application class and screen definitions

Example:
    From cli/app.py:
        # Start the TUI application
        from cli.tui.main import MainApp

        app = MainApp()
        run(app)  # Run Textual main loop in CLI context
"""

# Re-export main module for convenient imports
from .main import *  # noqa
