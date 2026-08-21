# Contributing to CVE Sentinel

## Getting Started

1. Fork the repository and clone it locally
2. Set up development environment (see README)
3. Run tests to verify your setup: `pytest --cov=.`
4. Create a branch for your changes: `git checkout -b feature/your-feature-name`

## Coding Standards

### File Organization

- Keep files under 300 lines where possible
- Document every module with Purpose, Inputs, Outputs, Responsibilities
- Use explicit naming over clever abbreviations
- One responsibility per file/module when feasible

### Naming Conventions

```python
# Module names: snake_case
from utils.helpers import format_csv, truncate_text


# Class names: PascalCase (or lowercase if utility class)
class SearchResult:
    def __init__(self): ...


def calculate_score(value):  # Functions use snake_case
    pass
```

### Testing Requirements

Every module must have tests for:
- Public functions/classes
- Data parsing/validation logic
- Edge cases and error handling

## Pull Request Guidelines

1. Update README or docs if API changed
2. Add test coverage for new functionality
3. Run all tests before submitting
4. Ensure linting passes (ruff, mypy)
5. Write clear commit messages with feature names

## Common Tasks

### Adding a New Source Adapter

See `sources/base.py` for the interface:

```python
class NVDAdapter(BaseAdapter):  # Must implement all methods
    def __init__(self, api_key): ...

    def fetch(self, query_params):  # Returns raw data
        pass

    def parse(self, raw_data):  # Returns list of dicts
        pass

    def normalize(self, record):  # Returns normalized format
        pass
```

### Adding a New CLI Command

1. Create `cli/commands/my_command.py`
2. Define Typer subcommand using decorator syntax
3. Implement the actual logic (can call core functions)

## Documentation

- Update docs/architecture.md if major architectural change
- Add examples to docstrings
- Write user-facing instructions in README.md sections

## Contact

For questions or issues, open an issue on GitHub or ask in the project community.
