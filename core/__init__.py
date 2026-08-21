"""
Core Application Logic.

Purpose: Contains all business logic, search algorithms, filtering, ranking, validation.
Inputs: Search queries, filter criteria, ranked results data.
Outputs: Filtered, sorted, and ranked result sets.
Responsibilities: Implement the brain of the application - processing user requests.
Dependencies: rapidfuzz for fuzzy matching, pydantic for validation, other core modules.

Functions/Classes:
    - search.py: Search query parsing and execution
    - filters.py: Filter criteria handling (severity ranges, CVSS ranges, etc.)
    - ranking.py: Result ranking by EPSS, exploit availability, severity
    - formatter.py: Results formatting for TUI output
    - validator.py: Input validation for all user inputs

Example:
    From search.py:
        results = search.query(query, filters)

    Then from ranking.py:
        ranked = ranking.rank(results, sort_by='epss')

"""

from .search import *  # noqa
from .filters import *  # noqa
from .ranking import *  # noqa
from .formatter import *  # noqa
from .validator import *  # noqa
