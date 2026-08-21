# CVE Sentinel API Reference

## Core Module (`core/`)

### Search Functions

| Function | Description | Input/Output |
|----------|-------------|--------------|
| `parse_query(query)` | Parse raw search string into internal format | str → dict |
| `execute_search(search_data, database)` | Execute parsed search against database | dict, DB → list of CVEs |
| `fuzzy_match(text, query_part)` | Calculate fuzzy match similarity score | str, str → float (0-1) |

### Filter Functions

| Class/Function | Description | Input/Output |
|----------------|-------------|--------------|
| `SeverityFilter(level, exclude_severities)` | Filter by severity level | dict → bool |
| `CVSSRangeFilter(min_score, max_score)` | Filter by CVSS score range | dict → bool |
| `DateFilter(published_since, published_before, updated_since, updated_before)` | Filter by date criteria | dict → bool |
| `apply_filters(results, filters)` | Apply all filters to result set | list, dict → filtered list |

### Ranking Functions

| Class/Function | Description | Input/Output |
|----------------|-------------|--------------|
| `EPSSRanker()` | Rank by exploitation probability (EPSS) | list → sorted list |
| `ExploitRanker()` | Prioritize CVEs with known exploits | list → sorted list |
| `CVSSRanker()` | Sort by CVSS severity score | list → sorted list |
| `rank_results(results, sort_by)` | Main ranking function | list, str → sorted list |

### Validation Functions

| Function | Description | Input/Output |
|----------|-------------|--------------|
| `validate_cve_id(cve_id)` | Validate CVE identifier format | str → bool or ValidationError |
| `validate_date(date_str)` | Validate date string format | str → bool or ValidationError |
| `validate_severity(severity)` | Validate severity level | str → bool or ValidationError |
| `validate_epss_score(value, allow_percentage=True)` | Validate EPSS score range | float → bool or ValidationError |

## Storage Module (`storage/`)

| Function | Description | Input/Output |
|----------|-------------|--------------|
| `init_database(db_path=None)` | Initialize SQLite database schema | None → True |
| `get_engine()` | Return SQLAlchemy engine instance | None → Engine |
| `create_session()` | Create new DB session (context manager) | None → Session |
| `get_connection()` | Get persistent connection | None → Connection |

## Source Adapters (`sources/`)

All adapters must implement:

```python
class BaseAdapter(ABC):
    def __init__(self, api_key=None, timeout=30.0): ...
    
    @abstractmethod
    def fetch(self, query_params=None) -> str | bytes:
        """Fetch raw data from source."""
        raise NotImplementedError
    
    @abstractmethod
    def parse(self, raw_data) -> List[Dict]:
        """Parse raw data into CVE records."""
        raise NotImplementedError
    
    @abstractmethod
    def normalize(self, record) -> Dict:
        """Normalize to canonical format."""
        raise NotImplementedError
```

## CLI Commands (`cli/commands/`)

### Typer Subcommands

| Command | Description | Usage Example |
|---------|-------------|---------------|
| `sync` | Synchronize data from sources | `cve-sentinel sync --source nvd` |
| `search` | Search local database for CVEs | `cve-sentinel search python vulnerable` |
| `export` | Export results to file formats | `cve-sentinel export --format json` |

## Data Model (Canonical CVE Format)

Every source normalizes into this schema:

```json
{
  "id": "",              // Unique CVE identifier (e.g., CVE-2024-12345)
  "summary": "",         // Brief description of the vulnerability  
  "severity": "",        // CVSS severity level
  "cvss_score": 0.0,     // Numeric CVSS score (0.0-10.0 or decimal)
  "vector": "",          // CVSS vector string representation
  "published": "YYYY-MM-DD",  // Publish date
  "updated": "YYYY-MM-DD",    // Update date
  "affected_products": [], // List of affected software products
  "references": [],        // External references/URLs to related info
  "exploit_available": false,     // Boolean indicating known exploits
  "epss": 0.0,             // Exploitation probability score (0-1)
  "cwe_id": "",            // CWE identifier if applicable
  "tags": []               // Tags for categorization
}
```

## Example Usage

### Basic Search
```python
from core.search import parse_query, execute_search
from storage.database import init_database, create_session

# Initialize database
init_database()

with create_session() as session:
    # Parse user query
    search_data = parse_query("python vulnerable")
    
    # Execute search against database
    results = execute_search(search_data, session)
```

### Apply Filters
```python
from core.filters import apply_filters, SeverityFilter, DateFilter

# Create filter objects
severity_filter = SeverityFilter(level="CRITICAL")
date_filter = DateFilter(published_since="2024-01-01")

# Apply filters to results
filtered_results = apply_filters(
    results,
    {"severity": {"level": "CRITICAL"}, "date": {"published_since": "2024-01-01"}},
)
```

### Rank Results by EPSS
```python
from core.ranking import rank_results

# Get results sorted by exploitation probability
ranked = rank_results(results, "epss")  # Most exploitable first
```
