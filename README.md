<p align="center">
  <h1 align="center">SuccessFactors-MCP</h1>
  <p align="center">
    <strong>SAP SuccessFactors Model Context Protocol Server</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> &middot;
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#tools">43 Tools</a> &middot;
    <a href="#deployment">Deployment</a> &middot;
    <a href="#api-reference">API Reference</a>
  </p>
</p>

<p align="center">
  <a href="https://github.com/aiadiguru2025/sf-mcp/releases"><img alt="Version" src="https://img.shields.io/badge/version-0.3.2-blue.svg" /></a>
  <a href="https://www.python.org/downloads/"><img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue.svg" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg" /></a>
  <a href="https://modelcontextprotocol.io"><img alt="MCP" src="https://img.shields.io/badge/MCP-compatible-purple.svg" /></a>
</p>

---

A production-grade [Model Context Protocol](https://modelcontextprotocol.io) server that connects Claude (or any MCP client) to **SAP SuccessFactors** via OData APIs. Query employee data, manage permissions, run compliance reports, and administer HR operations — all through natural language.

```
You: "Who on the Engineering team has a work anniversary this month?"

Claude: [calls get_anniversary_employees] Found 3 upcoming anniversaries...
         - Jane Smith (5 years - milestone!) - March 12
         - Bob Johnson (2 years) - March 18
         - Alice Chen (10 years - milestone!) - March 25
```

## Why SF-MCP?

| Challenge | SF-MCP Solution |
|-----------|-----------------|
| SAP SuccessFactors APIs are complex and verbose | **43 purpose-built tools** with clean interfaces |
| Building OData queries requires deep SF knowledge | **Natural language** — ask Claude in plain English |
| Security concerns with API access | **Per-request auth**, input validation, audit logging |
| Managing multiple SF instances | **21 data centers** supported, cross-instance comparison |
| API rate limits and performance | **Connection pooling**, response caching, rate limiting |

## Tools

43 tools organized across 13 categories:

<details>
<summary><strong>Configuration & Discovery</strong> (3 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_configuration` | Retrieve OData metadata for any entity |
| `list_entities` | Discover all available OData entities |
| `compare_configurations` | Compare entity config between two instances |

</details>

<details>
<summary><strong>RBP Security</strong> (7 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_rbp_roles` | List all Role-Based Permission roles |
| `get_role_permissions` | Get permissions for specific roles |
| `get_user_permissions` | Get all permissions for a user |
| `get_user_roles` | Get roles assigned to a user |
| `get_permission_metadata` | Map UI labels to permission types |
| `check_user_permission` | Check if user has specific permission |
| `get_dynamic_groups` | List permission groups (dynamic groups) |

</details>

<details>
<summary><strong>RBP Audit</strong> (2 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_role_history` | View modification history for roles |
| `get_role_assignment_history` | View history of role assignments |

</details>

<details>
<summary><strong>Data Query</strong> (2 tools)</summary>

| Tool | Description |
|------|-------------|
| `query_odata` | Flexible OData queries with filtering, pagination |
| `get_picklist_values` | Get dropdown/picklist options |

</details>

<details>
<summary><strong>Employee Lookup</strong> (4 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_employee_profile` | Complete profile with job info, manager, optional compensation |
| `search_employees` | Find by name, department, location, or manager |
| `get_employee_history` | Job history — promotions, transfers, title changes |
| `get_team_roster` | Manager's team with direct/indirect reports |

</details>

<details>
<summary><strong>Time Off</strong> (3 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_time_off_balances` | Vacation, PTO, sick leave balances |
| `get_upcoming_time_off` | Team absence calendar for a date range |
| `get_time_off_requests` | Pending/approved time-off requests |

</details>

<details>
<summary><strong>Hiring & Onboarding</strong> (3 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_open_requisitions` | Job requisitions with status and hiring manager |
| `get_candidate_pipeline` | Candidates by stage for a requisition |
| `get_new_hires` | Recent/upcoming hires for onboarding |

</details>

<details>
<summary><strong>Compliance & Reporting</strong> (3 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_terminations` | Terminated employees for exit processing |
| `get_employees_missing_data` | Incomplete profiles for compliance audits |
| `get_anniversary_employees` | Upcoming work anniversaries for recognition |

</details>

<details>
<summary><strong>Performance & Compensation</strong> (2 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_performance_review_status` | Review form completion across the org |
| `get_compensation_details` | Pay breakdown with recurring/non-recurring components |

</details>

<details>
<summary><strong>Position Management</strong> (3 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_position_details` | Position with incumbent, department, FTE |
| `get_vacant_positions` | Open positions for headcount planning |
| `get_org_chart` | Org hierarchy from any position (up or down) |

</details>

<details>
<summary><strong>MDF Objects</strong> (3 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_mdf_object_definitions` | List custom MDF objects and their fields |
| `query_mdf_object` | Query any MDF/generic object (`cust_*`) |
| `get_foundation_objects` | Query foundation objects (departments, cost centers, etc.) |

</details>

<details>
<summary><strong>Workflow</strong> (2 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_pending_approvals` | Pending workflow items for a user or globally |
| `get_workflow_history` | Audit trail of approval steps |

</details>

<details>
<summary><strong>Monitoring & Admin</strong> (6 tools)</summary>

| Tool | Description |
|------|-------------|
| `get_alert_notifications` | System alerts and notifications |
| `get_scheduled_job_status` | Scheduled job run status |
| `get_integration_center_jobs` | Integration Center job status |
| `get_api_quota_status` | Rate limit usage per instance |
| `get_cache_status` | Cache hit rates and entry counts |
| `clear_cache` | Clear cached responses |

</details>

## Installation

### Prerequisites

- **Python 3.10+**
- **[uv](https://docs.astral.sh/uv/)** package manager
- SAP SuccessFactors account with API access

### Setup

```bash
git clone https://github.com/aiadiguru2025/sf-mcp.git
cd sf-mcp
uv sync
```

### Quick Start

**Development mode** (MCP Inspector):
```bash
uv run mcp dev main.py
```

**Stdio mode** (Claude Desktop):
```bash
uv run main.py
```

**HTTP mode** (Cloud Run / remote):
```bash
PORT=8080 uv run main.py
```

## Claude Desktop Integration

### Step 1 — Find the path to `uv`

```bash
# macOS / Linux
which uv

# Windows (PowerShell)
Get-Command uv | Select-Object -ExpandProperty Source
```

### Step 2 — Edit your Claude Desktop config

| OS | Config path |
|----|------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

Add the sf-mcp server:

```json
{
  "mcpServers": {
    "sf-mcp": {
      "command": "/path/to/uv",
      "args": ["--directory", "/path/to/sf-mcp", "run", "main.py"]
    }
  }
}
```

### Step 3 — Restart Claude Desktop

The MCP tools icon (hammer) will appear in the input area with all 43 tools available.

> **Note:** Credentials (`auth_user_id` and `auth_password`) are provided on each tool call — nothing is stored in the config.

## Deployment

### Google Cloud Run

```bash
# Build and deploy
export PROJECT_ID=your-gcp-project-id
gcloud builds submit --tag gcr.io/$PROJECT_ID/sf-mcp
gcloud run deploy sf-mcp \
  --image gcr.io/$PROJECT_ID/sf-mcp \
  --platform managed \
  --region us-central1
```

Then point Claude Desktop to the remote URL:

```json
{
  "mcpServers": {
    "sf-mcp": {
      "url": "https://sf-mcp-xxxxx-uc.a.run.app/mcp"
    }
  }
}
```

### Docker (local)

```bash
docker build -t sf-mcp .
docker run -p 8080:8080 sf-mcp
```

### API Key Protection (optional)

Set `MCP_API_KEY` to require authentication on the HTTP endpoint:

```bash
MCP_API_KEY=your-secret-key PORT=8080 uv run main.py
```

Clients must then include `X-API-Key: your-secret-key` in requests.

## Configuration

All tool parameters (`data_center`, `environment`, `auth_user_id`, `auth_password`) are provided per-request. Server-side environment variables are optional:

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `SF_RATE_LIMIT` | `100` | Max requests per window per instance |
| `SF_RATE_LIMIT_WINDOW` | `60` | Window duration in seconds |
| `SF_RATE_LIMIT_WARN_THRESHOLD` | `0.8` | Log warning at 80% usage |
| `SF_RATE_LIMIT_RETRY_AFTER` | `5` | Seconds to wait on 429 retry |
| `SF_RATE_LIMIT_MAX_RETRIES` | `3` | Max 429 retry attempts |

### Response Caching

| Variable | Default | Description |
|----------|---------|-------------|
| `SF_CACHE_TTL_METADATA` | `3600` | Metadata cache TTL (1 hour) |
| `SF_CACHE_TTL_SERVICE_DOC` | `3600` | Service doc cache TTL (1 hour) |
| `SF_CACHE_TTL_PICKLIST` | `1800` | Picklist cache TTL (30 min) |
| `SF_CACHE_TTL_PERMISSIONS` | `3600` | Permission cache TTL (1 hour) |
| `SF_CACHE_TTL_DEFAULT` | `0` | Default TTL (0 = disabled) |
| `SF_CACHE_MAX_ENTRIES` | `1000` | Max cache entries before eviction |

### Endpoint Protection

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_API_KEY` | *(none)* | API key for HTTP endpoint auth |

Copy `.env.example` to `.env` to customize:
```bash
cp .env.example .env
```

## Supported Data Centers

21 data centers across 6 continents with alias support:

| Data Center | Alias | Location | Environments |
|-------------|-------|----------|--------------|
| DC2 | DC57 | Netherlands | preview, production, sales_demo |
| DC4 | DC68 | Virginia, US | preview, production, sales_demo |
| DC8 | DC70 | Ashburn, Virginia, US | preview, production, sales_demo |
| DC10 | DC66 | Sydney, Australia | preview, production |
| DC12 | DC33 | Germany | preview, production |
| DC15 | DC30 | Shanghai, China | preview, production |
| DC17 | DC60 | Toronto, Canada | preview, production |
| DC19 | DC62 | Sao Paulo, Brazil | preview, production |
| DC22 | — | Dubai, UAE | preview, production |
| DC23 | DC84 | Riyadh, Saudi Arabia | preview, production |
| DC40 | — | — | sales_demo |
| DC41 | — | Virginia, US | preview, production |
| DC44 | DC52 | Singapore | preview, production |
| DC47 | — | Canada Central | preview, production |
| DC50 | — | Tokyo, Japan | preview, production |
| DC55 | — | Frankfurt, Germany | preview, production |
| DC74 | — | Zurich, Switzerland | preview, production |
| DC80 | — | Mumbai, India | preview, production |
| DC82 | — | Riyadh, Saudi Arabia | preview, production |

## Architecture

```
sf-mcp/
├── main.py                     # Entry point (stdio + HTTP modes)
├── sf_mcp/
│   ├── server.py               # FastMCP instance
│   ├── config.py               # DC mappings, constants, env vars
│   ├── auth.py                 # Credential resolution, API key middleware
│   ├── client.py               # HTTP client (OData, metadata, service doc, pagination)
│   ├── cache.py                # TTL-based response cache with deep-copy safety
│   ├── rate_limiter.py         # Sliding-window rate limiter (per-instance)
│   ├── validation.py           # 10 input validators with registry pattern
│   ├── decorators.py           # sf_tool decorator (cross-cutting concerns)
│   ├── dependencies.py         # FastMCP DI for schema exclusion
│   ├── logging_config.py       # Cloud Logging JSON formatter, audit_log()
│   ├── xml_utils.py            # Safe XML parsing (defusedxml), SAP date parsing
│   └── tools/                  # 43 tools across 13 modules
│       ├── configuration.py    # get_configuration, compare_configurations, list_entities
│       ├── permissions.py      # 7 RBP security tools
│       ├── audit.py            # Role history, role assignment history
│       ├── query.py            # query_odata, get_picklist_values
│       ├── employee.py         # Profile, search, history, team roster
│       ├── time_off.py         # Balances, upcoming absences, requests
│       ├── recruiting.py       # Requisitions, pipeline, new hires
│       ├── compliance.py       # Terminations, missing data, anniversaries, reviews, comp
│       ├── position.py         # Position details, vacancies, org chart
│       ├── workflow.py         # Pending approvals, workflow history
│       ├── mdf.py              # MDF object definitions, queries, foundation objects
│       ├── monitoring.py       # Alerts, scheduled jobs, integration jobs
│       ├── admin.py            # Rate limit quota, cache status, cache clear
│       └── utils.py            # Shared utilities (display_name)
├── tests/                      # 110 tests
├── Dockerfile                  # Cloud Run container
├── .env.example                # Configuration template
└── pyproject.toml              # Project metadata, dependencies, linter config
```

### Design Principles

**Zero boilerplate** — The `sf_tool` decorator handles request ID generation, timing, audit logging, input validation, credential checking, error handling, and `$top` clamping. Tool functions contain only business logic.

**Secure by default** — 10 input validators (regex allowlists), OData injection prevention, XXE-safe XML parsing (defusedxml), timing-safe API key comparison (hmac.compare_digest), and automatic credential masking in logs.

**Production-ready** — Connection pooling (requests.Session), mutation-safe response caching (deep-copy on put/get), sliding-window rate limiting with automatic 429 retry, and Cloud Logging-compatible JSON audit trail.

**Schema-clean** — Internal parameters (`request_id`, `start_time`, `api_host`) are hidden from the MCP tool schema via FastMCP's Dependency injection, keeping tool interfaces clean for LLM consumers.

## Security

| Layer | Mechanism |
|-------|-----------|
| **Input validation** | 10 regex-based validators; OData filter blocklist checks raw + URL-decoded + double-decoded input |
| **Injection prevention** | Entity paths, $select, $orderby, $filter, $expand all validated; control characters rejected |
| **Authentication** | Per-request credentials (never stored); timing-safe API key comparison via `hmac.compare_digest` |
| **XML safety** | `defusedxml` prevents XXE, entity expansion, and DTD attacks |
| **Audit logging** | Every tool call logged with structured JSON; passwords automatically masked |
| **Cache safety** | Deep-copied on store and retrieval to prevent mutation bugs |
| **Date handling** | All SAP timestamp parsing uses explicit UTC to prevent timezone inconsistencies |

## Testing

```bash
# Run all 110 tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ --cov=sf_mcp

# Lint
uv run ruff check .

# Type check
uv run mypy sf_mcp/
```

Test coverage includes:
- **Config** — DC mapping resolution, case insensitivity, aliases, error cases
- **Validation** — All 10 validators with valid/invalid inputs, injection prevention
- **Client** — Mocked HTTP responses (200, 401, 500, empty, connection error)
- **Rate limiter** — Limit enforcement, sliding window, per-instance isolation, thread safety
- **Cache** — Put/get, TTL expiry, category TTLs, invalidation, eviction, deep-copy safety
- **Pagination** — Single/multi page, max_pages limit, error handling, $skip increments
- **Decorators** — Value injection, validation errors, max_top clamping, exception handling

## API Reference

Every tool accepts these common parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center code (e.g., `DC55`, `DC10`) |
| `environment` | string | Yes | `preview`, `production`, or `sales_demo` |
| `auth_user_id` | string | Yes | SuccessFactors user ID (without @instance) |
| `auth_password` | string | Yes | SuccessFactors password |

<details>
<summary><strong>Configuration Tools</strong></summary>

#### `get_configuration`

Retrieve OData metadata for a SuccessFactors entity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity` | string | Yes | OData entity name (e.g., `User`, `Position`) |

#### `list_entities`

Discover all available OData entities in an instance.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `category` | string | No | `foundation`, `employee`, `talent`, `platform`, or `all` |

#### `compare_configurations`

Compare entity config between two instances (e.g., dev vs prod).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance1` | string | Yes | First instance |
| `instance2` | string | Yes | Second instance |
| `entity` | string | Yes | Entity to compare |
| `data_center1` | string | Yes | Data center for instance1 |
| `environment1` | string | Yes | Environment for instance1 |
| `data_center2` | string | Yes | Data center for instance2 |
| `environment2` | string | Yes | Environment for instance2 |

</details>

<details>
<summary><strong>RBP Security Tools</strong></summary>

#### `get_rbp_roles`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `include_description` | boolean | No | Include role descriptions (default: false) |

#### `get_role_permissions`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `role_ids` | string | Yes | Single or comma-separated: `10` or `10,20,30` |
| `locale` | string | No | Locale for labels (default: `en-US`) |

#### `get_user_permissions`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_ids` | string | Yes | Single or comma-separated: `admin` or `admin,user2` |
| `locale` | string | No | Locale for labels (default: `en-US`) |

#### `get_user_roles`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | User ID to look up roles for |
| `include_permissions` | boolean | No | Also fetch permissions per role (default: false) |

#### `get_permission_metadata`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `locale` | string | No | Locale for labels (default: `en-US`) |

#### `check_user_permission`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `access_user_id` | string | Yes | User whose permission to check |
| `target_user_id` | string | Yes | Target user of the permission |
| `perm_type` | string | Yes | Permission type from metadata |
| `perm_string_value` | string | Yes | Permission string value |
| `perm_long_value` | string | No | Permission long value (default: `-1L`) |

#### `get_dynamic_groups`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `group_type` | string | No | Filter by group type |

</details>

<details>
<summary><strong>RBP Audit Tools</strong></summary>

#### `get_role_history`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `role_id` | string | No | Filter by role ID |
| `role_name` | string | No | Filter by role name |
| `from_date` | string | No | Start date (YYYY-MM-DD) |
| `to_date` | string | No | End date (YYYY-MM-DD) |
| `top` | integer | No | Max records (default: 100, max: 500) |

#### `get_role_assignment_history`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `role_id` | string | No | Filter by role ID |
| `user_id` | string | No | Filter by user ID |
| `from_date` | string | No | Start date (YYYY-MM-DD) |
| `to_date` | string | No | End date (YYYY-MM-DD) |
| `top` | integer | No | Max records (default: 100, max: 500) |

> At least one of `role_id` or `user_id` is required.

</details>

<details>
<summary><strong>Data Query Tools</strong></summary>

#### `query_odata`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity` | string | Yes | Entity name or key: `User` or `User('admin')` |
| `select` | string | No | Fields: `userId,firstName,lastName` |
| `filter` | string | No | OData filter: `status eq 'active'` |
| `expand` | string | No | Nav properties: `empInfo,jobInfoNav` |
| `top` | integer | No | Max records (default: 100, max: 1000) |
| `skip` | integer | No | Records to skip |
| `orderby` | string | No | Sort: `lastName asc` |
| `paginate` | boolean | No | Auto-fetch all pages (default: false) |
| `max_pages` | integer | No | Max pages when paginating (default: 10, max: 50) |

#### `get_picklist_values`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `picklist_id` | string | Yes | Picklist ID: `ecJobFunction`, `nationality` |
| `locale` | string | No | Locale for labels (default: `en-US`) |
| `include_inactive` | boolean | No | Include inactive values (default: false) |

</details>

<details>
<summary><strong>Employee Lookup Tools</strong></summary>

#### `get_employee_profile`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | Employee user ID |
| `include_compensation` | boolean | No | Include compensation (default: false) |

#### `search_employees`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `search_text` | string | No | Partial name search |
| `department` | string | No | Filter by department |
| `location` | string | No | Filter by location |
| `manager_id` | string | No | Filter to manager's reports |
| `status` | string | No | `active`, `inactive`, or `all` (default: `active`) |
| `top` | integer | No | Max results (default: 50, max: 200) |

#### `get_employee_history`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | Employee user ID |
| `include_compensation_changes` | boolean | No | Include salary history (default: false) |

#### `get_team_roster`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `manager_id` | string | Yes | Manager's user ID |
| `include_indirect_reports` | boolean | No | Include reports-of-reports (default: false) |
| `top` | integer | No | Max direct reports (default: 100, max: 200) |

</details>

<details>
<summary><strong>Time Off Tools</strong></summary>

#### `get_time_off_balances`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_ids` | string | Yes | Comma-separated user IDs (max 50) |
| `as_of_date` | string | No | Balance as of date (YYYY-MM-DD) |

#### `get_upcoming_time_off`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `start_date` | string | Yes | Range start (YYYY-MM-DD) |
| `end_date` | string | Yes | Range end (YYYY-MM-DD) |
| `department` | string | No | Filter by department |
| `manager_id` | string | No | Filter to manager's team |
| `status` | string | No | `approved`, `pending`, or `all` (default: `approved`) |
| `top` | integer | No | Max results (default: 200, max: 500) |

#### `get_time_off_requests`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | No | Filter to employee |
| `status` | string | No | `pending`, `approved`, `rejected`, `cancelled`, or `all` (default: `pending`) |
| `from_date` | string | No | Submitted after date (YYYY-MM-DD) |
| `top` | integer | No | Max results (default: 50, max: 200) |

</details>

<details>
<summary><strong>Hiring & Onboarding Tools</strong></summary>

#### `get_open_requisitions`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `department` | string | No | Filter by department |
| `hiring_manager_id` | string | No | Filter by hiring manager |
| `location` | string | No | Filter by location |
| `status` | string | No | `open`, `filled`, `closed`, or `all` (default: `open`) |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_candidate_pipeline`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requisition_id` | string | Yes | Job requisition ID |
| `include_rejected` | boolean | No | Include rejected candidates (default: false) |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_new_hires`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `start_date_from` | string | Yes | Hires on/after date (YYYY-MM-DD) |
| `start_date_to` | string | Yes | Hires on/before date (YYYY-MM-DD) |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

</details>

<details>
<summary><strong>Compliance & Reporting Tools</strong></summary>

#### `get_terminations`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `from_date` | string | Yes | Range start (YYYY-MM-DD) |
| `to_date` | string | Yes | Range end (YYYY-MM-DD) |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_employees_missing_data`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `check_fields` | string | Yes | Comma-separated: `email`, `phone`, `address`, `emergency_contact` |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_anniversary_employees`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `from_date` | string | Yes | Range start (YYYY-MM-DD) |
| `to_date` | string | Yes | Range end (YYYY-MM-DD) |
| `milestone_years_only` | boolean | No | Only 1, 5, 10, 15, 20, 25+ years (default: false) |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

</details>

<details>
<summary><strong>Performance & Compensation Tools</strong></summary>

#### `get_performance_review_status`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `form_template_id` | string | No | Filter by form template |
| `department` | string | No | Filter by department |
| `manager_id` | string | No | Filter by manager |
| `status` | string | No | `not_started`, `in_progress`, `completed`, or `""` for all |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_compensation_details`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_ids` | string | Yes | Comma-separated user IDs (max 20) |
| `effective_date` | string | No | Compensation as of date (YYYY-MM-DD) |

</details>

<details>
<summary><strong>Position Management Tools</strong></summary>

#### `get_position_details`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `position_id` | string | Yes | Position ID |

#### `get_vacant_positions`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `department` | string | No | Filter by department |
| `location` | string | No | Filter by location |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_org_chart`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `position_id` | string | Yes | Starting position ID |
| `direction` | string | No | `down` or `up` (default: `down`) |
| `levels` | integer | No | Levels to traverse (default: 2, max: 5) |

</details>

<details>
<summary><strong>MDF Object Tools</strong></summary>

#### `get_mdf_object_definitions`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `object_name` | string | No | Specific MDF object (e.g., `cust_myObject`). Empty = list all. |

#### `query_mdf_object`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `object_name` | string | Yes | MDF object name (e.g., `cust_myObject`) |
| `select` | string | No | Comma-separated fields |
| `filter` | string | No | OData filter |
| `top` | integer | No | Max results (default: 100, max: 500) |
| `skip` | integer | No | Pagination offset |
| `orderby` | string | No | Sort order |
| `effective_date` | string | No | Effective date filter (YYYY-MM-DD) |

#### `get_foundation_objects`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `object_type` | string | Yes | `company`, `department`, `division`, `location`, `cost_center`, `job_code`, `job_function`, `pay_grade`, `pay_group`, `business_unit`, `event_reason`, `legal_entity` |
| `filter` | string | No | Additional OData filter |
| `top` | integer | No | Max results (default: 100, max: 500) |
| `include_inactive` | boolean | No | Include end-dated records (default: false) |

</details>

<details>
<summary><strong>Workflow Tools</strong></summary>

#### `get_pending_approvals`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | No | Filter to specific approver |
| `wf_request_id` | string | No | Filter to specific workflow request |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_workflow_history`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `wf_request_id` | string | Yes | Workflow request ID |
| `top` | integer | No | Max results (default: 100, max: 500) |

</details>

<details>
<summary><strong>Monitoring & Admin Tools</strong></summary>

#### `get_alert_notifications`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `from_date` | string | No | Start date (YYYY-MM-DD) |
| `to_date` | string | No | End date (YYYY-MM-DD) |
| `top` | integer | No | Max results (default: 100, max: 500) |

#### `get_scheduled_job_status`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `job_name` | string | No | Filter by job name |
| `top` | integer | No | Max results (default: 50, max: 500) |

#### `get_integration_center_jobs`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `job_name` | string | No | Filter by job name |
| `status` | string | No | Filter by status |
| `top` | integer | No | Max results (default: 50, max: 500) |

#### `get_api_quota_status`

Returns current rate limit usage for the specified instance.

#### `get_cache_status`

Returns cache hit rates, entry counts by category, and memory usage.

#### `clear_cache`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target_instance` | string | No | Clear specific instance. Empty = clear all. |

</details>

## Example Queries

Ask Claude in natural language:

| Query | Tool Used |
|-------|-----------|
| "Show me all users in the Sales department" | `search_employees` |
| "What permissions does jsmith have?" | `get_user_permissions` |
| "Compare User config between dev and prod" | `compare_configurations` |
| "Who's on vacation next week?" | `get_upcoming_time_off` |
| "List all open job requisitions for Engineering" | `get_open_requisitions` |
| "How much PTO does jdoe have left?" | `get_time_off_balances` |
| "Show me all new hires starting in March" | `get_new_hires` |
| "Who has a 10-year anniversary this month?" | `get_anniversary_employees` |
| "What are the status of performance reviews for my team?" | `get_performance_review_status` |
| "Show John's complete job history" | `get_employee_history` |
| "What custom MDF objects exist in our instance?" | `get_mdf_object_definitions` |
| "List all departments with their cost centers" | `get_foundation_objects` |
| "Are there any pending workflow approvals?" | `get_pending_approvals` |
| "Check the status of our integration jobs" | `get_integration_center_jobs` |

## Common SuccessFactors Entities

| Category | Entities |
|----------|----------|
| **Employee** | User, EmpEmployment, EmpJob, PerPersonal, PerPhone, PerEmail |
| **Foundation** | FOCompany, FODepartment, FOJobCode, FOLocation, FOPayGrade |
| **Position** | Position, PositionEntity, PositionMatrixRelationship |
| **Talent** | Goal, GoalPlan, PerformanceReview, Competency |
| **Recruiting** | JobRequisition, Candidate, JobApplication |

Use `list_entities` to discover all available entities in your instance.

## Troubleshooting

<details>
<summary><strong>Authentication Errors (HTTP 401)</strong></summary>

- Verify credential format: user ID **without** `@instance`
- Confirm the password is correct
- Ensure the API user has proper permissions in SuccessFactors Admin Center

</details>

<details>
<summary><strong>Validation Errors</strong></summary>

All inputs are validated to prevent injection attacks:

| Parameter | Rules |
|-----------|-------|
| `instance` | Alphanumeric, underscores, hyphens only |
| `entity` | Valid OData entity name pattern |
| `filter` | No blocked keywords (`$batch`, `$metadata`, `<script>`, etc.) |
| `locale` | Format like `en-US` or `de` |
| `select` / `orderby` | Valid field name patterns |

</details>

<details>
<summary><strong>Server Disconnected (Claude Desktop)</strong></summary>

1. Verify `uv` path in config is correct: `which uv`
2. Check logs: `tail -f ~/Library/Logs/Claude/mcp*.log`
3. Test manually: `uv run mcp dev main.py`
4. Ensure Python 3.10+ is installed: `python3 --version`

</details>

<details>
<summary><strong>Rate Limit Errors</strong></summary>

- The server auto-retries HTTP 429 responses (up to 3 times)
- Use `get_api_quota_status` to check current usage
- Increase limits via `SF_RATE_LIMIT` environment variable
- Cache responses with `SF_CACHE_TTL_DEFAULT` to reduce API calls

</details>

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [fastmcp](https://gofastmcp.com) | >=2.0.0 | Model Context Protocol SDK |
| [requests](https://requests.readthedocs.io) | >=2.31.0 | HTTP client with connection pooling |
| [defusedxml](https://github.com/tiran/defusedxml) | >=0.7.0 | XXE-safe XML parsing |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | >=1.0.0 | Environment variable loading |
| [uvicorn](https://www.uvicorn.org) | >=0.30.0 | ASGI server for HTTP transport |

**Dev dependencies:** pytest, ruff, mypy

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Run tests: `uv run pytest tests/ -v`
4. Run linting: `uv run ruff check .`
5. Commit your changes
6. Open a Pull Request

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with <a href="https://gofastmcp.com">FastMCP</a> &middot;
  Powered by <a href="https://modelcontextprotocol.io">Model Context Protocol</a>
</p>
