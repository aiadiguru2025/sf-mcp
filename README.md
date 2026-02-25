# SF-MCP: SAP SuccessFactors MCP Server

A secure Model Context Protocol (MCP) server providing 40 tools for querying and managing SAP SuccessFactors via OData APIs.

## Overview

This MCP server enables Claude Desktop (or any MCP-compatible client) to interact with SAP SuccessFactors. It provides tools for configuration management, role-based permissions (RBP), data querying, HR operations, and cross-instance comparison.

## Features

### Tools (40 total)

| Category | Tool | Description |
|----------|------|-------------|
| **Configuration** | `get_configuration` | Retrieve OData metadata for any entity |
| **Configuration** | `list_entities` | Discover all available OData entities |
| **Configuration** | `compare_configurations` | Compare entity config between instances |
| **RBP Security** | `get_rbp_roles` | List all Role-Based Permission roles |
| **RBP Security** | `get_role_permissions` | Get permissions for specific roles |
| **RBP Security** | `get_user_permissions` | Get all permissions for a user |
| **RBP Security** | `get_user_roles` | Get roles assigned to a user |
| **RBP Security** | `get_permission_metadata` | Map UI labels to permission types |
| **RBP Security** | `check_user_permission` | Check if user has specific permission |
| **RBP Security** | `get_dynamic_groups` | List permission groups (dynamic groups) |
| **RBP Audit** | `get_role_history` | View modification history for roles |
| **RBP Audit** | `get_role_assignment_history` | View history of role assignments |
| **Data Query** | `query_odata` | Flexible OData queries with filtering |
| **Data Validation** | `get_picklist_values` | Get dropdown/picklist options |
| **Employee Lookup** | `get_employee_profile` | Get complete employee profile with job info and manager |
| **Employee Lookup** | `search_employees` | Find employees by name, department, location, or manager |
| **Employee Lookup** | `get_employee_history` | View job history (promotions, transfers, title changes) |
| **Employee Lookup** | `get_team_roster` | Get a manager's team roster with direct/indirect reports |
| **Time Off** | `get_time_off_balances` | Check vacation/PTO/sick leave balances |
| **Time Off** | `get_upcoming_time_off` | See who's out in a date range (absence calendar) |
| **Time Off** | `get_time_off_requests` | View pending time-off requests for approval tracking |
| **Hiring** | `get_open_requisitions` | List job requisitions with status and hiring manager |
| **Hiring** | `get_candidate_pipeline` | Track candidates through hiring stages |
| **Hiring** | `get_new_hires` | List recent/upcoming new hires for onboarding |
| **Compliance** | `get_terminations` | List terminated employees for exit processing |
| **Compliance** | `get_employees_missing_data` | Find employees with incomplete profiles |
| **Compliance** | `get_anniversary_employees` | Find upcoming work anniversaries for recognition |
| **Performance** | `get_performance_review_status` | Track review form completion across the org |
| **Compensation** | `get_compensation_details` | Get compensation breakdown with pay components |
| **Position Mgmt** | `get_position_details` | Get position details with incumbent, department, FTE |
| **Position Mgmt** | `get_vacant_positions` | List vacant positions for headcount planning |
| **Position Mgmt** | `get_org_chart` | Build org hierarchy from a position (up or down) |
| **MDF Objects** | `get_mdf_object_definitions` | List custom MDF objects and their fields |
| **MDF Objects** | `query_mdf_object` | Query data from any MDF/generic object (cust_*) |
| **MDF Objects** | `get_foundation_objects` | Query foundation objects (cost centers, departments, etc.) |
| **Workflow** | `get_pending_approvals` | Get pending workflow approval items for a user or globally |
| **Workflow** | `get_workflow_history` | Audit trail of approval steps for workflow requests |
| **Admin** | `get_api_quota_status` | Check API rate limit usage per instance |
| **Admin** | `get_cache_status` | View cache hit rates and entry counts |
| **Admin** | `clear_cache` | Clear cached responses (per-instance or all) |

### Security Features

- **Input Validation**: Regex-based validation prevents OData injection attacks
- **XXE Protection**: Uses `defusedxml` library for safe XML parsing
- **Audit Logging**: JSON-structured logs compatible with Cloud Logging
- **Per-Request Authentication**: Credentials required on every tool call (no stored defaults)

### Rate Limiting

- **Sliding window** algorithm tracks requests per instance over a configurable time window
- **429 retry** — automatic retry with exponential backoff when the SF API returns HTTP 429
- **Configurable** via environment variables: `SF_RATE_LIMIT` (default 100), `SF_RATE_LIMIT_WINDOW` (default 60s), `SF_RATE_LIMIT_MAX_RETRIES` (default 3)
- **Warning threshold** logs alerts when usage exceeds 80% of the limit (configurable via `SF_RATE_LIMIT_WARN_THRESHOLD`)

### Response Caching

- **Category-based TTLs** — metadata (1h), service docs (1h), picklists (30m), permissions (1h), default (disabled)
- **Cache keys** use SHA-256 of (instance, endpoint, params) — credentials are never included in keys
- **Auto-eviction** removes the oldest 10% of entries when `SF_CACHE_MAX_ENTRIES` (default 1000) is reached
- **Audit logging** on all cache operations for observability
- Use `clear_cache` tool or `get_cache_status` tool for runtime management

### Automatic Pagination

- Set `paginate=True` on `query_odata` to automatically fetch multiple pages of results
- Configurable `max_pages` per request (default 10, max 50)
- Returns partial results with error details if a mid-pagination API error occurs
- Manages `$skip`/`$top` internally — existing values in params are overridden

## Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/) package manager
- SAP SuccessFactors account with API access

## Installation

1. **Clone or download this repository**

2. **Install dependencies**
   ```bash
   cd sf-mcp
   uv sync
   ```

3. **Authentication & Configuration**

   Each tool call requires the following parameters:
   - `data_center`: SAP data center code (e.g., `DC55`, `DC10`, `DC4`)
   - `environment`: Environment type (`preview`, `production`, or `sales_demo`)
   - `auth_user_id`: Your SuccessFactors user ID (without @instance)
   - `auth_password`: Your SuccessFactors password

   **Note:** All connection parameters are provided by the MCP client on each tool call. No server-side configuration required.

## Supported Data Centers

| Data Center | Alias | Location | Environments |
|-------------|-------|----------|--------------|
| DC10 | DC66 | Sydney, Australia | preview, production |
| DC12 | DC33 | Germany | preview, production |
| DC15 | DC30 | Shanghai, China | preview, production |
| DC17 | DC60 | Toronto, Canada | preview, production |
| DC19 | DC62 | São Paulo, Brazil | preview, production |
| DC2 | DC57 | Netherlands | preview, production, sales_demo |
| DC22 | - | Dubai, UAE | preview, production |
| DC23 | DC84 | Riyadh, Saudi Arabia | preview, production |
| DC4 | DC68 | Virginia, US | preview, production, sales_demo |
| DC40 | - | - | sales_demo |
| DC41 | - | Virginia, US | preview, production |
| DC44 | DC52 | Singapore | preview, production |
| DC47 | - | Canada Central | preview, production |
| DC50 | - | Tokyo, Japan | preview, production |
| DC55 | - | Frankfurt, Germany | preview, production |
| DC74 | - | Zurich, Switzerland | preview, production |
| DC8 | DC70 | Ashburn, Virginia, US | preview, production, sales_demo |
| DC80 | - | Mumbai, India | preview, production |
| DC82 | - | Riyadh, Saudi Arabia | preview, production |

## Usage

### Running with MCP Dev Server

For development and testing:
```bash
uv run mcp dev main.py
```

### Running Standalone

```bash
uv run main.py
```

### Claude Desktop Integration

Follow these steps to add the SuccessFactors MCP server to Claude Desktop:

#### Step 1: Locate Your Configuration File

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

If the file doesn't exist, create it.

#### Step 2: Find the Path to `uv`

Run this command in your terminal to find where `uv` is installed:

```bash
# macOS/Linux
which uv

# Windows (PowerShell)
Get-Command uv | Select-Object -ExpandProperty Source
```

#### Step 3: Add the MCP Server Configuration

Edit your `claude_desktop_config.json` file and add the sf-mcp server:

```json
{
  "mcpServers": {
    "sf-mcp": {
      "command": "/path/to/uv",
      "args": [
        "--directory",
        "/path/to/sf-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

**Example with actual paths (macOS):**
```json
{
  "mcpServers": {
    "sf-mcp": {
      "command": "/Users/yourusername/.local/bin/uv",
      "args": [
        "--directory",
        "/Users/yourusername/projects/sf-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

**Example with actual paths (Windows):**
```json
{
  "mcpServers": {
    "sf-mcp": {
      "command": "C:\\Users\\yourusername\\.local\\bin\\uv.exe",
      "args": [
        "--directory",
        "C:\\Users\\yourusername\\projects\\sf-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

#### Step 4: Restart Claude Desktop

Completely quit and restart Claude Desktop for the changes to take effect.

#### Step 5: Verify the Connection

In Claude Desktop, you should see the MCP tools icon (hammer) in the input area. Click it to see the 32 SuccessFactors tools available.

**Note:** Credentials (`auth_user_id` and `auth_password`) must be provided on each tool call - they are not stored in the configuration.

#### Cloud Run Deployment (Alternative)

For remote deployment via Google Cloud Run:
```json
{
  "mcpServers": {
    "sf-mcp": {
      "url": "https://sf-mcp-xxxxx-uc.a.run.app/mcp"
    }
  }
}
```

---

## Tool Reference

### Configuration Tools

#### get_configuration

Retrieves OData metadata for a specified SuccessFactors entity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `entity` | string | Yes | OData entity name (e.g., "User", "Position") |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |

**Example:**
```
Get the configuration metadata for the "User" entity in instance "mycompany"
```

---

#### list_entities

Discover all available OData entities in an instance.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `category` | string | No | Filter: "foundation", "employee", "talent", "platform", or "all" |

**Response:**
```json
{
  "entities": ["User", "Position", "EmpEmployment", ...],
  "count": 150,
  "total_available": 500,
  "by_category": {
    "foundation": 85,
    "employee": 120,
    "talent": 45,
    "platform": 30,
    "other": 220
  }
}
```

---

#### compare_configurations

Compare entity configuration between two instances (e.g., dev vs prod).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance1` | string | Yes | First instance (e.g., dev) |
| `instance2` | string | Yes | Second instance (e.g., prod) |
| `entity` | string | Yes | Entity to compare |
| `data_center1` | string | Yes | SAP data center for instance1 (e.g., "DC55") |
| `environment1` | string | Yes | Environment for instance1 (e.g., "preview") |
| `data_center2` | string | Yes | SAP data center for instance2 (e.g., "DC55") |
| `environment2` | string | Yes | Environment for instance2 (e.g., "production") |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |

**Response:**
```json
{
  "entity": "User",
  "comparison": {
    "fields_only_in_instance1": ["customField1"],
    "fields_only_in_instance2": ["customField2"],
    "fields_in_both": 45,
    "type_differences": [],
    "match_percentage": 95.5
  },
  "summary": {
    "is_identical": false,
    "differences_found": 2
  }
}
```

---

### RBP Security Tools

#### get_rbp_roles

Lists all Role-Based Permission roles.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `include_description` | boolean | No | Include role descriptions (default: false) |

---

#### get_role_permissions

Gets permissions assigned to specific RBP roles. Supports multiple role IDs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `role_ids` | string | Yes | Single ID or comma-separated: "10" or "10,20,30" |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `locale` | string | No | Locale for labels (default: en-US) |

---

#### get_user_permissions

Gets all permissions for specific users based on their assigned roles.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_ids` | string | Yes | Single ID or comma-separated: "admin" or "admin,user2" |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `locale` | string | No | Locale for labels (default: en-US) |

---

#### get_user_roles

Gets all RBP roles assigned to a specific user.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_id` | string | Yes | User ID to look up roles for |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `include_permissions` | boolean | No | Also fetch permissions for each role (default: false) |

**Response:**
```json
{
  "user_id": "admin",
  "roles": [
    {"roleId": "10", "roleName": "Administrator", "roleDesc": "Full access"},
    {"roleId": "20", "roleName": "HR Manager", "roleDesc": "HR functions"}
  ],
  "role_count": 2
}
```

---

#### get_permission_metadata

Maps UI labels to permission types and values.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `locale` | string | No | Locale for labels (default: en-US) |

---

#### check_user_permission

Check if a user has a specific permission for a target user.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `access_user_id` | string | Yes | User whose permission to check |
| `target_user_id` | string | Yes | Target user of the permission |
| `perm_type` | string | Yes | Permission type from metadata |
| `perm_string_value` | string | Yes | Permission string value |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `perm_long_value` | string | No | Permission long value (default: -1L) |

---

#### get_dynamic_groups

Lists dynamic groups (permission groups) used in RBP rules.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `group_type` | string | No | Filter by group type |

---

### RBP Audit Tools

#### get_role_history

View modification history for RBP roles - who changed what and when.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `role_id` | string | No | Filter by specific role ID |
| `role_name` | string | No | Filter by role name (alternative to role_id) |
| `from_date` | string | No | Start date filter (YYYY-MM-DD) |
| `to_date` | string | No | End date filter (YYYY-MM-DD) |
| `top` | integer | No | Max records (default: 100, max: 500) |

**Response:**
```json
{
  "filters_applied": {
    "role_id": "10",
    "from_date": "2024-01-01"
  },
  "history": [
    {
      "role_id": "10",
      "role_name": "HR Manager",
      "role_description": "Human Resources management role",
      "user_type": "employee",
      "last_modified_by": "admin",
      "last_modified_date": "2024-03-15T10:30:00+00:00",
      "created_by": "admin",
      "created_date": "2023-01-01T09:00:00+00:00"
    }
  ],
  "count": 1
}
```

---

#### get_role_assignment_history

View history of role assignments - who was granted roles and when.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `role_id` | string | No | Filter assignments for a specific role |
| `user_id` | string | No | Filter assignments for a specific user |
| `from_date` | string | No | Start date filter (YYYY-MM-DD) |
| `to_date` | string | No | End date filter (YYYY-MM-DD) |
| `top` | integer | No | Max records (default: 100, max: 500) |

**Examples:**
```
# Get all assignments for a role
role_id="10"

# Get all roles assigned to a user
user_id="admin"

# Audit recent assignments
from_date="2024-01-01", to_date="2024-12-31"
```

**Response:**
```json
{
  "filters_applied": {
    "role_id": "10",
    "user_id": null,
    "from_date": "2024-01-01"
  },
  "assignments": [
    {
      "user_id": "emp001",
      "role_id": "10",
      "role_name": "HR Manager",
      "role_description": "Human Resources management role",
      "user_type": "employee",
      "assigned_by": "admin",
      "assigned_date": "2024-02-01T14:00:00+00:00",
      "last_modified_by": "admin",
      "last_modified_date": "2024-02-01T14:00:00+00:00"
    }
  ],
  "count": 1
}
```

---

### Data Query Tools

#### query_odata

Execute flexible OData queries against any SuccessFactors entity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `entity` | string | Yes | Entity name or entity with key: "User" or "User('admin')" |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `select` | string | No | Fields to return: "userId,firstName,lastName" |
| `filter` | string | No | OData filter: "status eq 'active'" |
| `expand` | string | No | Navigation properties: "empInfo,jobInfoNav" |
| `top` | integer | No | Max records (default: 100, max: 1000) |
| `skip` | integer | No | Records to skip for pagination |
| `orderby` | string | No | Sort: "lastName asc" or "hireDate desc" |

**Examples:**
```
# Get active users
entity="User", filter="status eq 'active'", select="userId,firstName,lastName"

# Get single user with expanded info
entity="User('admin')", expand="empInfo"

# Paginate through positions
entity="Position", top=100, skip=100
```

**Response:**
```json
{
  "entity": "User",
  "results": [...],
  "count": 100,
  "next_skip": 200
}
```

---

### Data Validation Tools

#### get_picklist_values

Get all values for a specific picklist (dropdown options).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `picklist_id` | string | Yes | Picklist ID: "ecJobFunction", "nationality" |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `locale` | string | No | Locale for labels (default: en-US) |
| `include_inactive` | boolean | No | Include inactive values (default: false) |

**Common Picklists:**
- `ecJobFunction` - Job functions
- `ecJobCode` - Job codes
- `ecPayGrade` - Pay grades
- `ecDepartment` - Departments
- `nationality` - Countries/nationalities
- `maritalStatus` - Marital status options

**Response:**
```json
{
  "picklist_id": "nationality",
  "locale": "en-US",
  "values": [
    {"id": "US", "externalCode": "US", "label": "United States", "status": "active"},
    {"id": "UK", "externalCode": "UK", "label": "United Kingdom", "status": "active"}
  ],
  "count": 195,
  "has_inactive": true
}
```

---

### Employee Lookup Tools

#### get_employee_profile

Get a complete employee profile including job info, contact details, and manager.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_id` | string | Yes | Employee's user ID (e.g., "jsmith") |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type: "preview", "production", or "sales_demo" |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `include_compensation` | boolean | No | Include current compensation details (default: false) |

---

#### search_employees

Find employees by name, department, location, or manager.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center (e.g., "DC55", "DC10") |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `search_text` | string | No | Partial name to search across first/last/display name |
| `department` | string | No | Filter by department |
| `location` | string | No | Filter by location |
| `manager_id` | string | No | Filter to a manager's direct reports |
| `status` | string | No | "active", "inactive", or "all" (default: "active") |
| `top` | integer | No | Max results (default: 50, max: 200) |

---

#### get_employee_history

View an employee's job history including promotions, transfers, and title changes.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_id` | string | Yes | Employee's user ID |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `include_compensation_changes` | boolean | No | Include salary history (default: false) |

---

#### get_team_roster

Get a manager's team roster with direct and optionally indirect reports.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `manager_id` | string | Yes | Manager's user ID |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `include_indirect_reports` | boolean | No | Include reports-of-reports (default: false) |
| `top` | integer | No | Max direct reports (default: 100, max: 200) |

---

### Time Off Tools

#### get_time_off_balances

Check vacation, PTO, and sick leave balances for one or more employees.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_ids` | string | Yes | Single or comma-separated user IDs (max 50) |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `as_of_date` | string | No | Check balance as of date (YYYY-MM-DD) |

---

#### get_upcoming_time_off

See who is out or taking time off in a date range (team absence calendar).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `start_date` | string | Yes | Start of date range (YYYY-MM-DD) |
| `end_date` | string | Yes | End of date range (YYYY-MM-DD) |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `department` | string | No | Filter by department |
| `manager_id` | string | No | Filter to manager's team |
| `status` | string | No | "approved", "pending", or "all" (default: "approved") |
| `top` | integer | No | Max results (default: 200, max: 500) |

---

#### get_time_off_requests

View time-off requests for approval tracking.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `user_id` | string | No | Filter to specific employee |
| `status` | string | No | "pending", "approved", "rejected", "cancelled", or "all" (default: "pending") |
| `from_date` | string | No | Only requests submitted after this date (YYYY-MM-DD) |
| `top` | integer | No | Max results (default: 50, max: 200) |

---

### Hiring & Onboarding Tools

#### get_open_requisitions

List job requisitions with status and hiring manager.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `department` | string | No | Filter by department |
| `hiring_manager_id` | string | No | Filter by hiring manager |
| `location` | string | No | Filter by location |
| `status` | string | No | "open", "filled", "closed", or "all" (default: "open") |
| `top` | integer | No | Max results (default: 100, max: 500) |

---

#### get_candidate_pipeline

Track candidates for a job requisition through hiring stages.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `requisition_id` | string | Yes | Job requisition ID |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `include_rejected` | boolean | No | Include rejected candidates (default: false) |
| `top` | integer | No | Max results (default: 100, max: 500) |

---

#### get_new_hires

List recent and upcoming new hires for onboarding planning.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `start_date_from` | string | Yes | Hires starting on/after this date (YYYY-MM-DD) |
| `start_date_to` | string | Yes | Hires starting on/before this date (YYYY-MM-DD) |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

---

### Compliance & Reporting Tools

#### get_terminations

List terminated employees in a date range for exit processing and compliance.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `from_date` | string | Yes | Start of date range (YYYY-MM-DD) |
| `to_date` | string | Yes | End of date range (YYYY-MM-DD) |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

---

#### get_employees_missing_data

Find employees with incomplete profiles for compliance audits.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `check_fields` | string | Yes | Comma-separated: "email", "phone", "address", "emergency_contact" |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

---

#### get_anniversary_employees

Find employees with upcoming work anniversaries for recognition programs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `from_date` | string | Yes | Start of anniversary search range (YYYY-MM-DD) |
| `to_date` | string | Yes | End of anniversary search range (YYYY-MM-DD) |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `milestone_years_only` | boolean | No | Only show 1, 5, 10, 15, 20, 25+ years (default: false) |
| `department` | string | No | Filter by department |
| `top` | integer | No | Max results (default: 100, max: 500) |

---

### Performance & Compensation Tools

#### get_performance_review_status

Track performance review form completion across the organization.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `form_template_id` | string | No | Filter by form template ID |
| `department` | string | No | Filter by department |
| `manager_id` | string | No | Filter by manager |
| `status` | string | No | "not_started", "in_progress", "completed", or "" for all |
| `top` | integer | No | Max results (default: 100, max: 500) |

---

#### get_compensation_details

Get compensation breakdown for employees including base pay and pay components.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_ids` | string | Yes | Single or comma-separated user IDs (max 20) |
| `data_center` | string | Yes | SAP data center |
| `environment` | string | Yes | Environment type |
| `auth_user_id` | string | Yes | SuccessFactors user ID for authentication |
| `auth_password` | string | Yes | SuccessFactors password for authentication |
| `effective_date` | string | No | Show compensation as of this date (YYYY-MM-DD) |

---

## Example Queries

Here are the top 10 questions you can ask Claude using this SuccessFactors MCP server:

### Top 10 SuccessFactors Queries

1. **"Show me all users in department 'Sales' with their job titles and manager information"**
   - Queries User and EmpJob entities with filters and navigation properties

2. **"What permissions does user 'jsmith' have in the system?"**
   - Uses `get_user_permissions` to see all effective permissions from assigned roles

3. **"Compare the User entity configuration between my dev instance (SFLAP012345) and production instance (PROD123)"**
   - Uses `compare_configurations` to identify configuration drift between environments

4. **"List all active employees hired in 2024 with their compensation details"**
   - Queries EmpEmployment/EmpJob with date filters and expansion to compensation data

5. **"Which users have both 'HR Role' and 'Manager Role' assigned?"**
   - Uses `get_user_roles` for multiple users to find role overlaps

6. **"Show me all available picklist values for 'ecJobCode' (Job Codes)"**
   - Uses `get_picklist_values` to see all job code options configured in the system

7. **"Get all employees reporting to manager 'asmith1' including their positions and locations"**
   - Queries User entity with manager filter and expands to job/location details

8. **"What are all the OData entities available in my SuccessFactors instance?"**
   - Uses `list_entities` to discover all queryable data entities

9. **"Show me the role modification history for the 'Recruiters' role in the last 6 months"**
   - Uses `get_role_history` with date filters to audit role changes

10. **"Check if user 'admin1' has permission to view payroll data for user 'jdoe'"**
    - Uses `check_user_permission` to verify specific access rights between users

### HR Operations Queries

11. **"Pull up the full profile for employee 'jsmith' including their compensation details"**
    - Uses `get_employee_profile` with `include_compensation=true`

12. **"Find all employees in the Marketing department"**
    - Uses `search_employees` with department filter

13. **"Show me who's on vacation next week"**
    - Uses `get_upcoming_time_off` with date range and status "approved"

14. **"What are the PTO balances for my team?"**
    - Uses `get_time_off_balances` with comma-separated user IDs

15. **"List all open job requisitions for the Engineering department"**
    - Uses `get_open_requisitions` with department filter

16. **"Show me all new hires starting in February 2026"**
    - Uses `get_new_hires` with start_date_from and start_date_to

17. **"Which employees are missing emergency contact information?"**
    - Uses `get_employees_missing_data` with check_fields="emergency_contact"

18. **"Who has a work anniversary this month? Show milestones only."**
    - Uses `get_anniversary_employees` with milestone_years_only=true

19. **"What's the status of performance reviews for my team?"**
    - Uses `get_performance_review_status` with manager_id filter

20. **"Show me John Smith's job history including all promotions"**
    - Uses `get_employee_history` to see chronological career progression

### Bonus Advanced Queries

- "Export all cost centers with their managers to analyze organizational structure"
- "Find all employees with expiring work permits in the next 90 days"
- "List all dynamic groups used in RBP rules"
- "Show me all fields in the Position entity that are marked as required"

These queries leverage the MCP server's capabilities for user management, permissions, HR operations, configuration analysis, and data extraction from your SuccessFactors system.

---

## Common SuccessFactors Entities

| Category | Entities |
|----------|----------|
| **Employee** | User, EmpEmployment, EmpJob, PerPersonal, PerPhone, PerEmail |
| **Foundation** | FOCompany, FODepartment, FOJobCode, FOLocation, FOPayGrade |
| **Position** | Position, PositionEntity, PositionMatrixRelationship |
| **Talent** | Goal, GoalPlan, PerformanceReview, Competency |
| **Recruiting** | JobRequisition, Candidate, JobApplication |

Use `list_entities` to discover all available entities in your instance.

---

## Cloud Deployment (Google Cloud Run)

### Prerequisites

- Google Cloud account with billing enabled
- [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) installed

### Deploy to Cloud Run

```bash
# Set project
export PROJECT_ID=your-gcp-project-id
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable run.googleapis.com

# Build and deploy
gcloud builds submit --tag gcr.io/$PROJECT_ID/sf-mcp
gcloud run deploy sf-mcp \
  --image gcr.io/$PROJECT_ID/sf-mcp \
  --platform managed \
  --region us-central1
```

**Note:** Credentials are provided on each tool call by the MCP client, not stored in the deployment.

### Local Testing with Docker

```bash
# Build the image
docker build -t sf-mcp .

# Run locally
docker run -p 8080:8080 sf-mcp

# Test endpoint
curl http://localhost:8080/mcp
```

**Note:** Credentials are provided on each tool call, not as Docker environment variables.

---

## Architecture

### Project Structure

```
sf-mcp/
├── main.py                          # Slim entry point (~40 lines)
├── sf_mcp/                          # Core package
│   ├── __init__.py                  # Re-exports mcp instance
│   ├── server.py                    # FastMCP instance creation
│   ├── config.py                    # DC mappings, constants, get_api_host()
│   ├── logging_config.py            # CloudLoggingFormatter, audit_log()
│   ├── validation.py                # Input validators with registry pattern
│   ├── auth.py                      # Credentials, API key, middleware
│   ├── rate_limiter.py               # Sliding-window rate limiter (per-instance)
│   ├── cache.py                     # TTL-based response cache with categories
│   ├── client.py                    # OData/metadata/service-doc HTTP clients
│   ├── xml_utils.py                 # Safe XML parsing (defusedxml), date parsing
│   ├── decorators.py                # sf_tool decorator (cross-cutting concerns)
│   ├── dependencies.py              # FastMCP Depends() DI for schema exclusion
│   └── tools/                       # Tool modules (40 tools across 12 files)
│       ├── __init__.py              # Imports all modules to trigger registration
│       ├── configuration.py         # get_configuration, compare_configurations, list_entities
│       ├── permissions.py           # 7 RBP security tools
│       ├── audit.py                 # get_role_history, get_role_assignment_history
│       ├── query.py                 # query_odata, get_picklist_values
│       ├── employee.py              # Profile, search, history, team roster
│       ├── time_off.py              # Balances, upcoming absences, requests
│       ├── recruiting.py            # Requisitions, pipeline, new hires
│       ├── compliance.py            # Terminations, missing data, anniversaries, reviews, comp
│       ├── position.py              # Position details, vacancies, org chart
│       ├── workflow.py              # Pending approvals, workflow history
│       ├── mdf.py                   # MDF object definitions, queries, foundation objects
│       └── admin.py                 # Rate limit quota, cache status, cache clear
├── tests/                           # Test suite (110 tests)
│   ├── conftest.py                  # Shared fixtures
│   ├── test_config.py              # DC mapping & constant tests
│   ├── test_validation.py          # All validator tests
│   ├── test_client.py              # Mocked HTTP client tests
│   ├── test_client_rate_limit.py   # Rate limiting & 429 retry tests
│   ├── test_cache.py              # Response cache tests
│   ├── test_pagination.py         # Automatic pagination tests
│   ├── test_rate_limiter.py       # Rate limiter unit tests
│   └── test_decorators.py          # sf_tool decorator behavior tests
├── pyproject.toml                   # Dependencies & pytest config
├── Dockerfile                       # Container image for Cloud Run
└── README.md                        # This documentation
```

### Design Principles

**Modular decomposition**: The original 4,778-line monolithic `main.py` has been decomposed into focused modules with single responsibilities. Production code reduced by ~50%.

**sf_tool decorator**: Eliminates ~400 lines of repeated boilerplate across 29 decorated tools. Each tool previously duplicated request ID generation, timing, audit logging, input validation, credential checking, and error handling. The decorator centralizes these cross-cutting concerns:

```python
@mcp.tool()
@sf_tool("get_rbp_roles")
def get_rbp_roles(
    instance: str, data_center: str, environment: str,
    auth_user_id: str, auth_password: str,
    include_description: bool = False,
    *, request_id: str = RequestId(), start_time: float = StartTime(), api_host: str = ApiHost(),
) -> dict[str, Any]:
    # Only business logic here - no boilerplate
    ...
```

**FastMCP Depends() injection**: Internal parameters (`request_id`, `start_time`, `api_host`) are hidden from the MCP tool schema using FastMCP's dependency injection system. The `Depends()` pattern replaces the deprecated `exclude_args` parameter.

**Validator registry**: Input validators are registered by name in a `VALIDATORS` dict, allowing the `sf_tool` decorator to apply additional validation via a declarative `validate={"locale": "locale"}` parameter.

**Consolidated HTTP clients**: Three request patterns (JSON OData, XML metadata, service document) are unified in `client.py` with shared auth, timeout, error handling, and audit logging.

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `config.py` | 50+ data center mappings, named constants, `get_api_host()` |
| `validation.py` | 10 regex-based validators + registry pattern |
| `logging_config.py` | Cloud Logging-compatible JSON formatter, audit trail |
| `auth.py` | Credential resolution, API key middleware |
| `rate_limiter.py` | Sliding-window rate limiter, per-instance tracking |
| `cache.py` | TTL-based response cache with category TTLs, eviction |
| `client.py` | OData request, metadata request, service doc, paginated request |
| `xml_utils.py` | XXE-safe XML parsing, SAP date parsing |
| `decorators.py` | `sf_tool` decorator for cross-cutting concerns |
| `dependencies.py` | FastMCP `Depends()` DI markers |

---

## Dependencies

- `fastmcp>=2.0.0` - Model Context Protocol SDK
- `requests>=2.31.0` - HTTP client library
- `defusedxml>=0.7.0` - Safe XML parsing (XXE protection)
- `python-dotenv>=1.0.0` - Environment variable loader
- `uvicorn>=0.30.0` - ASGI server for HTTP transport

### Dev Dependencies

- `pytest>=8.0.0` - Test framework
- `ruff>=0.9.0` - Linter and formatter
- `mypy>=1.14.0` - Static type checker

---

## Testing

Run the test suite:
```bash
uv run pytest tests/ -v
```

The test suite covers:
- **Config**: DC mapping resolution, case insensitivity, aliases, error cases
- **Validation**: All 10 validators with valid/invalid inputs, injection prevention
- **Client**: Mocked HTTP responses (200, 401, 500, empty, connection error)
- **Rate Limiter**: Limit enforcement, sliding window, per-instance isolation, thread safety
- **Cache**: Put/get, TTL expiry, category TTLs, invalidation, eviction, thread safety
- **Pagination**: Single/multi page, max_pages limit, error handling, $skip increments
- **Decorators**: Value injection, validation errors, max_top clamping, exception handling

---

## Troubleshooting

### Authentication Errors (HTTP 401)

- Verify credentials format: user ID without @instance
- Check password is correct
- Ensure API user has proper permissions in SuccessFactors

### Validation Errors

The server validates all inputs to prevent injection attacks. If you see validation errors:
- `instance`: Must contain only alphanumeric, underscores, hyphens
- `entity`: Must be valid OData entity name
- `filter`: Cannot contain blocked keywords ($batch, $metadata, script tags)
- `locale`: Must be format like "en-US" or "de"

### Server Disconnected

1. Verify `uv` path in config is correct
2. Check logs: `tail -f ~/Library/Logs/Claude/mcp*.log`
3. Test manually: `uv run mcp dev main.py`

---

## Security Considerations

- **Input Validation**: All parameters validated with regex patterns
- **XXE Protection**: XML parsing uses defusedxml library
- **Audit Logging**: All tool invocations logged in JSON format
- **Per-Request Authentication**: Credentials required on each tool call (no stored defaults)
- **Credential Masking**: Sensitive fields automatically masked in logs
- **Minimal Permissions**: Use dedicated API user with required permissions only

---

## License

MIT License
