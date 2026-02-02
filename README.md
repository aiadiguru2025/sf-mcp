# SF-MCP: SAP SuccessFactors MCP Server

A secure Model Context Protocol (MCP) server providing 14 tools for querying and managing SAP SuccessFactors via OData APIs.

## Overview

This MCP server enables Claude Desktop (or any MCP-compatible client) to interact with SAP SuccessFactors. It provides tools for configuration management, role-based permissions (RBP), data querying, and cross-instance comparison.

## Features

### Tools (14 total)

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

### Security Features

- **Input Validation**: Regex-based validation prevents OData injection attacks
- **XXE Protection**: Uses `defusedxml` library for safe XML parsing
- **Audit Logging**: JSON-structured logs compatible with Cloud Logging
- **Per-Request Authentication**: Credentials required on every tool call (no stored defaults)

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

Add to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

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

**Note:** Credentials (`auth_user_id` and `auth_password`) must be provided on each tool call.

For Cloud Run deployment:
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

## Project Structure

```
sf-mcp/
├── main.py              # MCP server with 14 tools
├── pyproject.toml       # Project dependencies
├── uv.lock              # Dependency lock file
├── Dockerfile           # Container image for Cloud Run
├── .env                 # Local credentials (gitignored)
├── .gitignore           # Git ignore rules
└── README.md            # This documentation
```

## Dependencies

- `fastmcp>=2.0.0` - Model Context Protocol SDK
- `requests>=2.31.0` - HTTP client library
- `defusedxml>=0.7.0` - Safe XML parsing (XXE protection)
- `python-dotenv>=1.0.0` - Environment variable loader
- `uvicorn>=0.30.0` - ASGI server for HTTP transport

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
