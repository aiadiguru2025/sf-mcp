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
- **Secret Manager**: GCP Secret Manager integration for credential storage
- **Credential Flexibility**: Pass credentials per-request or use environment defaults

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

3. **Configure credentials**

   Credentials can be provided in three ways (in order of precedence):

   1. **Per-request parameters**: `auth_user_id` and `auth_password` on each tool call
   2. **Environment variables**: `SF_USER_ID` and `SF_PASSWORD`
   3. **GCP Secret Manager**: Secrets named `sf-user-id` and `sf-password`

   | Variable | Required | Description |
   |----------|----------|-------------|
   | `SF_USER_ID` | Yes* | Your SuccessFactors user ID (without @instance) |
   | `SF_PASSWORD` | Yes* | Your SuccessFactors password |
   | `SF_API_HOST` | No | API host (defaults to `api55preview.sapsf.eu`) |

   *Required unless using per-request credentials or Secret Manager

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
      ],
      "env": {
        "SF_USER_ID": "your_user_id",
        "SF_PASSWORD": "your_password"
      }
    }
  }
}
```

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
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `category` | string | No | Filter: "foundation", "employee", "talent", "platform", or "all" |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `environment1` | string | No | Environment for instance1 (default: preview) |
| `environment2` | string | No | Environment for instance2 (default: production) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `include_description` | boolean | No | Include role descriptions (default: false) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

---

#### get_role_permissions

Gets permissions assigned to specific RBP roles. Supports multiple role IDs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `role_ids` | string | Yes | Single ID or comma-separated: "10" or "10,20,30" |
| `locale` | string | No | Locale for labels (default: en-US) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

---

#### get_user_permissions

Gets all permissions for specific users based on their assigned roles.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_ids` | string | Yes | Single ID or comma-separated: "admin" or "admin,user2" |
| `locale` | string | No | Locale for labels (default: en-US) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

---

#### get_user_roles

Gets all RBP roles assigned to a specific user.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `user_id` | string | Yes | User ID to look up roles for |
| `include_permissions` | boolean | No | Also fetch permissions for each role (default: false) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `locale` | string | No | Locale for labels (default: en-US) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `perm_long_value` | string | No | Permission long value (default: -1L) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

---

#### get_dynamic_groups

Lists dynamic groups (permission groups) used in RBP rules.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `group_type` | string | No | Filter by group type |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

---

### RBP Audit Tools

#### get_role_history

View modification history for RBP roles - who changed what and when.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | SuccessFactors company ID |
| `role_id` | string | No | Filter by specific role ID |
| `role_name` | string | No | Filter by role name (alternative to role_id) |
| `from_date` | string | No | Start date filter (YYYY-MM-DD) |
| `to_date` | string | No | End date filter (YYYY-MM-DD) |
| `top` | integer | No | Max records (default: 100, max: 500) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `role_id` | string | No | Filter assignments for a specific role |
| `user_id` | string | No | Filter assignments for a specific user |
| `from_date` | string | No | Start date filter (YYYY-MM-DD) |
| `to_date` | string | No | End date filter (YYYY-MM-DD) |
| `top` | integer | No | Max records (default: 100, max: 500) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `select` | string | No | Fields to return: "userId,firstName,lastName" |
| `filter` | string | No | OData filter: "status eq 'active'" |
| `expand` | string | No | Navigation properties: "empInfo,jobInfoNav" |
| `top` | integer | No | Max records (default: 100, max: 1000) |
| `skip` | integer | No | Records to skip for pagination |
| `orderby` | string | No | Sort: "lastName asc" or "hireDate desc" |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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
| `locale` | string | No | Locale for labels (default: en-US) |
| `include_inactive` | boolean | No | Include inactive values (default: false) |
| `environment` | string | No | "preview" or "production" (default: preview) |
| `auth_user_id` | string | No | Override default credentials |
| `auth_password` | string | No | Override default credentials |

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

### Deploy with Secret Manager (Recommended)

```bash
# Set project
export PROJECT_ID=your-gcp-project-id
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable secretmanager.googleapis.com run.googleapis.com

# Create secrets
echo -n "your_user_id" | gcloud secrets create sf-user-id --data-file=-
echo -n "your_password" | gcloud secrets create sf-password --data-file=-

# Grant access to Cloud Run service account
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud secrets add-iam-policy-binding sf-user-id \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
gcloud secrets add-iam-policy-binding sf-password \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Build and deploy
gcloud builds submit --tag gcr.io/$PROJECT_ID/sf-mcp
gcloud run deploy sf-mcp \
  --image gcr.io/$PROJECT_ID/sf-mcp \
  --platform managed \
  --region us-central1 \
  --set-env-vars "GCP_PROJECT_ID=$PROJECT_ID"
```

### Local Testing with Docker

```bash
# Build the image
docker build -t sf-mcp .

# Run locally
docker run -p 8080:8080 \
  -e SF_USER_ID=your_user \
  -e SF_PASSWORD=your_pass \
  sf-mcp

# Test endpoint
curl http://localhost:8080/mcp
```

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
- **Secret Manager**: Production credentials stored in GCP Secret Manager
- **No Hardcoded Secrets**: Credentials from environment or parameters only
- **Minimal Permissions**: Use dedicated API user with required permissions only

---

## License

MIT License
