# SF-MCP: SAP SuccessFactors MCP Server

A Model Context Protocol (MCP) server that provides tools for retrieving configuration metadata from SAP SuccessFactors OData APIs.

## Overview

This MCP server enables Claude Desktop (or any MCP-compatible client) to query SAP SuccessFactors entity metadata. It fetches OData `$metadata` endpoints and returns the configuration as structured JSON.

## Features

- **get_configuration**: Retrieve metadata for any SuccessFactors OData entity
- Automatic XML to JSON conversion
- Error handling with detailed error messages

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

   Credentials are configured via environment variables (never hardcode them):

   | Variable | Required | Description |
   |----------|----------|-------------|
   | `SF_USER_ID` | Yes | Your SuccessFactors user ID (without @instance) |
   | `SF_PASSWORD` | Yes | Your SuccessFactors password |
   | `SF_API_HOST` | No | API host (defaults to `api55preview.sapsf.eu`) |

   For local development, copy `.env.example` to `.env` and fill in your values:
   ```bash
   cp .env.example .env
   ```

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

Add the following to your Claude Desktop configuration file:

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
        "SF_PASSWORD": "your_password",
        "SF_API_HOST": "api55preview.sapsf.eu"
      }
    }
  }
}
```

> **Note**: Use the full path to `uv` (find it with `which uv` on macOS/Linux or `where uv` on Windows).

> **Security**: The `env` block in Claude Desktop config is stored locally and not synced. Replace placeholder values with your actual credentials.

After updating the config, restart Claude Desktop completely (Cmd+Q on macOS).

## Available Tools

### get_configuration

Retrieves OData metadata for a specified SuccessFactors entity.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `instance` | string | Yes | The SuccessFactors instance/company ID |
| `entity` | string | Yes | The OData entity name to retrieve metadata for |

**Example Usage in Claude:**

```
Get the configuration metadata for the "User" entity in instance "mycompany"
```

**Response:**

Returns a JSON object containing the parsed XML metadata, including:
- Entity type definitions
- Property definitions with types and constraints
- Navigation properties
- Associations and entity sets

**Error Responses:**

| Error | Description |
|-------|-------------|
| `HTTP 401` | Authentication failed - check credentials |
| `HTTP 403` | Access forbidden - user lacks permissions |
| `HTTP 404` | Entity not found |
| `Empty response` | API returned no data |
| `XML parse error` | Response was not valid XML |

## Common SuccessFactors Entities

Here are some commonly used OData entities you can query:

- `User` - Employee/user data
- `EmpEmployment` - Employment information
- `EmpJob` - Job information
- `Position` - Position management
- `JobRequisition` - Recruiting requisitions
- `Candidate` - Recruiting candidates
- `PerPersonal` - Personal information
- `PerPhone` - Phone numbers
- `PerEmail` - Email addresses
- `FOCompany` - Company foundation object
- `FODepartment` - Department foundation object
- `FOJobCode` - Job code foundation object

## Project Structure

```
sf-mcp/
├── main.py              # MCP server implementation
├── pyproject.toml       # Project dependencies
├── uv.lock              # Dependency lock file
├── .python-version      # Python version specification
├── .env.example         # Example environment variables
├── .gitignore           # Git ignore rules (includes .env)
└── README.md            # This documentation
```

## Dependencies

- `mcp[cli]>=1.25.0` - Model Context Protocol SDK
- `requests>=2.31.0` - HTTP client library
- `xmltodict>=0.13.0` - XML to dictionary parser

## Troubleshooting

### Server Disconnected Error

If Claude Desktop shows "server disconnected":

1. Verify `uv` path in config is correct (use full path)
2. Check Claude logs: `tail -f ~/Library/Logs/Claude/mcp*.log`
3. Test the server manually: `uv run mcp dev main.py`

### Authentication Errors (HTTP 401)

- Verify username format: `<user_id>@<company_id>`
- Check password is correct
- Ensure API user has proper permissions

### XML Parse Errors

The API may return HTML error pages instead of XML. The error response will include a preview of what was returned to help diagnose the issue.

### Empty Response

- Verify the entity name is correct
- Check the API URL host matches your datacenter

## Security Considerations

- **Environment variables**: Credentials are stored in environment variables, never in code
- **`.env` is gitignored**: The `.env` file is excluded from version control
- **Claude Desktop config**: Credentials in `claude_desktop_config.json` are stored locally only
- **Minimal permissions**: Use a dedicated API user with only the required permissions

## License

MIT License
