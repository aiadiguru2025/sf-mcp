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

## Cloud Deployment (Google Cloud Run)

Deploy this MCP server to Google Cloud Run for remote access.

### Prerequisites

- Google Cloud account with billing enabled
- [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) installed
- Docker installed (for local testing)

### Local Testing with Docker

```bash
# Build the image
docker build -t sf-mcp .

# Run locally (uses .env file)
docker run -p 8080:8080 --env-file .env sf-mcp

# Test the endpoint
curl http://localhost:8080/mcp
```

### Deploy to Cloud Run

```bash
# Set your project ID
export PROJECT_ID=your-gcp-project-id

# Build and push to Google Container Registry
gcloud builds submit --tag gcr.io/$PROJECT_ID/sf-mcp

# Deploy to Cloud Run
gcloud run deploy sf-mcp \
  --image gcr.io/$PROJECT_ID/sf-mcp \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "SF_USER_ID=your_user_id,SF_PASSWORD=your_password,SF_API_HOST=api55preview.sapsf.eu"
```

### Claude Desktop Config (Remote Server)

After deployment, update your Claude Desktop config to use the Cloud Run URL:

```json
{
  "mcpServers": {
    "sf-mcp": {
      "url": "https://sf-mcp-xxxxx-uc.a.run.app/mcp"
    }
  }
}
```

Replace `sf-mcp-xxxxx-uc.a.run.app` with your actual Cloud Run URL (shown after deployment).

### Security for Production

For production deployments, use Cloud Run secrets instead of plain environment variables:

```bash
# Create secrets
echo -n "your_user_id" | gcloud secrets create sf-user-id --data-file=-
echo -n "your_password" | gcloud secrets create sf-password --data-file=-

# Deploy with secrets
gcloud run deploy sf-mcp \
  --image gcr.io/$PROJECT_ID/sf-mcp \
  --platform managed \
  --region us-central1 \
  --set-secrets "SF_USER_ID=sf-user-id:latest,SF_PASSWORD=sf-password:latest" \
  --set-env-vars "SF_API_HOST=api55preview.sapsf.eu"
```

## Project Structure

```
sf-mcp/
├── main.py              # MCP server implementation
├── pyproject.toml       # Project dependencies
├── uv.lock              # Dependency lock file
├── .python-version      # Python version specification
├── .env.example         # Example environment variables
├── .env                 # Local environment variables (gitignored)
├── .gitignore           # Git ignore rules
├── Dockerfile           # Container image for Cloud Run
├── .dockerignore        # Files excluded from Docker build
└── README.md            # This documentation
```

## Dependencies

- `mcp[cli]>=1.25.0` - Model Context Protocol SDK
- `requests>=2.31.0` - HTTP client library
- `xmltodict>=0.13.0` - XML to dictionary parser
- `python-dotenv>=1.0.0` - Environment variable loader
- `uvicorn>=0.30.0` - ASGI server for HTTP transport

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
