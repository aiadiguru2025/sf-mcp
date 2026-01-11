FROM python:3.10-slim

WORKDIR /app

# Install uv package manager
RUN pip install uv

# Copy project files
COPY pyproject.toml uv.lock ./
COPY main.py ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Cloud Run uses PORT environment variable (default 8080)
ENV PORT=8080
EXPOSE 8080

# Run the MCP server
CMD ["uv", "run", "main.py"]
