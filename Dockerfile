FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
COPY uv.lock .
RUN pip install uv && uv sync

# Copy source
COPY . .

# Install Playwright (optional)
RUN uv run playwright install chromium || true

# Expose port
EXPOSE 8500

# Run
CMD ["uv", "run", "python", "-m", "core.main", "--config", "config.yaml"]
