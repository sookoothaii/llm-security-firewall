FROM python:3.12-slim

LABEL maintainer="Joerg Bollwahn"
LABEL description="LLM Security Firewall - Bidirectional Protection Framework"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install package
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd -m -u 1000 firewall && \
    chown -R firewall:firewall /app
USER firewall

# Expose health check port (optional)
EXPOSE 8080

# Default command: health check
CMD ["llm-firewall", "health-check"]



