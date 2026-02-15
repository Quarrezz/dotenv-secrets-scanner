# Use official Python runtime as a parent image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install git for git-based dependencies and operations
# Clean up apt cache to keep image size small
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install the package
RUN pip install --no-cache-dir .

# Create a non-root user
RUN useradd -m appuser
USER appuser

# Set the entrypoint to the scanner CLI
ENTRYPOINT ["secrets-scan"]

# Default command shows help
CMD ["--help"]
