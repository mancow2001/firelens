# FireLens Monitor - Multi-stage Docker Build
# Produces a minimal production image

# Stage 1: Build stage
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies for python3-saml (xmlsec1)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    pkg-config \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Install hatch for dynamic versioning
RUN pip install --no-cache-dir hatch hatchling

# Copy only requirements first for better caching
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Copy source and build wheel
COPY pyproject.toml MANIFEST.in LICENSE README.md ./
COPY src/ ./src/
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# Stage 2: Production image
FROM python:3.11-slim AS production

# Labels
LABEL org.opencontainers.image.title="FireLens Monitor"
LABEL org.opencontainers.image.description="Multi-vendor firewall monitoring solution"
LABEL org.opencontainers.image.version="1.0.30"
LABEL org.opencontainers.image.source="https://github.com/mancow2001/FireLens"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /bin/false firelens

# Copy wheels from builder and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

# Create directories
RUN mkdir -p /etc/firelens /var/lib/firelens/data /var/log/firelens /opt/firelens/certs \
    && chown -R firelens:firelens /etc/firelens /var/lib/firelens /var/log/firelens /opt/firelens

# Copy default config template
COPY docker/config.yaml.template /etc/firelens/config.yaml.template

# Switch to non-root user
USER firelens

# Set environment variables
ENV FIRELENS_CONFIG=/etc/firelens/config.yaml
ENV FIRELENS_DATA_DIR=/var/lib/firelens
ENV FIRELENS_LOG_DIR=/var/log/firelens

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/api/health', timeout=5)" || exit 1

# Volumes for persistence
VOLUME ["/etc/firelens", "/var/lib/firelens", "/var/log/firelens"]

# Entry point
ENTRYPOINT ["firelens"]
CMD ["--config", "/etc/firelens/config.yaml"]
