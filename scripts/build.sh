#!/bin/bash
# Build all packages for FireLens Monitor
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Extract version from __init__.py
VERSION=$(grep -oP '__version__\s*=\s*"\K[^"]+' "$PROJECT_ROOT/src/firelens/__init__.py")

echo "========================================"
echo "Building FireLens Monitor v${VERSION}"
echo "========================================"

cd "$PROJECT_ROOT"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info src/*.egg-info

# Install build tools if needed
pip install --quiet build

# Build Python package
echo ""
echo "Building Python wheel..."
python -m build

echo ""
echo "Build complete!"
echo ""
echo "Artifacts:"
ls -la dist/

# Build Docker image if docker is available
if command -v docker &> /dev/null; then
    echo ""
    echo "Building Docker image..."
    docker build -t firelens-monitor:${VERSION} -f docker/Dockerfile .
    docker tag firelens-monitor:${VERSION} firelens-monitor:latest
    echo ""
    echo "Docker images:"
    docker images | grep firelens-monitor
else
    echo ""
    echo "Docker not available - skipping Docker build"
fi

echo ""
echo "========================================"
echo "Build Summary:"
echo "  - Wheel: dist/firelens_monitor-${VERSION}-py3-none-any.whl"
echo "  - Source: dist/firelens_monitor-${VERSION}.tar.gz"
if command -v docker &> /dev/null; then
    echo "  - Docker: firelens-monitor:${VERSION}"
fi
echo "========================================"
