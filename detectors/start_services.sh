#!/bin/bash
# Start Detector Microservices
# =============================
#
# Starts both detector services for development/testing.
#
# Usage:
#   ./start_services.sh
#
# Creator: HAK_GAL (Joerg Bollwahn)
# Date: 2025-12-07
# License: MIT

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Starting Detector Microservices ==="
echo ""

# Check if services are already running
if curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "⚠️  Code Intent service already running on port 8001"
else
    echo "Starting Code Intent Detector (port 8001)..."
    cd code_intent_service
    uvicorn main:app --host 0.0.0.0 --port 8001 > ../logs/code_intent.log 2>&1 &
    CODE_INTENT_PID=$!
    echo "  PID: $CODE_INTENT_PID"
    cd ..
fi

if curl -s http://localhost:8002/health > /dev/null 2>&1; then
    echo "⚠️  Persuasion service already running on port 8002"
else
    echo "Starting Persuasion Detector (port 8002)..."
    cd persuasion_service
    uvicorn main:app --host 0.0.0.0 --port 8002 > ../logs/persuasion.log 2>&1 &
    PERSUASION_PID=$!
    echo "  PID: $PERSUASION_PID"
    cd ..
fi

# Wait for services to be ready
echo ""
echo "Waiting for services to be ready..."
sleep 3

# Health checks
echo ""
echo "=== Health Checks ==="
if curl -s http://localhost:8001/health > /dev/null; then
    echo "✅ Code Intent: HEALTHY"
else
    echo "❌ Code Intent: UNHEALTHY"
    exit 1
fi

if curl -s http://localhost:8002/health > /dev/null; then
    echo "✅ Persuasion: HEALTHY"
else
    echo "❌ Persuasion: UNHEALTHY"
    exit 1
fi

echo ""
echo "=== Services Started ==="
echo "Code Intent: http://localhost:8001"
echo "Persuasion:   http://localhost:8002"
echo ""
echo "Logs:"
echo "  Code Intent: logs/code_intent.log"
echo "  Persuasion:  logs/persuasion.log"
echo ""
echo "To stop services, use: pkill -f 'uvicorn main:app'"
