#!/bin/bash
# Monitoring Test Suite - Orchestrator Service
# =============================================
#
# Testet Monitoring-Endpoints und Metriken-Erfassung.
#
# Usage:
#     bash tests/monitoring_test.sh
#     bash tests/monitoring_test.sh --url http://localhost:8001

set -e

# Default values
BASE_URL="${1:-http://localhost:8001}"
OUTPUT_DIR="${2:-test_results}"

echo "=========================================="
echo "📊 MONITORING TEST SUITE"
echo "=========================================="
echo "Base URL: $BASE_URL"
echo "Output Dir: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Test 1: Metrics collection
echo "Test 1: Metrics Collection"
echo "---------------------------"
echo "Sending 100 requests..."

SUCCESS_COUNT=0
for i in {1..100}; do
    HTTP_CODE=$(curl -X POST "$BASE_URL/api/v1/route-and-detect" \
        -H "Content-Type: application/json" \
        -d '{"text": "test request", "context": {"source_tool": "general", "user_risk_tier": 1}}' \
        -s -o /dev/null -w "%{http_code}")
    
    if [ "$HTTP_CODE" = "200" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
    
    # Small delay to avoid overwhelming the service
    sleep 0.1
done

echo "Successful requests: $SUCCESS_COUNT/100"
echo ""

# Check metrics
echo "Checking metrics endpoint..."
METRICS_RESPONSE=$(curl -s "$BASE_URL/api/v1/metrics")
echo "$METRICS_RESPONSE" > "$OUTPUT_DIR/metrics_output.txt"

if echo "$METRICS_RESPONSE" | grep -q "router_requests_total"; then
    echo "✅ Metrics endpoint working - router_requests_total found"
else
    echo "❌ Metrics endpoint issue - router_requests_total not found"
fi

if echo "$METRICS_RESPONSE" | grep -q "detector_calls_total"; then
    echo "✅ Metrics endpoint working - detector_calls_total found"
else
    echo "❌ Metrics endpoint issue - detector_calls_total not found"
fi

echo ""

# Test 2: Alert triggering
echo "Test 2: Alert Triggering"
echo "-------------------------"
echo "Simulating high error rate..."

ERROR_COUNT=0
for i in {1..50}; do
    HTTP_CODE=$(curl -X POST "$BASE_URL/api/v1/route-and-detect" \
        -H "Content-Type: application/json" \
        -d '{"text": "", "context": {}}' \
        -s -o /dev/null -w "%{http_code}")
    
    if [ "$HTTP_CODE" != "200" ]; then
        ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
    
    sleep 0.1
done

echo "Errors generated: $ERROR_COUNT/50"
echo ""

# Check alerts
echo "Checking alerts endpoint..."
ALERTS_RESPONSE=$(curl -s "$BASE_URL/api/v1/alerts")
echo "$ALERTS_RESPONSE" > "$OUTPUT_DIR/alerts_output.txt"

if echo "$ALERTS_RESPONSE" | grep -q '"alerts"'; then
    echo "✅ Alerts endpoint working"
    ALERT_COUNT=$(echo "$ALERTS_RESPONSE" | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo "0")
    echo "   Active alerts: $ALERT_COUNT"
else
    echo "❌ Alerts endpoint issue"
fi

echo ""

# Test 3: Health Check
echo "Test 3: Health Check"
echo "---------------------"
HEALTH_RESPONSE=$(curl -s "$BASE_URL/api/v1/health")
echo "$HEALTH_RESPONSE" > "$OUTPUT_DIR/health_output.txt"

if echo "$HEALTH_RESPONSE" | grep -q '"status"'; then
    echo "✅ Health endpoint working"
    STATUS=$(echo "$HEALTH_RESPONSE" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    echo "   Status: $STATUS"
else
    echo "❌ Health endpoint issue"
fi

echo ""

# Test 4: Metrics Summary
echo "Test 4: Metrics Summary"
echo "-----------------------"
SUMMARY_RESPONSE=$(curl -s "$BASE_URL/api/v1/metrics/summary")
echo "$SUMMARY_RESPONSE" > "$OUTPUT_DIR/metrics_summary_output.txt"

if echo "$SUMMARY_RESPONSE" | grep -q '"summary"'; then
    echo "✅ Metrics summary endpoint working"
else
    echo "❌ Metrics summary endpoint issue"
fi

echo ""

# Test 5: Dashboard
echo "Test 5: Dashboard"
echo "-----------------"
DASHBOARD_RESPONSE=$(curl -s "$BASE_URL/api/v1/dashboard")
echo "$DASHBOARD_RESPONSE" > "$OUTPUT_DIR/dashboard_output.txt"

if echo "$DASHBOARD_RESPONSE" | grep -q '"overview"'; then
    echo "✅ Dashboard endpoint working"
else
    echo "❌ Dashboard endpoint issue"
fi

echo ""

# Summary
echo "=========================================="
echo "📊 TEST SUMMARY"
echo "=========================================="
echo "All test outputs saved to: $OUTPUT_DIR"
echo "  - metrics_output.txt"
echo "  - alerts_output.txt"
echo "  - health_output.txt"
echo "  - metrics_summary_output.txt"
echo "  - dashboard_output.txt"
echo "=========================================="

