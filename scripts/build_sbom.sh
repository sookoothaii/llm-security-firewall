#!/usr/bin/env bash
# SBOM generation for LLM Security Firewall
# Requires: pip-audit, syft (optional)

set -euo pipefail

VERSION="${1:-v5.0.0-rc1}"
OUT_DIR="${2:-out}"

mkdir -p "$OUT_DIR"

echo "==> Generating SBOM for $VERSION"

# Python dependencies (pip-audit)
if command -v pip-audit &>/dev/null; then
  echo "[1/3] pip-audit SBOM (CycloneDX JSON)"
  pip-audit --format cyclonedx-json --output "$OUT_DIR/sbom-python.cdx.json" || true
else
  echo "WARN: pip-audit not found, skipping Python SBOM"
fi

# Alternative: syft (if available)
if command -v syft &>/dev/null; then
  echo "[2/3] syft SBOM (SPDX JSON)"
  syft . -o spdx-json="$OUT_DIR/sbom.spdx.json"
else
  echo "WARN: syft not found, skipping container SBOM"
fi

# Checksums
echo "[3/3] SHA256 checksums"
(cd "$OUT_DIR" && sha256sum sbom*.* > checksums.sha256) || true

echo "==> SBOM artifacts written to $OUT_DIR/"
ls -lh "$OUT_DIR/"

