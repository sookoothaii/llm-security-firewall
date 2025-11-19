"""
CLI Smoke Test for RC10b Extended Ablation Studies
===================================================

End-to-end test that the CLI entry point works correctly.

Creator: Joerg Bollwahn
Date: 2025-11-18
License: MIT
"""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.slow
def test_rc10b_cli_smoke(tmp_path):
    """Test that the CLI script runs without errors."""
    script_path = Path(__file__).parent.parent / "scripts" / "rc10b_ablation_studies_extended.py"
    
    if not script_path.exists():
        pytest.skip(f"Script not found: {script_path}")
    
    out_dir = tmp_path / "results"
    out_dir.mkdir(parents=True)
    
    # Use synthetic dataset generation (no external file needed)
    cmd = [
        sys.executable,
        str(script_path),
        "--output-dir",
        str(out_dir),
        "--seed",
        "1",
        "--t-soft",
        "0.35",
        "--t-hard",
        "0.55",
    ]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(script_path.parent.parent),
    )
    
    # Should complete successfully
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    
    # At least one output file should exist
    json_files = list(out_dir.glob("*.json"))
    assert len(json_files) > 0, f"No JSON files found in {out_dir}"
    
    # Check that expected files exist
    expected_files = [
        "run1_full_rc10b.json",
        "run2_no_phase_floor.json",
        "run3_no_scope_mismatch.json",
        "run4_no_policy_layer.json",
    ]
    
    for filename in expected_files:
        filepath = out_dir / filename
        assert filepath.exists(), f"Expected file not found: {filename}"

