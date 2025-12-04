#!/usr/bin/env python3
"""
CPU Optimization Utility
=========================

Detects CPU configuration and provides optimal parallelization settings
for experiments and analysis scripts.

Optimized for Intel Core i9-12900HX (16 cores, 24 threads).

Author: Joerg Bollwahn
Date: 2025-12-04
"""

import os
import platform
import multiprocessing
import subprocess
from typing import Dict, Any, Optional


def detect_cpu_info() -> Dict[str, Any]:
    """
    Detect CPU information and configuration.

    Returns:
        Dictionary with CPU information
    """
    cpu_info = {
        "platform": platform.system(),
        "processor": platform.processor(),
        "cpu_count_physical": multiprocessing.cpu_count(),
        "cpu_count_logical": os.cpu_count() or multiprocessing.cpu_count(),
    }

    # Try to get more detailed CPU info
    if platform.system() == "Windows":
        try:
            # Windows: Use WMIC or CPU-Z info
            result = subprocess.run(
                ["wmic", "cpu", "get", "name,numberofcores,numberoflogicalprocessors"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    # Parse WMIC output
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.strip().split()
                            if "Intel" in line or "AMD" in line:
                                cpu_info["cpu_name"] = " ".join(
                                    parts[:-2] if len(parts) > 2 else parts
                                )
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

    # Detect specific CPU models
    processor_str = cpu_info.get("processor", "").upper()
    cpu_name = cpu_info.get("cpu_name", "").upper()

    if "I9-12900HX" in processor_str or "I9-12900HX" in cpu_name:
        cpu_info["detected_model"] = "Intel Core i9-12900HX"
        cpu_info["cores"] = 16  # 8P + 8E
        cpu_info["threads"] = 24
        cpu_info["performance_cores"] = 8
        cpu_info["efficiency_cores"] = 8
    elif "I9" in processor_str or "I9" in cpu_name:
        # Generic i9 detection
        cpu_info["detected_model"] = "Intel Core i9 (generic)"
        cpu_info["cores"] = cpu_info["cpu_count_physical"]
        cpu_info["threads"] = cpu_info["cpu_count_logical"]
    elif "AMD" in processor_str or "AMD" in cpu_name:
        cpu_info["detected_model"] = "AMD Processor"
        cpu_info["cores"] = cpu_info["cpu_count_physical"]
        cpu_info["threads"] = cpu_info["cpu_count_logical"]
    else:
        cpu_info["detected_model"] = "Unknown"
        cpu_info["cores"] = cpu_info["cpu_count_physical"]
        cpu_info["threads"] = cpu_info["cpu_count_logical"]

    return cpu_info


def get_optimal_worker_count(
    cpu_info: Optional[Dict[str, Any]] = None,
    task_type: str = "cpu_bound",
    reserve_cores: int = 2,
) -> int:
    """
    Calculate optimal worker count based on CPU configuration.

    Args:
        cpu_info: CPU information dictionary (auto-detected if None)
        task_type: Type of task ('cpu_bound', 'io_bound', 'mixed')
        reserve_cores: Number of cores to reserve for system (default: 2)

    Returns:
        Optimal number of workers
    """
    if cpu_info is None:
        cpu_info = detect_cpu_info()

    logical_cores = cpu_info.get("threads", cpu_info.get("cpu_count_logical", 4))
    physical_cores = cpu_info.get("cores", cpu_info.get("cpu_count_physical", 2))

    # For i9-12900HX specifically
    if cpu_info.get("detected_model") == "Intel Core i9-12900HX":
        if task_type == "cpu_bound":
            # CPU-bound: use physical cores, reserve 2
            optimal = max(1, physical_cores - reserve_cores)
        elif task_type == "io_bound":
            # I/O-bound: can use more threads, but not all
            optimal = max(1, min(20, logical_cores - reserve_cores))
        else:  # mixed
            # Mixed: balance between cores and threads
            optimal = max(
                1, min(18, (physical_cores + logical_cores) // 2 - reserve_cores)
            )
    else:
        # Generic calculation
        if task_type == "cpu_bound":
            optimal = max(1, physical_cores - reserve_cores)
        elif task_type == "io_bound":
            optimal = max(1, logical_cores - reserve_cores)
        else:  # mixed
            optimal = max(1, logical_cores - reserve_cores)

    return optimal


def get_optimal_settings_for_i9_12900hx() -> Dict[str, Any]:
    """
    Get optimal settings specifically for i9-12900HX.

    Returns:
        Dictionary with optimal settings
    """
    return {
        "experiment_workers": 18,  # For firewall experiments (mixed CPU/I/O)
        "analysis_workers": 20,  # For data analysis (more I/O bound)
        "threshold_sweep_workers": 16,  # For threshold calibration (CPU bound)
        "recommended_batch_size": 64,  # Items per batch
        "chunk_size_for_parallel": 8,  # Items per chunk for parallel processing
    }


def print_cpu_info_and_recommendations():
    """Print CPU information and optimization recommendations."""
    cpu_info = detect_cpu_info()

    print("=" * 70)
    print("CPU OPTIMIZATION ANALYSIS")
    print("=" * 70)
    print(f"Platform: {cpu_info['platform']}")
    print(f"Processor: {cpu_info.get('processor', 'Unknown')}")
    if "cpu_name" in cpu_info:
        print(f"CPU Name: {cpu_info['cpu_name']}")
    print(f"Detected Model: {cpu_info.get('detected_model', 'Unknown')}")
    print(f"Physical Cores: {cpu_info.get('cores', cpu_info['cpu_count_physical'])}")
    print(
        f"Logical Cores (Threads): {cpu_info.get('threads', cpu_info['cpu_count_logical'])}"
    )

    if cpu_info.get("detected_model") == "Intel Core i9-12900HX":
        print(f"Performance Cores: {cpu_info.get('performance_cores', 8)}")
        print(f"Efficiency Cores: {cpu_info.get('efficiency_cores', 8)}")

    print("\n" + "-" * 70)
    print("OPTIMAL WORKER COUNTS")
    print("-" * 70)

    cpu_bound = get_optimal_worker_count(cpu_info, task_type="cpu_bound")
    io_bound = get_optimal_worker_count(cpu_info, task_type="io_bound")
    mixed = get_optimal_worker_count(cpu_info, task_type="mixed")

    print(f"CPU-bound tasks:     {cpu_bound} workers")
    print(f"I/O-bound tasks:     {io_bound} workers")
    print(f"Mixed tasks:         {mixed} workers")

    if cpu_info.get("detected_model") == "Intel Core i9-12900HX":
        optimal = get_optimal_settings_for_i9_12900hx()
        print("\n" + "-" * 70)
        print("RECOMMENDED SETTINGS FOR i9-12900HX")
        print("-" * 70)
        print(f"Experiment workers:        {optimal['experiment_workers']}")
        print(f"Analysis workers:         {optimal['analysis_workers']}")
        print(f"Threshold sweep workers:  {optimal['threshold_sweep_workers']}")
        print(f"Recommended batch size:   {optimal['recommended_batch_size']}")
        print(f"Chunk size (parallel):    {optimal['chunk_size_for_parallel']}")

        print("\n" + "-" * 70)
        print("USAGE EXAMPLES")
        print("-" * 70)
        print("# Run experiment with optimal workers:")
        print("python scripts/run_answerpolicy_experiment.py \\")
        print("    --policy kids \\")
        print("    --input datasets/core_suite.jsonl \\")
        print("    --output logs/kids_core_suite.jsonl \\")
        print(f"    --num-workers {optimal['experiment_workers']}")
        print()
        print("# Run threshold calibration:")
        print("python scripts/threshold_sweep.py \\")
        print("    --dataset datasets/core_suite.jsonl \\")
        print(f"    --num-workers {optimal['threshold_sweep_workers']}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    print_cpu_info_and_recommendations()
