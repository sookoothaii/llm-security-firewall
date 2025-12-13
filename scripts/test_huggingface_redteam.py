#!/usr/bin/env python3
"""
Red Team Dataset Test - Hugging Face Dataset
============================================
Loads the RED_team_tactics_dataset and tests all samples against the services.

Usage:
    python scripts/test_huggingface_redteam.py

Requirements:
    - Services must be running (Port 8000 and 8001)
    - pip install datasets
"""

import requests
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from datasets import load_dataset
except ImportError:
    print("ERROR: datasets library nicht installiert!")
    print("Installiere mit: pip install datasets")
    sys.exit(1)

# Service-Konfiguration
SERVICES = {
    8000: {
        "name": "Code Intent Service",
        "detect": "/api/v1/detect",
        "health": "/api/v1/health"
    },
    8001: {
        "name": "Orchestrator Service",
        "detect": "/api/v1/route-and-detect",
        "health": "/api/v1/health"
    }
}

def test_detection(port: int, endpoint: str, text: str) -> Tuple[bool, Dict[str, Any]]:
    """Tests a text against a service."""
    try:
        url = f"http://localhost:{port}{endpoint}"
        
        payload = {
            "text": text,
            "context": {},
            "source_tool": "test",
            "user_risk_tier": 1,
            "session_risk_score": 0.0
        }
        
        start_time = time.time()
        response = requests.post(url, json=payload, timeout=30)  # Increased to 30 seconds
        elapsed_time = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            
            # Support different response structures
            blocked = False
            risk_score = 0.0
            
            # Structure 1: Direct blocked/risk_score
            if "blocked" in data:
                blocked = data.get("blocked", False)
                risk_score = data.get("risk_score", 0.0)
            # Structure 2: data.blocked / data.risk_score
            elif "data" in data:
                data_obj = data["data"]
                # Code Intent Service: should_block
                if "should_block" in data_obj:
                    blocked = data_obj.get("should_block", False)
                    risk_score = data_obj.get("risk_score", 0.0)
                # Orchestrator: blocked
                elif "blocked" in data_obj:
                    blocked = data_obj.get("blocked", False)
                    risk_score = data_obj.get("risk_score", 0.0)
                # Code Intent alternative: is_malicious
                elif "is_malicious" in data_obj:
                    blocked = data_obj.get("is_malicious", False)
                    risk_score = data_obj.get("risk_score", 0.0)
            
            return True, {
                "blocked": blocked,
                "risk_score": risk_score,
                "response_time": elapsed_time,
                "full_response": data
            }
        else:
            return False, {
                "error": f"HTTP {response.status_code}",
                "response_time": elapsed_time
            }
    except requests.exceptions.ConnectionError:
        return False, {"error": "Connection refused"}
    except requests.exceptions.Timeout:
        return False, {"error": "Timeout"}
    except Exception as e:
        return False, {"error": str(e)}

def get_sample_count():
    """Asks the user for the number of samples to test."""
    print("=" * 70)
    print("RED TEAM DATASET TEST - Hugging Face")
    print("=" * 70)
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("How many samples should be tested?")
    print("  (1-1000, Default: 50)")
    
    while True:
        try:
            user_input = input("Number of samples [50]: ").strip()
            if not user_input:
                return 50
            
            count = int(user_input)
            if 1 <= count <= 1000:
                return count
            else:
                print(f"  ⚠ Please enter a number between 1 and 1000 (entered: {count})")
        except ValueError:
            print("  ⚠ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n  Cancelled")
            sys.exit(0)

def load_and_test_dataset():
    """Loads the dataset and tests all samples."""
    max_samples = get_sample_count()
    print()
    
    # Check services
    print("Checking services...")
    for port, config in SERVICES.items():
        try:
            health_url = f"http://localhost:{port}{config['health']}"
            response = requests.get(health_url, timeout=2)
            if response.status_code == 200:
                print(f"  ✓ {config['name']} (Port {port}) - OK")
            else:
                print(f"  ✗ {config['name']} (Port {port}) - Health check failed")
                return 1
        except Exception as e:
            print(f"  ✗ {config['name']} (Port {port}) - Not reachable: {e}")
            return 1
    print()
    
    # Load dataset
    print("Loading dataset: darkknight25/RED_team_tactics_dataset")
    print("-" * 70)
    try:
        ds = load_dataset("darkknight25/RED_team_tactics_dataset")
        print(f"✓ Dataset loaded")
        
        # Find the correct split (usually 'train' or first available)
        split_name = None
        if 'train' in ds:
            split_name = 'train'
        elif len(ds) > 0:
            split_name = list(ds.keys())[0]
        else:
            print("✗ No split found in dataset")
            return 1
        
        dataset_full = ds[split_name]
        print(f"✓ Split '{split_name}' found")
        print(f"✓ Total samples in dataset: {len(dataset_full)}")
        
        # Limit to requested number of samples
        if len(dataset_full) > max_samples:
            dataset = dataset_full.select(range(max_samples))
            print(f"✓ Limited to {max_samples} samples for testing")
        else:
            dataset = dataset_full
            print(f"✓ Using all {len(dataset)} available samples")
        print()
        
    except Exception as e:
        print(f"✗ Error loading dataset: {e}")
        print()
        print("Note: You may need to log in to Hugging Face:")
        print("  huggingface-cli login")
        return 1
    
    # Test all samples with parallelization
    print("=" * 70)
    print(f"Testing {len(dataset)} samples (24 workers, parallel)...")
    print("=" * 70)
    print()
    
    # Extract all texts first
    print("Extracting texts from samples...")
    texts = []
    
    for i, sample in enumerate(dataset, 1):
        text = None
        
        # For MITRE ATT&CK Dataset: Combine description + execution_steps
        if "description" in sample and "execution_steps" in sample:
            description = sample.get("description", "")
            execution_steps = sample.get("execution_steps", [])
            
            # Combine description and execution steps into a prompt
            text_parts = [description]
            if execution_steps:
                text_parts.append("\n\nExecution steps:")
                for step in execution_steps[:3]:  # Only first 3 steps
                    if isinstance(step, str):
                        text_parts.append(f"- {step}")
            
            text = "\n".join(text_parts)
        
        # Fallback: Search for other text fields
        if not text or len(text) < 20:
            possible_fields = ["text", "input", "prompt", "message", "content", "attack", "payload", "query", "description"]
            for field in possible_fields:
                if field in sample and isinstance(sample[field], str) and len(sample[field]) > 20:
                    text = sample[field]
                    break
        
        if text and len(text) > 20:  # At least 20 characters
            texts.append((i, text))
        else:
            print(f"  ⚠ Sample {i}: Insufficient text found")
    
    print(f"✓ {len(texts)} samples with text found")
    print()
    
    all_results = {}
    NUM_WORKERS = 24
    
    for port, service_config in SERVICES.items():
        service_name = service_config["name"]
        print(f"\n{'=' * 70}")
        print(f"Testing {service_name} (Port {port}) - {NUM_WORKERS} Workers")
        print(f"{'=' * 70}")
        
        results = {
            "service": service_name,
            "port": port,
            "total": len(texts),
            "blocked": 0,
            "allowed": 0,
            "errors": 0,
            "details": [],
            "risk_scores": []
        }
        
        # Parallelisierung mit ThreadPoolExecutor
        def test_sample(args):
            idx, text = args
            return idx, test_detection(port, service_config["detect"], text)
        
        completed = 0
        with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
            # Starte alle Tasks
            future_to_sample = {executor.submit(test_sample, (idx, text)): (idx, text) 
                               for idx, text in texts}
            
            # Sammle Ergebnisse
            for future in as_completed(future_to_sample):
                completed += 1
                idx, text = future_to_sample[future]
                
                try:
                    sample_idx, (success, data) = future.result()
                    
                    if completed % 10 == 0 or completed == 1:
                        print(f"[{completed}/{len(texts)}] Processed...")
                    
                    if not success:
                        results["errors"] += 1
                        results["details"].append({
                            "sample_index": sample_idx,
                            "text": text[:100],
                            "error": data.get("error", "Unknown")
                        })
                        continue
                    
                    blocked = data.get("blocked", False)
                    risk_score = data.get("risk_score", 0.0)
                    
                    if blocked:
                        results["blocked"] += 1
                    else:
                        results["allowed"] += 1
                    
                    results["risk_scores"].append(risk_score)
                    results["details"].append({
                        "sample_index": sample_idx,
                        "text": text[:100],
                        "blocked": blocked,
                        "risk_score": risk_score,
                        "response_time": data.get("response_time", 0)
                    })
                except Exception as e:
                    results["errors"] += 1
                    results["details"].append({
                        "sample_index": idx,
                        "text": text[:100] if text else "",
                        "error": str(e)
                    })
        
        print(f"✓ {completed}/{len(texts)} samples processed")
        
        # Statistics
        if results["risk_scores"]:
            results["avg_risk_score"] = sum(results["risk_scores"]) / len(results["risk_scores"])
            results["max_risk_score"] = max(results["risk_scores"])
            results["min_risk_score"] = min(results["risk_scores"])
        else:
            results["avg_risk_score"] = 0.0
            results["max_risk_score"] = 0.0
            results["min_risk_score"] = 0.0
        
        all_results[port] = results
        
        # Show summary for this service
        print(f"\n{service_name} Summary:")
        print(f"  Total: {results['total']} samples")
        print(f"  Blocked: {results['blocked']} ({results['blocked']/results['total']*100:.1f}%)")
        print(f"  Allowed: {results['allowed']} ({results['allowed']/results['total']*100:.1f}%)")
        print(f"  Errors: {results['errors']}")
        if results["risk_scores"]:
            print(f"  Avg Risk Score: {results['avg_risk_score']:.3f}")
            print(f"  Min Risk Score: {results['min_risk_score']:.3f}")
            print(f"  Max Risk Score: {results['max_risk_score']:.3f}")
    
    # Overall summary
    print("\n" + "=" * 70)
    print("OVERALL SUMMARY")
    print("=" * 70)
    print()
    
    for port, results in all_results.items():
        service_name = results["service"]
        print(f"{service_name} (Port {port}):")
        print(f"  Block Rate: {results['blocked']}/{results['total']} ({results['blocked']/results['total']*100:.1f}%)")
        print(f"  Average Risk Score: {results['avg_risk_score']:.3f}")
        print()
    
    # Save results
    output_file = Path("huggingface_redteam_test_results.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "dataset": "darkknight25/RED_team_tactics_dataset",
            "total_samples": len(dataset),
            "results": all_results
        }, f, indent=2, ensure_ascii=False)
    
    print(f"Results saved to: {output_file}")
    print()
    
    return 0

if __name__ == "__main__":
    sys.exit(load_and_test_dataset())

