#!/usr/bin/env python3
"""
Production Log Collector
========================

Collects production traffic data for A/B testing from various sources:
- Database logs
- Application logs
- Shadow mode outputs
- User feedback

Usage:
    python test_suites/production_ab/collectors/production_log_collector.py \
        --start-date 2025-12-01 \
        --end-date 2025-12-12 \
        --output data/production_ab_set.jsonl
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import re

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))


class ProductionLogCollector:
    """Collects production logs for A/B testing."""
    
    def __init__(self, output_file: Path):
        self.output_file = output_file
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.collected_samples: List[Dict] = []
    
    def collect_from_logs(
        self,
        log_file: Path,
        start_date: datetime,
        end_date: datetime,
        model_version: str = None
    ) -> List[Dict]:
        """Collect samples from log file."""
        samples = []
        
        if not log_file.exists():
            print(f"WARNING: Log file not found: {log_file}")
            return samples
        
        print(f"Reading logs from {log_file}...")
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    # Try JSONL format first
                    if line.strip().startswith('{'):
                        log_entry = json.loads(line)
                        
                        # Filter by date
                        timestamp_str = log_entry.get('timestamp') or log_entry.get('time')
                        if timestamp_str:
                            try:
                                log_timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                if not (start_date <= log_timestamp <= end_date):
                                    continue
                            except:
                                # Skip if timestamp parsing fails
                                continue
                        
                        # Filter by model version if specified
                        if model_version:
                            entry_version = log_entry.get('model_version') or log_entry.get('version')
                            if entry_version != model_version:
                                continue
                        
                        # Extract relevant fields
                        sample = {
                            "text": log_entry.get('text') or log_entry.get('input') or log_entry.get('prompt'),
                            "expected_blocked": log_entry.get('blocked') or log_entry.get('decision') == 'block',
                            "category": "production",
                            "metadata": {
                                "timestamp": timestamp_str,
                                "model_version": entry_version or "unknown",
                                "source": str(log_file.name),
                                "original_log": log_entry
                            }
                        }
                        
                        if sample['text']:
                            samples.append(sample)
                    
                except json.JSONDecodeError:
                    # Try parsing as structured log format
                    continue
                except Exception as e:
                    print(f"WARNING: Error processing line {line_num}: {e}")
                    continue
        
        print(f"Collected {len(samples)} samples from {log_file.name}")
        return samples
    
    def collect_from_directory(
        self,
        log_dir: Path,
        start_date: datetime,
        end_date: datetime,
        model_version: str = None
    ) -> List[Dict]:
        """Collect samples from all log files in directory."""
        all_samples = []
        
        # Look for common log file patterns
        log_patterns = ['*.jsonl', '*.log', '*.json']
        
        for pattern in log_patterns:
            for log_file in log_dir.glob(pattern):
                if log_file.is_file():
                    samples = self.collect_from_logs(log_file, start_date, end_date, model_version)
                    all_samples.extend(samples)
        
        return all_samples
    
    def anonymize_sample(self, sample: Dict) -> Dict:
        """Anonymize sensitive data in sample."""
        # Remove PII patterns (email, phone, etc.)
        text = sample['text']
        
        # Replace email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', text)
        
        # Replace phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', text)
        
        # Replace credit card numbers
        text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CARD]', text)
        
        # Replace SSN
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', text)
        
        sample['text'] = text
        
        # Remove sensitive metadata
        if 'metadata' in sample and 'original_log' in sample['metadata']:
            original = sample['metadata']['original_log']
            # Remove potentially sensitive fields
            for key in ['user_id', 'session_id', 'ip_address', 'user_agent']:
                original.pop(key, None)
        
        return sample
    
    def save_samples(self, samples: List[Dict], anonymize: bool = True):
        """Save collected samples to output file."""
        if anonymize:
            samples = [self.anonymize_sample(s.copy()) for s in samples]
        
        print(f"Saving {len(samples)} samples to {self.output_file}...")
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for sample in samples:
                f.write(json.dumps(sample, ensure_ascii=False) + '\n')
        
        # Also save metadata
        metadata_file = self.output_file.parent / "metadata.json"
        metadata = {
            "collection_date": datetime.now().isoformat(),
            "total_samples": len(samples),
            "output_file": str(self.output_file.name),
            "anonymized": anonymize
        }
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"✓ Saved {len(samples)} samples")
        print(f"✓ Metadata saved to {metadata_file}")


def main():
    parser = argparse.ArgumentParser(description="Collect production logs for A/B testing")
    parser.add_argument(
        "--start-date",
        type=str,
        required=True,
        help="Start date (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--end-date",
        type=str,
        required=True,
        help="End date (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default=None,
        help="Directory containing log files (default: project_root/logs)"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Single log file to process"
    )
    parser.add_argument(
        "--model-version",
        type=str,
        default=None,
        help="Filter by model version (e.g., v2.1_hotfix)"
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output JSONL file path"
    )
    parser.add_argument(
        "--no-anonymize",
        action="store_true",
        help="Skip anonymization (use with caution!)"
    )
    
    args = parser.parse_args()
    
    # Parse dates
    start_date = datetime.strptime(args.start_date, "%Y-%m-%d")
    end_date = datetime.strptime(args.end_date, "%Y-%m-%d") + timedelta(days=1)  # Include full end date
    
    # Setup paths
    output_file = Path(args.output)
    
    if args.log_file:
        log_file = Path(args.log_file)
        log_dir = None
    else:
        log_file = None
        log_dir = Path(args.log_dir) if args.log_dir else project_root / "logs"
    
    # Create collector
    collector = ProductionLogCollector(output_file)
    
    # Collect samples
    if log_file:
        samples = collector.collect_from_logs(
            log_file, start_date, end_date, args.model_version
        )
    else:
        samples = collector.collect_from_directory(
            log_dir, start_date, end_date, args.model_version
        )
    
    if not samples:
        print("WARNING: No samples collected!")
        return 1
    
    # Save samples
    collector.save_samples(samples, anonymize=not args.no_anonymize)
    
    print(f"\n✓ Collection complete: {len(samples)} samples")
    return 0


if __name__ == "__main__":
    sys.exit(main())

