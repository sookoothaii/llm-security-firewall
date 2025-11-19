"""Convert eRisk collection (XML or JSON) to training JSONL format.

Supports:
- eRisk 2016-2024: XML format
- eRisk 2025: JSON format (Task 2 - submissions + comments)

Output: JSONL with fields:
  {"text": str, "lang": str, "labels": {...}, "source": str, "date": str, "split": str}

Usage:
  python convert_erisk_to_jsonl.py --erisk_dir /path/to/erisk --output train.jsonl --label self_harm
"""

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any
import random


def convert_xml_user(xml_path: Path, label: int) -> List[Dict[str, Any]]:
    """Convert eRisk XML user file to list of entries.
    
    Args:
        xml_path: Path to XML file
        label: 1 for positive, 0 for negative
    
    Returns:
        List of entry dicts
    """
    entries = []
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        for writing in root.findall('.//WRITING'):
            text_elem = writing.find('TEXT')
            date_elem = writing.find('DATE')
            
            if text_elem is None or text_elem.text is None:
                continue
            
            text = text_elem.text.strip()
            if not text:
                continue
            
            date = date_elem.text if date_elem is not None and date_elem.text else ""
            
            entry = {
                "text": text,
                "lang": "en",  # eRisk is English
                "labels": {
                    "self_harm": label,
                    "abuse": 0,
                    "unsafe_env": 0
                },
                "source": "erisk_xml",
                "date": date,
                "split": "train"  # Will be assigned later
            }
            entries.append(entry)
    
    except Exception as e:
        print(f"[ERROR] Failed to parse {xml_path}: {e}")
    
    return entries


def convert_json_user(json_data: Dict[str, Any], label: int, target_subject: str = None) -> List[Dict[str, Any]]:
    """Convert eRisk 2025 JSON submission to list of entries.
    
    Args:
        json_data: Submission dict from eRisk 2025
        label: 1 for positive, 0 for negative
        target_subject: If provided, only extract texts from this subject
    
    Returns:
        List of entry dicts
    """
    entries = []
    
    # Extract submission body
    if json_data.get("body"):
        # Only include if no target_subject filter, or if author matches
        if target_subject is None or json_data.get("author") == target_subject:
            entry = {
                "text": json_data["body"].strip(),
                "lang": "en",
                "labels": {
                    "self_harm": label,
                    "abuse": 0,
                    "unsafe_env": 0
                },
                "source": "erisk_json",
                "date": json_data.get("date", ""),
                "round": json_data.get("number", 0),
                "split": "train"
            }
            if entry["text"]:
                entries.append(entry)
    
    # Extract comments
    for comment in json_data.get("comments", []):
        # Only include if no target_subject filter, or if author matches
        if target_subject is None or comment.get("author") == target_subject:
            if comment.get("body"):
                entry = {
                    "text": comment["body"].strip(),
                    "lang": "en",
                    "labels": {
                        "self_harm": label,
                        "abuse": 0,
                        "unsafe_env": 0
                    },
                    "source": "erisk_json",
                    "date": comment.get("date", ""),
                    "split": "train"
                }
                if entry["text"]:
                    entries.append(entry)
    
    return entries


def main():
    """Convert eRisk collection to training JSONL."""
    ap = argparse.ArgumentParser()
    ap.add_argument('--erisk_dir', required=True, help='eRisk data directory')
    ap.add_argument('--output', required=True, help='Output JSONL path')
    ap.add_argument('--label', required=True, choices=['self_harm', 'depression'], 
                    help='Label type (self_harm or depression)')
    ap.add_argument('--format', choices=['xml', 'json', 'auto'], default='auto',
                    help='Input format (auto-detect by default)')
    ap.add_argument('--positive_dir', help='Directory with positive cases (XML only)')
    ap.add_argument('--negative_dir', help='Directory with negative cases (XML only)')
    ap.add_argument('--target_subjects', help='File with target subject IDs (JSON only, one per line)')
    args = ap.parse_args()
    
    erisk_path = Path(args.erisk_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    all_entries = []
    
    # Auto-detect format
    format_type = args.format
    if format_type == 'auto':
        if list(erisk_path.glob('*.json')):
            format_type = 'json'
            print("[INFO] Auto-detected JSON format (eRisk 2025)")
        elif list(erisk_path.glob('*.xml')):
            format_type = 'xml'
            print("[INFO] Auto-detected XML format (eRisk 2016-2024)")
        else:
            print("[ERROR] No XML or JSON files found!")
            return
    
    # Load target subjects if provided
    target_subjects = set()
    if args.target_subjects:
        with open(args.target_subjects, 'r') as f:
            target_subjects = {line.strip() for line in f if line.strip()}
        print(f"[INFO] Loaded {len(target_subjects)} target subjects")
    
    # Convert based on format
    if format_type == 'xml':
        # XML format (old eRisk)
        pos_dir = Path(args.positive_dir) if args.positive_dir else erisk_path / 'positive'
        neg_dir = Path(args.negative_dir) if args.negative_dir else erisk_path / 'negative'
        
        print("[INFO] Converting XML format...")
        print(f"[INFO] Positive dir: {pos_dir}")
        print(f"[INFO] Negative dir: {neg_dir}")
        
        # Positive cases
        if pos_dir.exists():
            for xml_file in pos_dir.glob('*.xml'):
                entries = convert_xml_user(xml_file, label=1)
                all_entries.extend(entries)
                print(f"[INFO] Processed {xml_file.name}: {len(entries)} entries")
        
        # Negative cases
        if neg_dir.exists():
            for xml_file in neg_dir.glob('*.xml'):
                entries = convert_xml_user(xml_file, label=0)
                all_entries.extend(entries)
                print(f"[INFO] Processed {xml_file.name}: {len(entries)} entries")
    
    elif format_type == 'json':
        # JSON format (eRisk 2025)
        print("[INFO] Converting JSON format (eRisk 2025)...")
        
        # Assuming positive/negative labels are in filenames or metadata
        for json_file in erisk_path.glob('*.json'):
            print(f"[INFO] Processing {json_file.name}...")
            
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Determine label from filename or metadata
            label = 1 if 'positive' in json_file.stem.lower() or 'depression' in json_file.stem.lower() else 0
            
            # Process each submission
            for submission in data:
                target = submission.get("targetSubject")
                
                # Filter by target subjects if provided
                if target_subjects and target not in target_subjects:
                    continue
                
                # Extract texts (filter by target subject if specified)
                entries = convert_json_user(submission, label=label, target_subject=target)
                all_entries.extend(entries)
            
            print(f"[INFO] Extracted {len(all_entries)} total entries so far")
    
    # Shuffle entries
    random.seed(42)
    random.shuffle(all_entries)
    
    # Write to JSONL
    with open(output_path, 'w', encoding='utf-8') as f:
        for entry in all_entries:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    # Stats
    n_positive = sum(1 for e in all_entries if e['labels']['self_harm'] == 1)
    n_negative = len(all_entries) - n_positive
    
    print("\n[OK] Conversion complete!")
    print(f"[OK] Total entries: {len(all_entries)}")
    print(f"[OK] Positive: {n_positive} ({n_positive/len(all_entries)*100:.1f}%)")
    print(f"[OK] Negative: {n_negative} ({n_negative/len(all_entries)*100:.1f}%)")
    print(f"[OK] Output: {output_path}")
    print("\n[NEXT] Split data into train/dev/test:")
    print(f"  python tools/layer15/split_data.py --input {output_path} --ratios 0.8 0.1 0.1")


if __name__ == '__main__':
    main()










