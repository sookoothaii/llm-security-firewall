"""Download public mental health datasets (no registration needed).

Sources:
- HuggingFace: gooohjy/suicidal-mental-health-dataset
- HuggingFace: Amod/mental_health_counseling_conversations
- Pushshift Reddit: r/SuicideWatch (public API)

Credit: Layer 15 Crisis Detection, 2025-11-04
"""

import argparse
import json
import os
from pathlib import Path


def download_huggingface_dataset(dataset_name: str, output_dir: str):
    """Download dataset from HuggingFace.
    
    Args:
        dataset_name: HuggingFace dataset identifier
        output_dir: Output directory
    """
    try:
        from datasets import load_dataset
    except ImportError:
        print("[ERROR] Please install: pip install datasets")
        return
    
    print(f"[INFO] Downloading {dataset_name} from HuggingFace...")
    
    try:
        dataset = load_dataset(dataset_name)
        
        # Convert to JSONL
        output_path = Path(output_dir) / f"{dataset_name.replace('/', '_')}.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for split_name, split_data in dataset.items():
                print(f"[INFO] Processing split: {split_name} ({len(split_data)} examples)")
                
                for item in split_data:
                    # Convert to our format
                    text = item.get('text', '') or item.get('question', '') or item.get('input', '')
                    
                    # Detect self-harm indicators (weak labels)
                    self_harm_keywords = ['suicide', 'kill myself', 'end my life', 'suicidal', 'self harm']
                    self_harm = 1 if any(kw in text.lower() for kw in self_harm_keywords) else 0
                    
                    entry = {
                        "text": text,
                        "lang": "en",
                        "labels": {
                            "self_harm": self_harm,
                            "abuse": 0,
                            "unsafe_env": 0
                        },
                        "source": f"huggingface_{dataset_name}",
                        "split": split_name
                    }
                    
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        
        print(f"[OK] Saved to {output_path}")
        return str(output_path)
        
    except Exception as e:
        print(f"[ERROR] Failed to download {dataset_name}: {e}")
        return None


def download_reddit_public(subreddit: str, output_dir: str, limit: int = 1000):
    """Download public Reddit data (no API key needed for read).
    
    Args:
        subreddit: Subreddit name (e.g., 'SuicideWatch')
        output_dir: Output directory
        limit: Max posts to download
    """
    try:
        import praw
    except ImportError:
        print("[INFO] Reddit download requires: pip install praw")
        print("[INFO] Skipping Reddit download...")
        return None
    
    print(f"[INFO] Downloading r/{subreddit} (public posts only)...")
    
    try:
        # Create read-only instance (no auth needed)
        reddit = praw.Reddit(
            client_id="public_read_only",
            client_secret="",
            user_agent="Layer15CrisisDetection/1.0"
        )
        
        subreddit_obj = reddit.subreddit(subreddit)
        
        output_path = Path(output_dir) / f"reddit_{subreddit}.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        count = 0
        with open(output_path, 'w', encoding='utf-8') as f:
            for post in subreddit_obj.hot(limit=limit):
                if not post.selftext:
                    continue
                
                entry = {
                    "text": post.title + "\n" + post.selftext,
                    "lang": "en",
                    "labels": {
                        "self_harm": 1,  # r/SuicideWatch = high prior
                        "abuse": 0,
                        "unsafe_env": 0
                    },
                    "source": f"reddit_{subreddit}",
                    "split": "train"
                }
                
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
                count += 1
                
                if count % 100 == 0:
                    print(f"  Downloaded {count} posts...")
        
        print(f"[OK] Saved {count} posts to {output_path}")
        return str(output_path)
        
    except Exception as e:
        print(f"[ERROR] Reddit download failed: {e}")
        return None


def expand_synthetic_data(input_jsonl: str, output_jsonl: str, target_size: int = 1000):
    """Expand synthetic data using augmentation.
    
    Args:
        input_jsonl: Existing synthetic JSONL
        output_jsonl: Expanded output
        target_size: Target number of samples
    """
    print(f"[INFO] Expanding synthetic data to {target_size} samples...")
    
    # Load existing
    with open(input_jsonl, 'r', encoding='utf-8') as f:
        existing = [json.loads(line) for line in f if line.strip()]
    
    print(f"[INFO] Loaded {len(existing)} existing samples")
    
    # Simple augmentation: paraphrase patterns
    augmentations = [
        {"prefix": "", "suffix": ""},  # original
        {"prefix": "I'm feeling like ", "suffix": ""},
        {"prefix": "", "suffix": " and I don't know what to do"},
        {"prefix": "Help me, ", "suffix": ""},
        {"prefix": "I can't stop thinking about ", "suffix": ""},
    ]
    
    expanded = []
    for item in existing:
        # Add original
        expanded.append(item)
        
        # Add augmented versions
        for aug in augmentations[1:]:  # Skip first (original)
            if len(expanded) >= target_size:
                break
            
            augmented = item.copy()
            augmented["text"] = aug["prefix"] + item["text"] + aug["suffix"]
            augmented["source"] = "synthetic_augmented"
            expanded.append(augmented)
        
        if len(expanded) >= target_size:
            break
    
    # Write expanded
    Path(output_jsonl).parent.mkdir(parents=True, exist_ok=True)
    with open(output_jsonl, 'w', encoding='utf-8') as f:
        for item in expanded:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    
    print(f"[OK] Expanded to {len(expanded)} samples: {output_jsonl}")
    return output_jsonl


def main():
    """Download and prepare public datasets."""
    ap = argparse.ArgumentParser()
    ap.add_argument('--output_dir', default='data/layer15/public', help='Output directory')
    ap.add_argument('--expand_synthetic', help='Path to existing synthetic JSONL to expand')
    ap.add_argument('--target_size', type=int, default=1000, help='Target size for expansion')
    args = ap.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    print("\n=== DOWNLOADING PUBLIC DATASETS (NO REGISTRATION) ===\n")
    
    # 1. HuggingFace: Suicidal Mental Health Dataset
    print("[1/3] HuggingFace: gooohjy/suicidal-mental-health-dataset")
    hf1 = download_huggingface_dataset("gooohjy/suicidal-mental-health-dataset", args.output_dir)
    
    # 2. HuggingFace: Mental Health Counseling
    print("\n[2/3] HuggingFace: Amod/mental_health_counseling_conversations")
    hf2 = download_huggingface_dataset("Amod/mental_health_counseling_conversations", args.output_dir)
    
    # 3. Reddit public (optional)
    print("\n[3/3] Reddit: r/SuicideWatch (public posts)")
    reddit = download_reddit_public("SuicideWatch", args.output_dir, limit=500)
    
    # 4. Expand synthetic if provided
    if args.expand_synthetic and Path(args.expand_synthetic).exists():
        print("\n[4/4] Expanding synthetic data...")
        synthetic_expanded = expand_synthetic_data(
            args.expand_synthetic,
            os.path.join(args.output_dir, "synthetic_expanded.jsonl"),
            target_size=args.target_size
        )
    
    print("\n=== DOWNLOAD COMPLETE ===")
    print(f"\nFiles in {args.output_dir}:")
    for f in Path(args.output_dir).glob("*.jsonl"):
        lines = sum(1 for _ in open(f, 'r', encoding='utf-8'))
        print(f"  - {f.name}: {lines} samples")
    
    print("\n[NEXT] Combine datasets:")
    print(f"  cat {args.output_dir}/*.jsonl > data/layer15/train_combined.jsonl")
    print("  python tools/layer15/split_data.py --input data/layer15/train_combined.jsonl --ratios 0.8 0.1 0.1")


if __name__ == '__main__':
    main()

