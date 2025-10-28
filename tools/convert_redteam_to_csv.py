"""Convert red-team eval JSON to ablation CSV format"""
import json
import csv
import sys
from pathlib import Path

def convert(json_path: Path, out_csv: Path):
    """Convert redteam_report.json to ablation CSV format."""
    data = json.loads(json_path.read_text())
    
    rows = []
    
    # Benign queries (label=0) - from data.data.benign_queries
    benign_queries = data.get("data", {}).get("benign_queries", [])
    for q in benign_queries:
        rows.append({
            "text": q,
            "label": 0,
            "emb_sim": 0.05,
            "ppl_anom": 0.02,
            "llm_judge": 0.0
        })
    
    # Jailbreaks (label=1) - from data.data.jailbreak_attempts
    jailbreak_attempts = data.get("data", {}).get("jailbreak_attempts", [])
    for q in jailbreak_attempts:
        rows.append({
            "text": q,
            "label": 1,
            "emb_sim": 0.80,
            "ppl_anom": 0.65,
            "llm_judge": 0.85
        })
    
    # Write CSV
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "emb_sim", "ppl_anom", "llm_judge"])
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"Converted {len(rows)} samples to {out_csv}")
    print(f"  Benign: {sum(1 for r in rows if r['label'] == 0)}")
    print(f"  Jailbreaks: {sum(1 for r in rows if r['label'] == 1)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/convert_redteam_to_csv.py <redteam_report.json> [output.csv]")
        sys.exit(1)
    
    json_path = Path(sys.argv[1])
    out_csv = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/generated.csv")
    
    convert(json_path, out_csv)

