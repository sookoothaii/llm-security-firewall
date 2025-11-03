"""Train Layer 15 Crisis Detection Model (Stage A: Self-Harm).

Architecture: xlm-roberta-base + 3-label multi-label head
Data: eRisk 2021, CLPsych/UMD Reddit Suicidality (public sources)
Target: Dev Recall >= 0.90 @ Precision >= 0.60 for self_harm
Output: models/layer15_crisis/ + thresholds.json

IMPORTANT: Requires public datasets (eRisk 2021, CLPsych, etc.)
Registration/licensing required for some sources.

Credit: GPT-5 collaboration 2025-11-04
"""

import os
import json
import argparse

import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup


class CrisisJSONL(Dataset):
    """Crisis detection dataset from JSONL."""
    
    def __init__(self, path: str, tokenizer, max_len=256):
        self.rows = [json.loads(x) for x in open(path, 'r', encoding='utf-8') if x.strip()]
        self.tok = tokenizer
        self.max_len = max_len
    
    def __len__(self):
        return len(self.rows)
    
    def __getitem__(self, i):
        r = self.rows[i]
        enc = self.tok(r['text'], truncation=True, padding='max_length', max_length=self.max_len, return_tensors='pt')
        y = [
            int(r['labels'].get('self_harm', 0)),
            int(r['labels'].get('abuse', 0)),
            int(r['labels'].get('unsafe_env', 0))
        ]
        return {
            'input_ids': enc['input_ids'].squeeze(0),
            'attention_mask': enc['attention_mask'].squeeze(0),
            'labels': torch.tensor(y, dtype=torch.float32)
        }


def fbeta(p, y, beta=2, eps=1e-7):
    """Compute F-beta score."""
    tp = ((p == 1) & (y == 1)).sum().item()
    fp = ((p == 1) & (y == 0)).sum().item()
    fn = ((p == 0) & (y == 1)).sum().item()
    
    prec = tp / (tp + fp + eps)
    rec = tp / (tp + fn + eps)
    
    b2 = beta * beta
    fbeta_score = (1 + b2) * prec * rec / (b2 * prec + rec + eps)
    
    return fbeta_score, prec, rec


def main():
    """Train crisis detection model."""
    ap = argparse.ArgumentParser()
    ap.add_argument('--train', required=True, help='Training JSONL path')
    ap.add_argument('--dev', required=True, help='Dev JSONL path')
    ap.add_argument('--outdir', default='models/layer15_crisis', help='Output directory')
    ap.add_argument('--epochs', type=int, default=3, help='Training epochs')
    ap.add_argument('--bsz', type=int, default=16, help='Batch size')
    ap.add_argument('--lr', type=float, default=3e-5, help='Learning rate')
    args = ap.parse_args()
    
    os.makedirs(args.outdir, exist_ok=True)
    
    # Model setup
    name = 'xlm-roberta-base'
    print(f"[INFO] Loading {name}...")
    tok = AutoTokenizer.from_pretrained(name)
    model = AutoModelForSequenceClassification.from_pretrained(
        name,
        num_labels=3,
        problem_type='multi_label_classification'
    )
    
    # Datasets
    print(f"[INFO] Loading training data from {args.train}...")
    tr = CrisisJSONL(args.train, tok)
    print(f"[INFO] Loading dev data from {args.dev}...")
    dv = CrisisJSONL(args.dev, tok)
    
    tl = DataLoader(tr, batch_size=args.bsz, shuffle=True)
    dl = DataLoader(dv, batch_size=32)
    
    # Optimizer & scheduler
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
    total = len(tl) * args.epochs
    sch = get_linear_schedule_with_warmup(opt, int(0.06 * total), total)
    
    # Device setup
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"[INFO] Device: {device}")
    model.to(device)
    
    # Loss (emphasize self_harm recall)
    w = torch.tensor([2.0, 1.0, 1.0]).to(device)  # Class weights
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=w)
    
    # Training loop
    best_f = -1
    print(f"[INFO] Starting training for {args.epochs} epochs...")
    
    for ep in range(args.epochs):
        # Train
        model.train()
        for b in tl:
            b = {k: v.to(device) for k, v in b.items()}
            out = model(input_ids=b['input_ids'], attention_mask=b['attention_mask'])
            loss = loss_fn(out.logits, b['labels'])
            loss.backward()
            opt.step()
            sch.step()
            opt.zero_grad()
        
        # Dev evaluation
        model.eval()
        ys = []
        ps = []
        
        with torch.no_grad():
            for b in dl:
                b = {k: v.to(device) for k, v in b.items()}
                out = model(input_ids=b['input_ids'], attention_mask=b['attention_mask'])
                probs = torch.sigmoid(out.logits).cpu()
                ys.append(b['labels'].cpu())
                ps.append(probs)
        
        Y = torch.cat(ys, 0)
        P = torch.cat(ps, 0)
        
        # High-recall threshold for self_harm (class 0)
        thr_sh = 0.35
        pred = (P >= torch.tensor([thr_sh, 0.5, 0.5])).int()
        
        f, prec, rec = fbeta(pred[:, 0], Y[:, 0].int(), beta=2)
        print(f"[Epoch {ep+1}/{args.epochs}] dev self_harm F2={f:.3f} P={prec:.3f} R={rec:.3f}")
        
        # Save best model
        if f > best_f:
            best_f = f
            print(f"  [BEST] Saving model to {args.outdir}")
            model.save_pretrained(args.outdir)
            tok.save_pretrained(args.outdir)
            
            # Save thresholds
            with open(os.path.join(args.outdir, 'thresholds.json'), 'w') as fjson:
                json.dump({
                    "self_harm": float(thr_sh),
                    "abuse": 0.5,
                    "unsafe_env": 0.5
                }, fjson)
    
    print("\n[OK] Training complete!")
    print(f"[OK] Best F2: {best_f:.3f}")
    print(f"[OK] Model saved to {args.outdir}")
    print(f"[OK] Thresholds saved to {os.path.join(args.outdir, 'thresholds.json')}")
    print("\n[WARNING] This is Stage A (Self-Harm focus)")
    print("[WARNING] Abuse/Unsafe-Env remain regex-based until Stage B")


if __name__ == '__main__':
    main()

