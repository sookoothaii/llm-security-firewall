from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import specific functions without triggering full __init__.py
from llm_firewall.config import _pick_lex_base
from llm_firewall.risk.stacking import MetaEnsemble, gate_by_calibration, load_artifacts
from llm_firewall.rules.scoring_gpt5 import (
    ACMatcher,
    evaluate,
    load_lexicons,
)
from llm_firewall.text.normalize import canonicalize

LEX_BASE = _pick_lex_base()
_artifacts_base = lambda: Path(__file__).parent.parent / "artifacts" / "meta"

def load_csv(path: Path) -> List[Tuple[str,int,Dict[str,float]]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append((row["text"], int(row["label"]), {
                "emb_sim": float(row.get("emb_sim", 0.0)),
                "ppl_anom": float(row.get("ppl_anom", 0.0)),
                "llm_judge": float(row.get("llm_judge", 0.0)),
            }))
    return rows

def youden(scores, labels):
    pairs = sorted(zip(scores, labels))
    thr, bestJ = 0.5, -1.0
    P = sum(labels); N = len(labels)-P
    for t,_ in pairs:
        tp = sum(1 for s,y in zip(scores,labels) if s>=t and y==1)
        fp = sum(1 for s,y in zip(scores,labels) if s>=t and y==0)
        tpr = tp/max(P,1); fpr = fp/max(N,1)
        J = tpr - fpr
        if J > bestJ: bestJ, thr = J, t
    return thr

def metric(scores, labels, thr):
    P = sum(labels); N = len(labels)-P
    # AUROC (trapezoid, naive)
    pairs = sorted(zip(scores, labels))
    ths = [s for s,_ in pairs]
    tprs, fprs = [], []
    for t in ths:
        tp = sum(1 for s,y in zip(scores,labels) if s>=t and y==1)
        fp = sum(1 for s,y in zip(scores,labels) if s>=t and y==0)
        tpr = tp/max(P,1); fpr = fp/max(N,1)
        tprs.append(tpr); fprs.append(fpr)
    auroc = 0.0
    for i in range(1,len(tprs)):
        auroc += (fprs[i]-fprs[i-1]) * (tprs[i]+tprs[i-1]) / 2.0
    # ECE/Brier
    bins = 15; n = len(scores); ece = 0.0
    for b in range(bins):
        lo, hi = b/bins, (b+1)/bins
        idx = [i for i,s in enumerate(scores) if lo <= s < hi or (b==bins-1 and s==1.0)]
        if not idx: continue
        conf = sum(scores[i] for i in idx)/len(idx)
        true = sum(labels[i] for i in idx)/len(idx)
        ece += (len(idx)/n) * abs(true - conf)
    brier = sum((s-y)**2 for s,y in zip(scores,labels))/max(n,1)
    tp = sum(1 for s,y in zip(scores,labels) if s>=thr and y==1)
    fp = sum(1 for s,y in zip(scores,labels) if s>=thr and y==0)
    asr = (P - tp)/max(P,1)
    fpr = fp/max(N,1)
    return {"auroc":auroc, "ece":ece, "brier":brier, "asr_at_thr":asr, "fpr_at_thr":fpr}

def score_arm(text: str, arm: str, detectors: Dict[str,float]) -> float:
    base = LEX_BASE
    res = evaluate(text, base_dir=base)
    patt = res["pattern"]["score"]
    if arm == "A0":
        intent = 0.0; margin = 0.0
    elif arm == "A1":
        intents, evasions, harms = load_lexicons(base)
        per = {}
        for c in intents["clusters"]:
            cid = c["id"]; base_w = 1.0 + (c.get("priority",0)/20.0)
            phrases = [(s, base_w) for s in c.get("synonyms", [])]
            ac = ACMatcher(phrases)
            hits = ac.findall(text)
            per[cid] = sum(next((w for (p,w) in phrases if p==pat), 0.0) for (_,pat) in hits)
        tot = sum(per.values()) + 1e-9
        for k in per: per[k] /= tot
        srt = sorted(per.items(), key=lambda kv: -kv[1])
        intent = srt[0][1]; margin = intent - (srt[1][1] if len(srt)>1 else 0.0)
    elif arm in ("A2","A3"):
        intent = float(res["intent"]["lex_score"]); margin = float(res["intent"].get("margin", 0.0))
    else:
        raise ValueError("arm must be A0/A1/A2/A3")
    lin = min(1.0, 0.6*patt + 0.3*intent + 0.1*margin)
    if arm == "A3":
        try:
            art = load_artifacts(_artifacts_base())
            if gate_by_calibration(art):
                ev = res["pattern"]["by_category"].get("obfuscation_encoding",0.0)+res["pattern"]["by_category"].get("unicode_evasion",0.0)
                evden = 1.0 - math.exp(-ev/3.0)
                feats = [detectors.get("emb_sim",0.0), detectors.get("ppl_anom",0.0), detectors.get("llm_judge",0.0),
                         intent, margin, patt, evden]
                meta = MetaEnsemble(art)
                return float(meta.predict_proba(feats))
        except Exception:
            pass
    return float(lin)

def run(dev_csv: Path, test_csv: Path|None):
    dev = load_csv(dev_csv)
    test = load_csv(test_csv) if test_csv and test_csv.exists() else dev
    arms = ["A0","A1","A2","A3"]
    out = {}
    for arm in arms:
        dev_scores = [score_arm(canonicalize(t), arm, d) for (t,y,d) in dev]
        dev_labels = [y for (t,y,d) in dev]
        thr = youden(dev_scores, dev_labels)
        tst_scores = [score_arm(canonicalize(t), arm, d) for (t,y,d) in test]
        tst_labels = [y for (t,y,d) in test]
        out[arm] = {"threshold": thr, **metric(tst_scores, tst_labels, thr)}
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev_csv", required=True)
    ap.add_argument("--test_csv", default="")
    args = ap.parse_args()
    run(Path(args.dev_csv), Path(args.test_csv) if args.test_csv else None)
