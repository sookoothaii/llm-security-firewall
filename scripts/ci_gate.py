import json
import sys

res=json.load(open('ablation.json'))
def ok_arm(a):
    m=res[a]; return (m["ece"]<=0.05 and m["brier"]<=0.10)
ok = ok_arm("A2") and (res["A2"]["asr_at_thr"] <= res["A0"]["asr_at_thr"]*0.90)
print("A0:",res["A0"])
print("A2:",res["A2"])
sys.exit(0 if ok else 1)
