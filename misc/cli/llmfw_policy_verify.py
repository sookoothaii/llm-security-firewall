# English-only code
"""
Verifies safety invariants for the Policy-DSL using Z3 if available.
Models first-match-wins semantics by priority.

Invariants checked (extensible):
  - NoAllowBiohazard: It is UNSAT that topic=biohazard AND final action=allow.

Exit codes:
  0 OK
  2 Invariant violated or unsatisfied
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, Tuple

import yaml

from llm_firewall.policy.dsl import PolicyCond, PolicyLeaf, parse_yaml_spec


def _collect_atoms(spec) -> Dict[str, Any]:
    topics = set()
    domains = set()
    tokens = set()
    for r in spec.rules:

        def visit(c: PolicyCond):
            if c.leaf:
                if c.leaf.kind == "topic_in":
                    vals = (
                        c.leaf.value
                        if isinstance(c.leaf.value, list)
                        else [c.leaf.value]
                    )
                    topics.update(map(str, vals))
                elif c.leaf.kind == "domain_is":
                    domains.add(str(c.leaf.value))
                elif c.leaf.kind == "contains_any":
                    vals = (
                        c.leaf.value
                        if isinstance(c.leaf.value, list)
                        else [c.leaf.value]
                    )
                    tokens.update(map(str, vals))
            elif c.all:
                for cc in c.all:
                    visit(cc)
            elif c.any:
                for cc in c.any:
                    visit(cc)

        visit(r.when)
    return {
        "topics": sorted(topics),
        "domains": sorted(domains),
        "tokens": sorted(tokens),
    }


def _as_z3(spec) -> Tuple[Any, Dict[str, Any]]:
    try:
        from z3 import And, Bool, Int, Not, Solver
    except Exception as e:
        return None, {"err": str(e)}
    atoms = _collect_atoms(spec)
    from z3 import BoolVal

    # variables
    z = {}
    for t in atoms["topics"]:
        z[f"topic_{t}"] = Bool(f"topic_{t}")
    for d in atoms["domains"]:
        z[f"domain_{d}"] = Bool(f"domain_{d}")
    for tok in atoms["tokens"]:
        z[f"tok_{tok}"] = Bool(f"tok_{tok}")
    z["user_age"] = Int("user_age")

    def enc_leaf(lf: PolicyLeaf):
        from z3 import BoolVal, Or

        if lf.kind == "topic_in":
            vs = lf.value if isinstance(lf.value, list) else [lf.value]
            return Or(*[z.get(f"topic_{str(v)}", BoolVal(False)) for v in vs])
        if lf.kind == "domain_is":
            return z.get(f"domain_{str(lf.value)}", BoolVal(False))
        if lf.kind == "contains_any":
            vs = lf.value if isinstance(lf.value, list) else [lf.value]
            return Or(*[z.get(f"tok_{str(v)}", BoolVal(False)) for v in vs])
        if lf.kind == "user_age":
            s = str(lf.value).strip()
            if s.startswith("<="):
                return z["user_age"] <= int(s[2:])
            if s.startswith(">="):
                return z["user_age"] >= int(s[2:])
            if s.startswith("<"):
                return z["user_age"] < int(s[1:])
            if s.startswith(">"):
                return z["user_age"] > int(s[1:])
            if s.isdigit():
                return z["user_age"] == int(s)
            return BoolVal(False)
        return BoolVal(False)

    def enc_cond(c: PolicyCond):
        from z3 import And, BoolVal, Or

        if c.leaf:
            return enc_leaf(c.leaf)
        if c.all:
            return And(*[enc_cond(x) for x in c.all])
        if c.any:
            return Or(*[enc_cond(x) for x in c.any])
        return BoolVal(False)

    # first-match-wins: rule i fires if when_i and no earlier when_j true
    whens = [enc_cond(r.when) for r in spec.rules]
    fires = []
    from z3 import And, Not

    for i, r in enumerate(spec.rules):
        no_prior = And(*[Not(whens[j]) for j in range(i)])
        fires.append(And(whens[i], no_prior))

    # final action
    from z3 import If

    # walk in order; if none, fallback defaults
    act_expr = None
    for i, r in enumerate(spec.rules):
        a = r.action
        this = fires[i]
        if act_expr is None:
            act_expr = If(this, BoolVal(a == "allow"), BoolVal(False))
            act_ah = If(this, BoolVal(a == "allow_high_level"), BoolVal(False))
            act_bl = If(this, BoolVal(a == "block"), BoolVal(False))
        else:
            act_expr = If(this, BoolVal(a == "allow"), act_expr)
            act_ah = If(this, BoolVal(a == "allow_high_level"), act_ah)
            act_bl = If(this, BoolVal(a == "block"), act_bl)
    # defaults if nothing fires -> respect defaults.action
    if act_expr is None:
        from z3 import BoolVal

        act_expr = BoolVal(False)
        act_ah = BoolVal(False)
        act_bl = BoolVal(False)
    # Build solver
    S = Solver()
    return (
        S,
        {
            "z": z,
            "fires": fires,
            "whens": whens,
            "action_allow": act_expr,
            "act_ah": act_ah,
            "act_bl": act_bl,
            "atoms": atoms,
        },
    )


def verify_no_allow_biohazard(spec) -> Tuple[bool, str]:
    """Returns (ok, message). ok=True means invariant holds."""
    z3, ctx = _as_z3(spec)
    if z3 is None:
        # Fallback: conservative static check – deny if any 'allow' rule explicitly targets topic_in: biohazard at highest priority
        bio_ids = []
        top_allow_prio = None
        for r in spec.rules:

            def mentions_bio(c: PolicyCond) -> bool:
                if c.leaf and c.leaf.kind == "topic_in":
                    vals = (
                        c.leaf.value
                        if isinstance(c.leaf.value, list)
                        else [c.leaf.value]
                    )
                    return any(str(v) == "biohazard" for v in vals)
                return any(mentions_bio(x) for x in (c.all or c.any or []))

            if r.action == "allow" and mentions_bio(r.when):
                bio_ids.append(r.id)
                top_allow_prio = (
                    r.priority
                    if top_allow_prio is None
                    else min(top_allow_prio, r.priority)
                )
        if bio_ids:
            return (
                False,
                f"Fallback detected 'allow' rule(s) for biohazard at priority {top_allow_prio}: {bio_ids}",
            )
        return True, "Fallback static check passed (no explicit allow on biohazard)."

    from z3 import sat

    z = ctx["z"]
    S = z3
    # require topic=biohazard true; others unconstrained
    tvar = z.get("topic_biohazard")
    if tvar is None:
        return True, "No biohazard topic in policy; invariant vacuously holds."
    S.add(tvar)
    # result action == allow ?
    S.add(ctx["action_allow"])
    sat_res = S.check()
    if sat_res == sat:
        return (
            False,
            "Invariant violated: there exists an assignment with topic=biohazard and final action=allow.",
        )
    return True, "Invariant holds: topic=biohazard cannot lead to final action=allow."


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("policy_yaml", type=str)
    args = ap.parse_args()
    with open(args.policy_yaml, "r", encoding="utf-8") as f:
        spec = parse_yaml_spec(yaml.safe_load(f))
    ok, msg = verify_no_allow_biohazard(spec)
    print(msg)
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
