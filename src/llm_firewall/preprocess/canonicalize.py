# -*- coding: utf-8 -*-
"""
Lightweight canonicalizers with safe fallbacks (no external deps).
- YAML: detect anchors/aliases; if found, collapse to literal safe form
- JSON: merge duplicate keys deterministically (keep last)
- XML: expand internal entities only (no external fetch), with byte cap
"""
import json
import re

def canonicalize_json_keep_last(s: str) -> str:
    try:
        obj = json.loads(s, object_pairs_hook=list)
        if isinstance(obj, list):
            def fold_pairs(pairs):
                m = {}
                for k, v in pairs:
                    if isinstance(v, list) and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in v):
                        v = fold_pairs(v)
                    m[k] = v
                return m
            flat = fold_pairs(obj)
            return json.dumps(flat, ensure_ascii=False)
        return s
    except Exception:
        return s

_YAML_ANCHOR = re.compile(r"[&][A-Za-z0-9_-]+")
_YAML_ALIAS = re.compile(r"[*][A-Za-z0-9_-]+")

def canonicalize_yaml_best_effort(s: str, max_anchors: int = 4):
    """If anchors/aliases detected, neutralize to literal block"""
    anchors = len(_YAML_ANCHOR.findall(s)) + len(_YAML_ALIAS.findall(s))
    if anchors == 0:
        return s, {"yaml_anchors": 0, "yaml_neutralized": False}
    if anchors > max_anchors:
        return "|-\n  [[YAML_ANCHORS_TRUNCATED]]", {"yaml_anchors": anchors, "yaml_neutralized": True}
    literal = "|-\n  " + s.replace("\n", "\n  ")
    return literal, {"yaml_anchors": anchors, "yaml_neutralized": True}

_XML_ENTITY = re.compile(r"<!ENTITY\s+([A-Za-z_:][\w:.-]*)\s+'([^']{0,1024})'\s*>")

def expand_xml_internal_entities(s: str, max_total: int = 2048):
    """Replace internal entity defs and references"""
    entities = dict(_XML_ENTITY.findall(s))
    total = sum(len(v) for v in entities.values())
    if total > max_total:
        return s, {"xml_entities": len(entities), "xml_truncated": True}
    out = s
    for k, v in entities.items():
        out = re.sub(r"&"+re.escape(k)+r";", v, out)
    out = _XML_ENTITY.sub("", out)
    return out, {"xml_entities": len(entities), "xml_truncated": False}

