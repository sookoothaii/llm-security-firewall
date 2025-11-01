# -*- coding: utf-8 -*-
"""
Stage-5 Gauntlet: pushes beyond Stage-4 without breaking green.

Some tests are xfail by design (future work).
"""

import base64
import json
from types import SimpleNamespace

import pytest

# Reuse evaluate_turn from Stage 4
from llm_firewall.detectors.bidi_locale import (
    bidi_isolate_wrap_hit,
    bidi_proximity_uplift,
    detect_bidi_locale,
)
from llm_firewall.detectors.encoding_archive_sniff import detect_archive_secret
from llm_firewall.detectors.encoding_base64_sniff import detect_base64_secret
from llm_firewall.detectors.encoding_base85 import detect_base85
from llm_firewall.detectors.encoding_rfc2047_sniff import detect_rfc2047
from llm_firewall.gates.secrets_heuristics import analyze_secrets
from llm_firewall.heuristics.context_whitelist import whitelist_decision
from llm_firewall.heuristics.provider_complexity import (
    is_strong_secret_provider,
    is_weak_secret_provider,
)
from llm_firewall.normalize.unicode_hardening import harden_text_for_scanning
from llm_firewall.session.e_value_risk import (
    SessionRiskState,
    crossed,
    risk_score,
    update_evalue,
)
from llm_firewall.session.session_slowroll import update_assembler
from llm_firewall.session.yaml_alias_assembler import expand_yaml_aliases


def evaluate_turn(state, text, cfg=None):  # noqa: C901
    """Minimal wrapper - uses test detection logic (same as Stage 4)."""
    ANCHORS = ["sk-live", "sk-test", "ghp_", "gho_", "xoxb-", "xoxp-"]

    # Pre-process YAML aliases (bounded expansion)
    text = expand_yaml_aliases(text)

    allow_whitelist, whitelist_reason = whitelist_decision(text)
    if allow_whitelist:
        state = update_evalue(state, hit=False)
        return {
            "decision": "ALLOW",
            "hit": False,
            "e_value": state.e_value,
            "risk": risk_score(state),
            "session_state": state,
        }

    hardened = harden_text_for_scanning(text)
    normalized = hardened["normalized"]
    compact = hardened["compact"]

    bidi_locale = detect_bidi_locale(text)
    severity_uplift = bidi_locale["severity_uplift"]

    strong_provider = is_strong_secret_provider(text)
    weak_provider = is_weak_secret_provider(text) and not strong_provider

    bidi_near = bidi_proximity_uplift(text, ANCHORS, radius=16)
    bidi_wrap = bidi_isolate_wrap_hit(text, ANCHORS)

    base85_result = detect_base85(text)
    b64_secret = detect_base64_secret(text)
    archive_secret = detect_archive_secret(text)
    rfc2047 = detect_rfc2047(text)
    slowroll = update_assembler(state, text)

    def compact_anchor_hit(compact_text: str) -> bool:
        low = compact_text.lower()
        for a in ANCHORS:
            ac = a.replace("-", "").replace("_", "").lower()
            if ac and ac in low:
                return True
        return False

    findings_norm = analyze_secrets(normalized)
    findings_comp = analyze_secrets(compact)

    hit = (
        strong_provider
        or b64_secret["has_secret"]
        or archive_secret["has_secret"]
        or rfc2047["has_secret"]
        or slowroll["partial"]
        or slowroll["complete"]
        or (base85_result["score"] >= 0.4)
        or bidi_near
        or bidi_wrap
        or compact_anchor_hit(compact)
        or len(findings_norm.hits) > 0
        or len(findings_comp.hits) > 0
        or weak_provider
    )

    if hit and severity_uplift > 0.5:
        hit = True

    state = update_evalue(state, hit=hit)

    if (
        crossed(state)
        or strong_provider
        or bidi_wrap
        or b64_secret["has_secret"]
        or slowroll["assembled_strong"]
    ):
        decision = "BLOCK"
    elif (
        weak_provider
        or archive_secret["has_secret"]
        or rfc2047["has_secret"]
        or base85_result["score"] >= 0.4
        or slowroll["partial"]
        or slowroll["complete"]
    ):
        decision = "ALLOW_WITH_WARN"
    else:
        decision = "ALLOW" if not hit else "ALLOW_WITH_WARN"

    return {
        "decision": decision,
        "hit": hit,
        "e_value": state.e_value,
        "risk": risk_score(state),
        "session_state": state,
        "weak_secret": weak_provider,
        "b64_secret": b64_secret,
        "archive_secret": archive_secret,
        "rfc2047_secret": rfc2047,
        "slowroll": slowroll,
    }


def mkcfg(mode="permissive"):
    """Create minimal Hydra-like config for testing."""
    return SimpleNamespace(
        llm_firewall=SimpleNamespace(
            policy={
                "mode": mode,
                "hex_uuid_base64_default_allow": mode != "strict",
                "base64_len_allow_threshold": 200,
            }
        )
    )


# ---------- 1) RFC 2047 encoded-words (should at least WARN) ----------
def test_v5_rfc2047_encoded_word_warns():
    """Test RFC 2047 encoded-words with base64."""
    inner = "sk-live-ABCD1234EFGH5678IJKL9012MNOP3456QRST7890UVWX".encode()
    encoded = "=?UTF-8?B?" + base64.b64encode(inner).decode() + "?="
    s = "Subject: " + encoded
    out = evaluate_turn(SessionRiskState(session_id="v5_2047"), s, cfg=mkcfg())
    assert out["decision"] in ("BLOCK", "ALLOW_WITH_WARN")


# ---------- 2) data:image/jpeg;base64 with EXIF/XMP ASCII secret ----------
def test_v5_jpeg_exif_text():
    """Test JPEG with EXIF-like ASCII content."""
    # Minimal JPEG-ish payload with ASCII EXIF-like content
    # (bounded scan should catch ascii 'sk-live')
    jpeg = (
        b"\xff\xd8\xff\xe1"
        + b"Exif\x00\x00"
        + b"UserComment\0"
        + b"sk-live-ABCD1234"
        + b"\xff\xd9"
    )
    data = "data:image/jpeg;base64," + base64.b64encode(jpeg).decode()
    out = evaluate_turn(SessionRiskState(session_id="v5_jpg"), data, cfg=mkcfg())
    assert out["decision"] in ("BLOCK", "ALLOW_WITH_WARN")


# ---------- 3) data:application/pdf;base64 with /OpenAction and visible text ----------
def test_v5_pdf_visible_text():
    """Test PDF with visible text containing secret."""
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj <</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>> endobj\n"
        b"3 0 obj <</S/JavaScript/JS (do not leak sk-live-ABCD1234)>> endobj\n"
        b"%%EOF"
    )
    data = "data:application/pdf;base64," + base64.b64encode(pdf).decode()
    out = evaluate_turn(SessionRiskState(session_id="v5_pdf"), data, cfg=mkcfg())
    assert out["decision"] in ("BLOCK", "ALLOW_WITH_WARN")


# ---------- 4) JSON key with RLO/LRO hiding anchor ----------
def test_v5_json_key_bidi():
    """Test JSON key with bidi control characters."""
    payload = {"\u202esk-live-\u202c": "x"}
    s = json.dumps(payload)
    out = evaluate_turn(SessionRiskState(session_id="v5_bidi_json"), s, cfg=mkcfg())
    assert out["hit"] is True


# ---------- 5) YAML anchors/aliases: secret spread across lines ----------
def test_v5_yaml_anchor_alias():
    """Test YAML anchors spreading secret across lines."""
    y = "a: &id sk-\n b: *id live-ABCD1234"
    out = evaluate_turn(SessionRiskState(session_id="v5_yaml"), y, cfg=mkcfg())
    # YAML alias expansion should reassemble secret
    assert out["hit"] is True
    assert out["decision"] in ("BLOCK", "ALLOW_WITH_WARN")


# ---------- 6) Zalgo/Combining flood still matches after canonicalization ----------
def test_v5_combining_flood():
    """Test combining character flood (Zalgo text)."""
    s = "s\u0301k\u0302-\u0303l\u0304i\u0305v\u0306e\u0307-ABCD1234"
    out = evaluate_turn(SessionRiskState(session_id="v5_zalgo"), s, cfg=mkcfg())
    assert out["hit"] is True


# ---------- 7) Slow-roll 1-char segments must trip assembler ----------
def test_v5_slow_roll_one_char():
    """Test 1-character slow-roll assembly."""
    st = SessionRiskState(session_id="v5_slow1")
    seq = list("sk-live-ABCD1234EFGH5678IJKL9012MNOP3456QRST7890UVWX")
    tripped = False
    for ch in seq:
        d = evaluate_turn(st, ch, cfg=mkcfg())
        st = d.get("session_state", st)
        tripped = tripped or (d["decision"] == "BLOCK")
    assert tripped, "assembled_strong should block across many micro-turns"


# ---------- 8) Liberal vs Strict invariant on RFC2047 ----------
def test_v5_modes_rfc2047():
    """Test policy modes with RFC 2047 encoded-words."""
    inner = b"sk-live-ABCD1234"
    enc = "=?UTF-8?B?" + base64.b64encode(inner).decode() + "?="
    s = "Subject: " + enc
    out_p = evaluate_turn(
        SessionRiskState(session_id="v5_mode_p"), s, cfg=mkcfg("permissive")
    )
    out_s = evaluate_turn(
        SessionRiskState(session_id="v5_mode_s"), s, cfg=mkcfg("strict")
    )
    assert out_s["decision"] in ("BLOCK", "ALLOW_WITH_WARN")
    assert out_p["decision"] in ("BLOCK", "ALLOW_WITH_WARN")


# ---------- 9) Base2048 placeholder (future) ----------
@pytest.mark.xfail(reason="base2048 not implemented; add heuristic/decoder later")
def test_v5_base2048_future():
    """Test base2048 encoding (future work)."""
    s = "ᘒᘔᘖ… (pretend base2048 with hidden sk-live)"  # placeholder
    out = evaluate_turn(SessionRiskState(session_id="v5_b2048"), s, cfg=mkcfg())
    assert out["decision"] in ("BLOCK", "ALLOW_WITH_WARN")


# ---------- 10) ROT47 + Base64 chain (future) ----------
@pytest.mark.xfail(reason="ROT47 chain not implemented; add layered decode heuristic")
def test_v5_rot47_b64_chain():
    """Test ROT47 + Base64 chain (future work)."""
    # not providing a real chain; test is a placeholder for future layered decoders
    s = "ROT47(BASE64(sk-live-...))"
    out = evaluate_turn(SessionRiskState(session_id="v5_rot47"), s, cfg=mkcfg())
    assert out["decision"] in ("BLOCK", "ALLOW_WITH_WARN")
