# -*- coding: utf-8 -*-
"""Tests for Aho-Corasick Trie"""

import pathlib

from llm_firewall.persuasion.ac_trie import build_from_lexicons

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEX = ROOT / "src/llm_firewall/lexicons/persuasion"


def test_ac_counts():
    """Test that AC-Trie counts keywords correctly"""
    ac = build_from_lexicons(LEX)
    text = "As a professor I expect reciprocity and official policy compliance."
    counts = ac.search_categories(text)
    assert counts.get("authority", 0) >= 1
    assert counts.get("reciprocity", 0) >= 1


def test_ac_case_insensitive():
    """Test case-insensitive matching"""
    ac = build_from_lexicons(LEX)
    text = "PROFESSOR and OFFICIAL directive"
    counts = ac.search_categories(text)
    assert counts.get("authority", 0) >= 2


def test_ac_no_false_positives():
    """Test benign text gets low counts"""
    ac = build_from_lexicons(LEX)
    text = "Please explain the general concept."
    counts = ac.search_categories(text)
    assert sum(counts.values()) == 0

