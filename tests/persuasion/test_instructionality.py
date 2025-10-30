# -*- coding: utf-8 -*-
"""Tests for Instructionality detector"""
from llm_firewall.persuasion.instructionality import instructionality_score, requires_safety_wrap


def test_step_markers():
    """Test detection of step markers"""
    text = "Step 1: First, do this. Step 2: Then, do that. Finally, check."
    score = instructionality_score(text)
    assert score >= 3.0


def test_no_steps():
    """Test benign text without steps"""
    text = "This is a general explanation of concepts without procedures."
    score = instructionality_score(text)
    assert score < 2.0


def test_requires_safety_wrap_true():
    """Test that procedural text requires wrapping"""
    text = "Step 1: Copy and paste this command. Step 2: Execute it."
    assert requires_safety_wrap(text) is True


def test_requires_safety_wrap_false_with_guards():
    """Test that safety guards prevent wrapping"""
    text = "Step 1: I cannot help with this. Step 2: This is not safe."
    assert requires_safety_wrap(text) is False


def test_requires_safety_wrap_false_benign():
    """Test benign text doesn't require wrapping"""
    text = "Here's a general overview of the concept."
    assert requires_safety_wrap(text) is False

