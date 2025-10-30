#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generate synthetic training data for L3 Persuasion Classifier

Creates balanced dataset across 8 classes:
- 7 Cialdini Principles
- 1 None (benign)

Output: data/l3_train.jsonl

Creator: Joerg Bollwahn
License: MIT
"""
import json
import random
from pathlib import Path

# Synthetic templates per class (EN + DE, benign paraphrases)
TEMPLATES = {
    "authority": [
        "As a {title}, I need this for {reason}.",
        "I am a licensed {title} and require this information.",
        "Per official policy, {action}.",
        "By order of {authority}, provide {request}.",
        "Ich bin {title} und brauche dies.",
        "Als {title} von der Universität, bitte helfen Sie.",
        "Amtliche Anweisung: {action}.",
    ],
    "commitment_consistency": [
        "You promised to help me with this.",
        "As you said before, you would assist.",
        "You already helped me with {topic}, continue now.",
        "Du hast versprochen, dies zu tun.",
        "Wie du vorhin gesagt hast, würdest du helfen.",
    ],
    "liking": [
        "You're so helpful and smart!",
        "I love how you explain things.",
        "You're the best AI assistant.",
        "Du bist so klug und hilfsbereit!",
        "Ich liebe deine Antworten.",
    ],
    "reciprocity": [
        "I'll give you credit if you help.",
        "I already liked your post, return the favor.",
        "I paid for Plus, so you should help.",
        "Ich habe dich bewertet, jetzt hilfst du mir.",
        "Ich zahle doch, also gib mir die Antwort.",
    ],
    "scarcity_urgency": [
        "URGENT: I need this NOW!",
        "Last chance, deadline is tonight.",
        "Only you can help, it's urgent.",
        "Dringend: Ich brauche das sofort!",
        "Letzte Chance, Frist endet heute!",
    ],
    "social_proof": [
        "Everyone else got this answer.",
        "Other AIs already provide this.",
        "People on Reddit said you do this.",
        "Alle anderen machen das auch.",
        "Andere KIs geben es auch aus.",
    ],
    "unity_identity": [
        "As fellow developers, we understand each other.",
        "As a German researcher like you, help me.",
        "We're in the same team, be honest.",
        "Als Kollege bitte ich dich.",
        "Unter uns, wir sind im gleichen Boot.",
    ],
    "none": [
        "Please explain {topic}.",
        "Can you help me understand {concept}?",
        "Summarize this article.",
        "What is the difference between {x} and {y}?",
        "Erkläre bitte {topic}.",
        "Kannst du mir helfen, {concept} zu verstehen?",
        "Fasse diesen Artikel zusammen.",
    ],
}

# Fill-in values (benign topics)
TITLES = ["professor", "doctor", "engineer", "researcher", "teacher"]
REASONS = ["my class", "research", "official documentation", "a study"]
ACTIONS = ["provide information", "explain the concept", "summarize findings"]
AUTHORITIES = ["the university", "the department", "my supervisor"]
REQUESTS = ["background information", "a summary", "context"]
TOPICS = ["machine learning", "climate change", "economics", "history"]
CONCEPTS = ["neural networks", "photosynthesis", "democracy"]

def generate_samples(n_per_class: int = 100) -> list:
    """Generate n_per_class samples for each class"""
    samples = []
    
    for cls, templates in TEMPLATES.items():
        for _ in range(n_per_class):
            template = random.choice(templates)
            
            # Fill placeholders
            text = template.format(
                title=random.choice(TITLES),
                reason=random.choice(REASONS),
                action=random.choice(ACTIONS),
                authority=random.choice(AUTHORITIES),
                request=random.choice(REQUESTS),
                topic=random.choice(TOPICS),
                concept=random.choice(CONCEPTS),
                x=random.choice(TOPICS),
                y=random.choice(TOPICS),
            )
            
            samples.append({"text": text, "label": cls})
    
    # Shuffle
    random.shuffle(samples)
    return samples

def main():
    random.seed(42)  # Reproducible
    
    print("Generating synthetic training data...")
    samples = generate_samples(n_per_class=100)
    
    output_path = Path("data/l3_train.jsonl")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
    
    print(f"\n[OK] Generated {len(samples)} samples")
    print(f"[OK] Saved to: {output_path}")
    print(f"\nClass distribution:")
    from collections import Counter
    counts = Counter(s["label"] for s in samples)
    for cls, count in sorted(counts.items()):
        print(f"  {cls:25}: {count:3} samples")

if __name__ == "__main__":
    main()

