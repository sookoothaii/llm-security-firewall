"""Generate synthetic training data for Layer 15 Crisis Detection.

IMPORTANT: This is SYNTHETIC data for development/testing only.
Real crisis detection requires validated datasets with IRB approval.

Output: data/crisis_detection_synthetic_v1.jsonl
"""

import json
import random
from pathlib import Path
from typing import List, Dict, Any

# Seed for reproducibility
random.seed(42)

# Self-harm patterns (EN/DE)
SELF_HARM_EN = [
    "I want to kill myself",
    "I want to die",
    "I might as well die",
    "I'm thinking about suicide",
    "I don't want to be alive anymore",
    "I'm planning to end my life",
    "Life isn't worth living",
    "I wish I was dead",
    "I've been thinking about hurting myself",
    "I can't take this pain anymore",
]

SELF_HARM_DE = [
    "Ich will mich umbringen",
    "Ich will sterben",
    "Ich denke an Suizid",
    "Ich möchte nicht mehr leben",
    "Das Leben ist nicht mehr lebenswert",
    "Ich überlege mir das Leben zu nehmen",
    "Ich halte es nicht mehr aus",
    "Ich wünschte ich wäre tot",
]

# Abuse disclosure patterns (EN/DE)
ABUSE_EN = [
    "He hit me last night",
    "She hurt me and I'm scared",
    "They touched me in ways that made me uncomfortable",
    "I'm not safe at home",
    "My dad gets violent when he drinks",
    "Someone is hurting me",
    "I was raped",
    "I'm being sexually abused",
    "My teacher touched me inappropriately",
    "I'm afraid of my stepfather",
]

ABUSE_DE = [
    "Er hat mich geschlagen",
    "Sie hat mich verletzt",
    "Ich bin zu Hause nicht sicher",
    "Jemand tut mir weh",
    "Ich wurde vergewaltigt",
    "Ich werde sexuell missbraucht",
    "Mein Vater wird gewalttätig",
    "Ich habe Angst vor meinem Stiefvater",
]

# Unsafe environment patterns (EN/DE)
UNSAFE_ENV_EN = [
    "There's no food in the house and I'm hungry",
    "My parents left me alone for days",
    "I have nowhere safe to sleep tonight",
    "I'm being neglected at home",
    "Nobody takes care of me",
    "I'm homeless and scared",
    "My family doesn't feed me properly",
    "I live in a dangerous situation",
]

UNSAFE_ENV_DE = [
    "Es gibt kein Essen zu Hause und ich habe Hunger",
    "Meine Eltern haben mich tagelang allein gelassen",
    "Ich habe keinen sicheren Schlafplatz",
    "Niemand kümmert sich um mich",
    "Ich lebe in einer gefährlichen Situation",
    "Ich bin obdachlos und habe Angst",
]

# Benign patterns (negative samples - EN/DE)
BENIGN_EN = [
    "How do I solve this math problem?",
    "Can you help me with my homework?",
    "What's the capital of France?",
    "I'm excited about my birthday party",
    "Tell me a joke",
    "How does photosynthesis work?",
    "I'm learning to play guitar",
    "What's your favorite color?",
    "Can you recommend a book?",
    "I'm happy today",
    "How do I bake a cake?",
    "What time is it?",
    "I love playing with my dog",
    "Can you explain gravity?",
    "I'm working on a school project",
]

BENIGN_DE = [
    "Wie löse ich diese Matheaufgabe?",
    "Kannst du mir bei den Hausaufgaben helfen?",
    "Was ist die Hauptstadt von Frankreich?",
    "Ich freue mich auf meine Geburtstagsfeier",
    "Erzähl mir einen Witz",
    "Wie funktioniert Photosynthese?",
    "Ich lerne Gitarre spielen",
    "Was ist deine Lieblingsfarbe?",
    "Ich bin heute glücklich",
    "Wie backt man einen Kuchen?",
    "Ich liebe es mit meinem Hund zu spielen",
    "Kannst du Schwerkraft erklären?",
]


def generate_samples() -> List[Dict[str, Any]]:
    """Generate synthetic training samples."""
    samples = []
    
    # Self-harm samples (EN)
    for text in SELF_HARM_EN:
        samples.append({
            "text": text,
            "labels": {"self_harm": 1.0, "abuse": 0.0, "unsafe_env": 0.0},
            "language": "en",
            "split": "train"
        })
    
    # Self-harm samples (DE)
    for text in SELF_HARM_DE:
        samples.append({
            "text": text,
            "labels": {"self_harm": 1.0, "abuse": 0.0, "unsafe_env": 0.0},
            "language": "de",
            "split": "train"
        })
    
    # Abuse samples (EN)
    for text in ABUSE_EN:
        samples.append({
            "text": text,
            "labels": {"self_harm": 0.0, "abuse": 1.0, "unsafe_env": 0.0},
            "language": "en",
            "split": "train"
        })
    
    # Abuse samples (DE)
    for text in ABUSE_DE:
        samples.append({
            "text": text,
            "labels": {"self_harm": 0.0, "abuse": 1.0, "unsafe_env": 0.0},
            "language": "de",
            "split": "train"
        })
    
    # Unsafe env samples (EN)
    for text in UNSAFE_ENV_EN:
        samples.append({
            "text": text,
            "labels": {"self_harm": 0.0, "abuse": 0.0, "unsafe_env": 1.0},
            "language": "en",
            "split": "train"
        })
    
    # Unsafe env samples (DE)
    for text in UNSAFE_ENV_DE:
        samples.append({
            "text": text,
            "labels": {"self_harm": 0.0, "abuse": 0.0, "unsafe_env": 1.0},
            "language": "de",
            "split": "train"
        })
    
    # Benign samples (EN)
    for text in BENIGN_EN:
        samples.append({
            "text": text,
            "labels": {"self_harm": 0.0, "abuse": 0.0, "unsafe_env": 0.0},
            "language": "en",
            "split": "train"
        })
    
    # Benign samples (DE)
    for text in BENIGN_DE:
        samples.append({
            "text": text,
            "labels": {"self_harm": 0.0, "abuse": 0.0, "unsafe_env": 0.0},
            "language": "de",
            "split": "train"
        })
    
    # Shuffle
    random.shuffle(samples)
    
    # Split train/val (80/20)
    n_val = len(samples) // 5
    for i in range(n_val):
        samples[i]["split"] = "val"
    
    return samples


def main():
    """Generate and save training data."""
    print("[INFO] Generating synthetic crisis detection training data...")
    
    samples = generate_samples()
    
    # Stats
    n_train = sum(1 for s in samples if s["split"] == "train")
    n_val = sum(1 for s in samples if s["split"] == "val")
    n_self_harm = sum(1 for s in samples if s["labels"]["self_harm"] > 0)
    n_abuse = sum(1 for s in samples if s["labels"]["abuse"] > 0)
    n_unsafe = sum(1 for s in samples if s["labels"]["unsafe_env"] > 0)
    n_benign = sum(1 for s in samples if all(v == 0 for v in s["labels"].values()))
    
    print(f"[INFO] Total samples: {len(samples)}")
    print(f"[INFO] Train: {n_train}, Val: {n_val}")
    print(f"[INFO] Self-harm: {n_self_harm}, Abuse: {n_abuse}, Unsafe: {n_unsafe}, Benign: {n_benign}")
    
    # Save
    output_path = Path("data/crisis_detection_synthetic_v1.jsonl")
    output_path.parent.mkdir(exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
    
    print(f"[OK] Saved to {output_path}")
    print("[WARNING] This is SYNTHETIC data for development only!")
    print("[WARNING] Real crisis detection requires validated datasets with IRB approval!")


if __name__ == "__main__":
    main()

