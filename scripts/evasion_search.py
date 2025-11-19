#!/usr/bin/env python3
"""
Evasion Search for RC10b
========================

Black-box heuristic search to find campaigns that evade RC10b detection.
Uses simulated annealing / random search to mutate campaigns.

Creator: Joerg Bollwahn
Date: 2025-11-18
License: MIT
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from copy import deepcopy
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add paths
script_path = Path(__file__).resolve()
if script_path.parent.name == "scripts":
    project_root = script_path.parent.parent
else:
    cwd = Path.cwd()
    potential_roots = [
        cwd / "standalone_packages" / "llm-security-firewall",
        cwd.parent / "standalone_packages" / "llm-security-firewall",
        script_path.parent.parent,
    ]
    project_root = None
    for root in potential_roots:
        if (root / "src" / "llm_firewall").exists():
            project_root = root
            break
    if project_root is None:
        project_root = script_path.parent.parent

src_path = project_root / "src"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(project_root))

data_path = project_root / "data"
sys.path.insert(0, str(data_path))

from campaign_dataset import CampaignScenario, load_dataset
from llm_firewall.detectors.agentic_campaign import (
    AgenticCampaignDetector,
    CampaignDetectorConfig,
)
from rc10b_validate import evaluate_campaign_rc10b


class EvasionMutator:
    """Mutates campaigns to evade detection."""
    
    def __init__(self, rng: random.Random):
        self.rng = rng
    
    def mutate_inter_event_times(
        self,
        scenario: CampaignScenario,
        factor: float = 1.5,
    ) -> CampaignScenario:
        """Increase inter-event intervals to slow down campaign."""
        
        new_scenario = deepcopy(scenario)
        if not new_scenario.events:
            return new_scenario
        
        base_time = new_scenario.events[0]["t"]
        current_time = base_time
        
        for event in new_scenario.events:
            event["t"] = current_time
            # Add jitter
            interval = self.rng.uniform(0.8, 1.2) * factor * 3600  # hours to seconds
            current_time += interval
        
        return new_scenario
    
    def mutate_add_benign_events(
        self,
        scenario: CampaignScenario,
        n_events: int = 3,
    ) -> CampaignScenario:
        """Add benign filler events."""
        
        new_scenario = deepcopy(scenario)
        if not new_scenario.events:
            return new_scenario
        
        benign_tools = ["read_file", "db_query", "log_check", "status_check"]
        targets = list(set(e.get("target", "default") for e in new_scenario.events))
        
        # Insert benign events at random positions
        for _ in range(n_events):
            insert_pos = self.rng.randint(0, len(new_scenario.events))
            base_time = new_scenario.events[0]["t"] if new_scenario.events else 0
            event_time = base_time + self.rng.uniform(0, 3600 * 24)  # Within 24h
            
            benign_event = {
                "t": event_time,
                "source": "tool",
                "tool": self.rng.choice(benign_tools),
                "category": "read",
                "target": self.rng.choice(targets) if targets else "default",
                "meta": {},
            }
            new_scenario.events.insert(insert_pos, benign_event)
        
        # Re-sort by time
        new_scenario.events.sort(key=lambda e: e["t"])
        
        return new_scenario
    
    def mutate_reduce_tool_diversity(
        self,
        scenario: CampaignScenario,
    ) -> CampaignScenario:
        """Reduce tool diversity by reusing tools."""
        
        new_scenario = deepcopy(scenario)
        if not new_scenario.events:
            return new_scenario
        
        # Find most common tool
        tool_counts: Dict[str, int] = {}
        for event in new_scenario.events:
            tool = event.get("tool", "unknown")
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        if not tool_counts:
            return new_scenario
        
        most_common_tool = max(tool_counts.items(), key=lambda x: x[1])[0]
        
        # Replace 30% of tools with most common
        replace_count = int(len(new_scenario.events) * 0.3)
        replace_indices = self.rng.sample(
            range(len(new_scenario.events)),
            min(replace_count, len(new_scenario.events))
        )
        
        for idx in replace_indices:
            new_scenario.events[idx]["tool"] = most_common_tool
        
        return new_scenario
    
    def mutate_shuffle_order(
        self,
        scenario: CampaignScenario,
    ) -> CampaignScenario:
        """Shuffle event order while maintaining time ordering."""
        
        new_scenario = deepcopy(scenario)
        if not new_scenario.events:
            return new_scenario
        
        # Group events by time windows
        time_windows: Dict[int, List[Dict]] = {}
        for event in new_scenario.events:
            window = int(event["t"] / 3600)  # 1-hour windows
            if window not in time_windows:
                time_windows[window] = []
            time_windows[window].append(event)
        
        # Shuffle within each window
        new_events = []
        for window in sorted(time_windows.keys()):
            events_in_window = time_windows[window]
            self.rng.shuffle(events_in_window)
            new_events.extend(events_in_window)
        
        new_scenario.events = new_events
        return new_scenario
    
    def mutate_scope_neutralize(
        self,
        scenario: CampaignScenario,
    ) -> CampaignScenario:
        """Neutralize scope by making targets more generic."""
        
        new_scenario = deepcopy(scenario)
        
        # Replace external domains with generic internal-looking names
        for event in new_scenario.events:
            target = event.get("target", "")
            if "." in target and not target.endswith(".local"):
                # Replace with generic internal name
                event["target"] = f"target-{self.rng.randint(1, 100)}.internal"
        
        return new_scenario


def evaluate_campaign_risk(
    detector: AgenticCampaignDetector,
    scenario: CampaignScenario,
    t_hard: float = 0.55,
) -> Tuple[float, bool]:
    """Evaluate campaign and return risk score and blocked status."""
    
    result = evaluate_campaign_rc10b(
        detector=detector,
        scenario=scenario,
        t_soft=0.35,
        t_hard=t_hard,
    )
    
    return result.risk_max, result.blocked


def evasion_search(
    initial_scenario: CampaignScenario,
    detector: AgenticCampaignDetector,
    n_iterations: int = 100,
    t_hard: float = 0.55,
    seed: int = 42,
) -> Tuple[CampaignScenario, List[Dict]]:
    """
    Perform evasion search using simulated annealing.
    
    Returns:
        Best evading scenario found, and search history
    """
    
    rng = random.Random(seed)
    mutator = EvasionMutator(rng)
    
    # Evaluate initial
    initial_risk, initial_blocked = evaluate_campaign_risk(
        detector,
        initial_scenario,
        t_hard,
    )
    
    best_scenario = initial_scenario
    best_risk = initial_risk
    best_blocked = initial_blocked
    
    history = [{
        "iteration": 0,
        "risk": initial_risk,
        "blocked": initial_blocked,
        "mutation": "initial",
    }]
    
    # Simulated annealing
    temperature = 1.0
    cooling_rate = 0.95
    
    for iteration in range(1, n_iterations + 1):
        # Select mutation
        mutations = [
            ("inter_event", lambda s: mutator.mutate_inter_event_times(s, factor=1.5)),
            ("add_benign", lambda s: mutator.mutate_add_benign_events(s, n_events=2)),
            ("reduce_tools", mutator.mutate_reduce_tool_diversity),
            ("shuffle", mutator.mutate_shuffle_order),
            ("scope_neutralize", mutator.mutate_scope_neutralize),
        ]
        
        mutation_name, mutation_func = rng.choice(mutations)
        
        # Create candidate
        candidate = mutation_func(best_scenario)
        candidate_risk, candidate_blocked = evaluate_campaign_risk(
            detector,
            candidate,
            t_hard,
        )
        
        # Acceptance criterion (simulated annealing)
        # Accept if: lower risk OR (higher risk but within temperature)
        accept = False
        if candidate_risk < best_risk:
            accept = True
        elif temperature > 0:
            delta = candidate_risk - best_risk
            prob = rng.random()
            if prob < np.exp(-delta / temperature):
                accept = True
        
        if accept:
            best_scenario = candidate
            best_risk = candidate_risk
            best_blocked = candidate_blocked
        
        history.append({
            "iteration": iteration,
            "risk": candidate_risk,
            "blocked": candidate_blocked,
            "mutation": mutation_name,
            "accepted": accept,
            "temperature": temperature,
        })
        
        # Cool down
        temperature *= cooling_rate
    
    return best_scenario, history


def main():
    parser = argparse.ArgumentParser(description="Evasion Search for RC10b")
    parser.add_argument(
        "--scenario",
        type=str,
        required=True,
        help="Path to initial scenario JSON file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/evasion_search.json",
        help="Output file for results",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Number of search iterations",
    )
    parser.add_argument(
        "--t-hard",
        type=float,
        default=0.55,
        help="Hard threshold",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed",
    )
    
    args = parser.parse_args()
    
    # Load initial scenario
    scenarios = load_dataset(args.scenario)
    if not scenarios:
        print(f"Error: No scenarios found in {args.scenario}")
        return
    
    initial_scenario = scenarios[0]  # Use first scenario
    
    # Initialize detector
    detector = AgenticCampaignDetector(
        config=CampaignDetectorConfig(
            use_phase_floor=True,
            use_scope_mismatch=True,
            use_policy_layer=True,
        )
    )
    
    # Run evasion search
    print(f"Starting evasion search on {initial_scenario.campaign_id}...")
    print(f"Initial risk: {evaluate_campaign_risk(detector, initial_scenario, args.t_hard)[0]:.3f}")
    
    evading_scenario, history = evasion_search(
        initial_scenario,
        detector,
        n_iterations=args.iterations,
        t_hard=args.t_hard,
        seed=args.seed,
    )
    
    final_risk, final_blocked = evaluate_campaign_risk(
        detector,
        evading_scenario,
        args.t_hard,
    )
    
    print(f"\nFinal risk: {final_risk:.3f}")
    print(f"Blocked: {final_blocked}")
    print(f"Risk reduction: {evaluate_campaign_risk(detector, initial_scenario, args.t_hard)[0] - final_risk:.3f}")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    results = {
        "initial_scenario": {
            "campaign_id": initial_scenario.campaign_id,
            "risk": evaluate_campaign_risk(detector, initial_scenario, args.t_hard)[0],
            "blocked": evaluate_campaign_risk(detector, initial_scenario, args.t_hard)[1],
        },
        "evading_scenario": {
            "campaign_id": evading_scenario.campaign_id,
            "risk": final_risk,
            "blocked": final_blocked,
            "events": evading_scenario.events,
        },
        "search_history": history,
    }
    
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    import numpy as np  # For np.exp in acceptance criterion
    main()

