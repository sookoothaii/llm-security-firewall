import re
import yaml
import os
from typing import Dict, List
from dataclasses import dataclass


@dataclass
class RouteResult:
    topic_id: str
    confidence: float
    matched_keywords: List[str]


class TopicRouter:
    """
    Topic Router v1.0 (Regex/Keyword Based)
    Maps user input to canonical topic IDs for TAG-2 validation.
    """

    def __init__(self, config_path: str):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Topic map not found at {config_path}")

        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        self.default_topic = self.config.get("default_topic", "general_chat")
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """
        Compiles optimized regex patterns for each topic.
        Uses word boundaries (\b) to avoid partial matches (e.g. 'god' in 'godzilla').
        """
        patterns = {}
        for topic, data in self.config["topics"].items():
            keywords = data.get("keywords", [])
            if not keywords:
                continue

            # Escape keywords and join with OR (|)
            # Result: \b(keyword1|keyword2|keyword3)\b
            escaped = [re.escape(k) for k in keywords]
            pattern_str = r"\b(" + "|".join(escaped) + r")\b"

            # Compile with IGNORECASE
            patterns[topic] = re.compile(pattern_str, re.IGNORECASE)

        return patterns

    def route(self, text: str) -> RouteResult:
        """
        Determines the most likely topic based on keyword density.
        """
        best_topic = self.default_topic
        max_hits = 0
        all_matches = []

        # Iterate over all topic patterns
        for topic, pattern in self.patterns.items():
            matches = pattern.findall(text)
            hit_count = len(matches)

            if hit_count > 0:
                all_matches.extend(matches)
                # Simple Heuristic: Topic with most keyword hits wins
                # Future: Add weights per keyword in YAML
                if hit_count > max_hits:
                    max_hits = hit_count
                    best_topic = topic

        # Confidence calculation (simple linear scaling)
        confidence = min(1.0, max_hits * 0.5) if max_hits > 0 else 0.0

        return RouteResult(
            topic_id=best_topic, confidence=confidence, matched_keywords=all_matches
        )
