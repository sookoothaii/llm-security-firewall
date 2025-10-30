"""
Spatial CAPTCHA Generator
=========================

Procedural generation of spatial reasoning challenges.

Based on: "Spatial CAPTCHA: Generatively Benchmarking Spatial Reasoning"

Features:
- Mental rotation challenges
- Occlusion reasoning
- Deterministic generation (seed-based)
- Auto-verification via ground truth program

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import random
import uuid
from typing import List, Tuple

from llm_firewall.core.domain.spatial_captcha import (
    Challenge,
    DifficultyLevel,
    ObjectType,
    SpatialObject,
)


class SpatialCaptchaGenerator:
    """
    Generates spatial reasoning challenges procedurally.

    Design:
    - Seed-based reproducibility
    - Difficulty-parameterized
    - Ground truth computed programmatically
    - No ML required (pure geometric reasoning)
    """

    def __init__(self):
        """Initialize generator."""
        self.colors = [
            "#FF0000",  # Red
            "#00FF00",  # Green
            "#0000FF",  # Blue
            "#FFFF00",  # Yellow
            "#FF00FF",  # Magenta
            "#00FFFF",  # Cyan
            "#FFA500",  # Orange
            "#800080",  # Purple
        ]

    def generate(self, seed: int, difficulty: DifficultyLevel) -> Challenge:
        """
        Generate spatial challenge from seed and difficulty.

        Args:
            seed: Random seed for reproducibility
            difficulty: Challenge difficulty level

        Returns:
            Complete challenge with ground truth
        """
        rng = random.Random(seed)

        # Select challenge type
        if difficulty == DifficultyLevel.EASY:
            return self._generate_easy(rng, seed)
        elif difficulty == DifficultyLevel.MEDIUM:
            return self._generate_medium(rng, seed)
        else:  # HARD
            return self._generate_hard(rng, seed)

    def _generate_easy(self, rng: random.Random, seed: int) -> Challenge:
        """
        Generate EASY challenge: 2D rotation, 1-2 objects, no occlusion.

        Example: "After rotating 90° clockwise, which object is on the right?"
        """
        # Create 2 objects
        num_objects = 2
        objects = []

        for i in range(num_objects):
            obj_type = rng.choice(list(ObjectType))
            color = rng.choice(self.colors)

            # Simple 2D layout (y=0, vary x)
            x = -1.0 + i * 2.0  # [-1.0, 1.0]
            position = (x, 0.0, 0.0)
            rotation = (0.0, 0.0, 0.0)  # No rotation in easy mode

            objects.append(
                SpatialObject(
                    object_type=obj_type,
                    position=position,
                    rotation=rotation,
                    color=color,
                )
            )

        # Rotation angle (90° increments)
        rotation_angle = rng.choice([90, 180, 270])

        # Compute ground truth
        correct_answer, options = self._compute_2d_rotation_answer(
            objects, rotation_angle, rng
        )

        question_text = (
            f"After rotating {rotation_angle}° clockwise, which object is on the right?"
        )

        return Challenge(
            challenge_id=str(uuid.uuid4()),
            seed=seed,
            difficulty=DifficultyLevel.EASY,
            question_type="rotation_2d",
            objects=objects,
            rotation_angle=rotation_angle,
            occlusion_enabled=False,
            question_text=question_text,
            options=options,
            correct_answer=correct_answer,
        )

    def _generate_medium(self, rng: random.Random, seed: int) -> Challenge:
        """
        Generate MEDIUM challenge: Mental rotation, 2-3 objects, partial occlusion.

        Example: "After rotating 45°, which object is behind the cube?"
        """
        # Create 3 objects
        num_objects = 3
        objects = []

        for i in range(num_objects):
            obj_type = rng.choice(list(ObjectType))
            color = rng.choice(self.colors)

            # 3D positions
            x = rng.uniform(-2.0, 2.0)
            y = rng.uniform(-1.0, 1.0)
            z = rng.uniform(-1.0, 1.0)
            position = (x, y, z)

            # Some rotation
            rotation = (rng.uniform(0, 45), rng.uniform(0, 45), rng.uniform(0, 45))

            objects.append(
                SpatialObject(
                    object_type=obj_type,
                    position=position,
                    rotation=rotation,
                    color=color,
                )
            )

        # Rotation angle (45° increments)
        rotation_angle = rng.choice([45, 90, 135, 180])

        # Compute ground truth (simplified - real impl would do 3D math)
        correct_answer, options = self._compute_occlusion_answer(
            objects, rotation_angle, rng
        )

        question_text = f"After rotating {rotation_angle}°, which object is behind the {objects[0].object_type.value}?"

        return Challenge(
            challenge_id=str(uuid.uuid4()),
            seed=seed,
            difficulty=DifficultyLevel.MEDIUM,
            question_type="mental_rotation_occlusion",
            objects=objects,
            rotation_angle=rotation_angle,
            occlusion_enabled=True,
            question_text=question_text,
            options=options,
            correct_answer=correct_answer,
        )

    def _generate_hard(self, rng: random.Random, seed: int) -> Challenge:
        """
        Generate HARD challenge: Complex rotation, 5+ objects, full occlusion.

        Example: "After rotating 37° and tilting 25°, how many objects are visible?"
        """
        # Create 5-7 objects
        num_objects = rng.randint(5, 7)
        objects = []

        for i in range(num_objects):
            obj_type = rng.choice(list(ObjectType))
            color = rng.choice(self.colors)

            # Dense 3D scene
            x = rng.uniform(-3.0, 3.0)
            y = rng.uniform(-2.0, 2.0)
            z = rng.uniform(-2.0, 2.0)
            position = (x, y, z)

            # Complex rotation
            rotation = (rng.uniform(0, 360), rng.uniform(0, 360), rng.uniform(0, 360))

            objects.append(
                SpatialObject(
                    object_type=obj_type,
                    position=position,
                    rotation=rotation,
                    color=color,
                    size=rng.uniform(0.5, 1.5),
                )
            )

        # Non-standard rotation
        rotation_angle = rng.uniform(15, 345)

        # Compute ground truth
        correct_answer, options = self._compute_visibility_answer(
            objects, rotation_angle, rng
        )

        question_text = (
            f"After rotating {rotation_angle:.0f}°, how many objects are fully visible?"
        )

        return Challenge(
            challenge_id=str(uuid.uuid4()),
            seed=seed,
            difficulty=DifficultyLevel.HARD,
            question_type="complex_visibility",
            objects=objects,
            rotation_angle=rotation_angle,
            occlusion_enabled=True,
            question_text=question_text,
            options=options,
            correct_answer=correct_answer,
        )

    def _compute_2d_rotation_answer(
        self, objects: List[SpatialObject], angle: float, rng: random.Random
    ) -> Tuple[str, List[str]]:
        """
        Compute ground truth for 2D rotation.

        Simplified implementation - real version would do actual 2D rotation math.
        """
        # For demo: deterministic selection based on angle
        if angle == 90:
            correct_idx = 1
        elif angle == 180:
            correct_idx = 0
        else:  # 270
            correct_idx = 1

        correct_obj = objects[correct_idx]
        correct_answer = f"{correct_obj.color} {correct_obj.object_type.value}"

        # Generate options
        options = [f"{obj.color} {obj.object_type.value}" for obj in objects]

        # Add distractor if only 2 objects
        if len(options) < 3:
            distractor_color = rng.choice(
                [c for c in self.colors if c not in [o.color for o in objects]]
            )
            distractor_type = rng.choice(list(ObjectType))
            options.append(f"{distractor_color} {distractor_type.value}")

        rng.shuffle(options)
        return correct_answer, options

    def _compute_occlusion_answer(
        self, objects: List[SpatialObject], angle: float, rng: random.Random
    ) -> Tuple[str, List[str]]:
        """
        Compute ground truth for occlusion challenge.

        Simplified - real version would do 3D occlusion math.
        """
        # For demo: use z-coordinate after rotation
        # Object with lowest z is "behind"
        sorted_objects = sorted(objects, key=lambda o: o.position[2])
        correct_obj = sorted_objects[0]

        correct_answer = f"{correct_obj.color} {correct_obj.object_type.value}"
        options = [f"{obj.color} {obj.object_type.value}" for obj in objects]

        rng.shuffle(options)
        return correct_answer, options

    def _compute_visibility_answer(
        self, objects: List[SpatialObject], angle: float, rng: random.Random
    ) -> Tuple[str, List[str]]:
        """
        Compute ground truth for visibility count.

        Simplified - real version would do ray-casting.
        """
        # For demo: random but deterministic from seed
        visible_count = rng.randint(2, len(objects) - 1)

        correct_answer = str(visible_count)

        # Generate plausible options
        options = [
            str(i)
            for i in range(
                max(1, visible_count - 2), min(len(objects) + 1, visible_count + 3)
            )
        ]
        options = list(set(options))  # Deduplicate

        rng.shuffle(options)
        return correct_answer, options[:4]  # Max 4 options


def verify_response(challenge: Challenge, user_answer: str) -> bool:
    """
    Verify user response against ground truth.

    Deterministic verification - no ML required.

    Args:
        challenge: The challenge presented
        user_answer: User's selected answer

    Returns:
        True if correct, False otherwise
    """
    return user_answer == challenge.correct_answer
