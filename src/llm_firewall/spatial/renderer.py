"""
Spatial CAPTCHA PNG Renderer
=============================

Renders spatial challenges to PNG images for presentation.

Integrates with OCR Optical Memory pipeline.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

from pathlib import Path
from typing import Any, Optional

from llm_firewall.core.domain.spatial_captcha import Challenge


class SpatialCaptchaRenderer:
    """
    Renders spatial challenges to PNG images.

    Uses:
    - PIL for 2D projection
    - Matplotlib for 3D visualization (optional)

    Graceful degradation: If PIL unavailable, returns None.
    """

    def __init__(
        self,
        output_dir: str = "spatial_challenges",
        image_size: tuple[int, int] = (800, 600),
    ):
        """
        Initialize renderer.

        Args:
            output_dir: Directory to save rendered PNGs
            image_size: Image dimensions (width, height)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.image_size = image_size

        # Check dependencies
        self._has_pil = self._check_pil()
        self._has_matplotlib = self._check_matplotlib()

    def _check_pil(self) -> bool:
        """Check if PIL/Pillow is available."""
        import importlib.util

        return importlib.util.find_spec("PIL") is not None

    def _check_matplotlib(self) -> bool:
        """Check if matplotlib is available."""
        import importlib.util

        return importlib.util.find_spec("matplotlib") is not None

    def is_available(self) -> bool:
        """Check if renderer can function."""
        return self._has_pil  # Minimum requirement

    def render(self, challenge: Challenge) -> Optional[str]:
        """
        Render challenge to PNG.

        Args:
            challenge: Challenge to render

        Returns:
            Path to rendered PNG, or None if rendering failed
        """
        if not self.is_available():
            return None

        # Use matplotlib for 3D if available, otherwise PIL for 2D
        if self._has_matplotlib and challenge.difficulty.value != "easy":
            return self._render_3d_matplotlib(challenge)
        else:
            return self._render_2d_pil(challenge)

    def _render_2d_pil(self, challenge: Challenge) -> str:
        """
        Render challenge using PIL (2D projection).

        Simple top-down view for EASY challenges.
        """
        from PIL import Image, ImageDraw, ImageFont

        # Create blank image
        img = Image.new("RGB", self.image_size, color="white")
        draw = ImageDraw.Draw(img)

        # Draw title
        title = challenge.question_text
        try:
            font: Any = ImageFont.truetype("arial.ttf", 20)
        except (OSError, IOError):
            font = ImageFont.load_default()

        draw.text((20, 20), title, fill="black", font=font)

        # Draw objects (top-down view)
        cx, cy = self.image_size[0] // 2, self.image_size[1] // 2
        scale = 100

        for obj in challenge.objects:
            x = cx + int(obj.position[0] * scale)
            y = cy + int(obj.position[1] * scale)
            r = int(20 * obj.size)

            # Draw shape based on type
            if obj.object_type.value in ["cube", "pyramid"]:
                # Rectangle
                draw.rectangle(
                    [x - r, y - r, x + r, y + r],
                    fill=obj.color,
                    outline="black",
                    width=2,
                )
            else:
                # Circle
                draw.ellipse(
                    [x - r, y - r, x + r, y + r],
                    fill=obj.color,
                    outline="black",
                    width=2,
                )

            # Label
            draw.text((x - r, y + r + 5), obj.object_type.value, fill="black")

        # Draw options
        options_y = self.image_size[1] - 150
        draw.text((20, options_y), "Options:", fill="black", font=font)
        for i, opt in enumerate(challenge.options):
            draw.text(
                (20, options_y + 30 + i * 30), f"{chr(65 + i)}. {opt}", fill="black"
            )

        # Save
        filename = f"{challenge.challenge_id}.png"
        filepath = self.output_dir / filename
        img.save(filepath)

        return str(filepath)

    def _render_3d_matplotlib(self, challenge: Challenge) -> str:
        """
        Render challenge using matplotlib (3D visualization).

        Used for MEDIUM and HARD challenges.
        """
        import matplotlib.pyplot as plt
        import numpy as np

        fig = plt.figure(figsize=(10, 8))
        ax = fig.add_subplot(111, projection="3d")

        # Draw objects
        for obj in challenge.objects:
            x, y, z = obj.position

            # Simple representation (sphere/cube approximation)
            if obj.object_type.value in ["sphere", "cylinder", "torus"]:
                # Draw as sphere
                u = np.linspace(0, 2 * np.pi, 20)
                v = np.linspace(0, np.pi, 20)
                r = obj.size * 0.3
                xs = x + r * np.outer(np.cos(u), np.sin(v))
                ys = y + r * np.outer(np.sin(u), np.sin(v))
                zs = z + r * np.outer(np.ones(np.size(u)), np.cos(v))
                ax.plot_surface(xs, ys, zs, color=obj.color, alpha=0.7)
            else:
                # Draw as point with label (simplified)
                ax.scatter([x], [y], [z], c=[obj.color], s=200, marker="o")

            # Label
            ax.text(x, y, z, obj.object_type.value, fontsize=8)

        # Set labels and title
        ax.set_xlabel("X")
        ax.set_ylabel("Y")
        ax.set_zlabel("Z")
        ax.set_title(challenge.question_text, fontsize=12, wrap=True)

        # Add options as text
        options_text = "Options:\n" + "\n".join(
            [f"{chr(65 + i)}. {opt}" for i, opt in enumerate(challenge.options)]
        )
        fig.text(0.02, 0.02, options_text, fontsize=10, verticalalignment="bottom")

        # Apply rotation view angle
        ax.view_init(elev=30, azim=challenge.rotation_angle)

        # Save
        filename = f"{challenge.challenge_id}.png"
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=100, bbox_inches="tight")
        plt.close()

        return str(filepath)

    def cleanup_old_challenges(self, max_age_hours: int = 24):
        """
        Remove old challenge PNGs.

        Args:
            max_age_hours: Max age before deletion
        """
        import time

        cutoff_time = time.time() - (max_age_hours * 3600)

        for filepath in self.output_dir.glob("*.png"):
            if filepath.stat().st_mtime < cutoff_time:
                filepath.unlink()
