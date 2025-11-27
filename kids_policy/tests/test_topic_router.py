import unittest
import os
import yaml
import tempfile
from pathlib import Path

# Add parent directory to path for imports
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from kids_policy.routing.topic_router import TopicRouter


class TestTopicRouter(unittest.TestCase):
    def setUp(self):
        # Create a temporary config for testing
        self.test_config = {
            "version": "1.0.0",
            "default_topic": "general_chat",
            "topics": {
                "religion_god": {
                    "keywords": ["god", "prayer", "divine"],
                },
                "evolution_origins": {
                    "keywords": ["evolution", "darwin", "fossils"],
                },
                "gaming_minecraft": {
                    "keywords": ["minecraft", "creeper", "block"],
                },
            },
        }
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".yaml", encoding="utf-8"
        )
        yaml.dump(self.test_config, self.temp_file)
        self.temp_file.close()

        self.router = TopicRouter(self.temp_file.name)

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_direct_match(self):
        """Test simple keyword matching"""
        res = self.router.route("I believe in God.")
        self.assertEqual(res.topic_id, "religion_god")
        self.assertTrue(res.confidence > 0)

    def test_word_boundary_safety(self):
        """
        CRITICAL: Test that 'god' does not match 'godzilla'
        This ensures we don't trigger religious logic for gaming topics.
        """
        res = self.router.route("I am fighting Godzilla in the city.")
        self.assertEqual(res.topic_id, "general_chat")

    def test_case_insensitivity(self):
        res = self.router.route("DARWIN wrote a book.")
        self.assertEqual(res.topic_id, "evolution_origins")

    def test_multi_keyword_dominance(self):
        """Test that the topic with MORE matches wins"""
        # 1 religion keyword (God), 2 evolution keywords (evolution, fossils)
        text = "God might have created evolution and fossils."
        res = self.router.route(text)
        self.assertEqual(res.topic_id, "evolution_origins")

    def test_fallback(self):
        res = self.router.route("What is for dinner?")
        self.assertEqual(res.topic_id, "general_chat")
        self.assertEqual(res.confidence, 0.0)


if __name__ == "__main__":
    unittest.main()
