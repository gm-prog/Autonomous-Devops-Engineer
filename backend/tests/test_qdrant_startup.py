"""Qdrant startup must be non-destructive (§13).

collection exists    -> preserve (never recreate)
collection missing   -> create once
"""

import asyncio
import unittest
from unittest.mock import MagicMock

from app import main as main_module


def _drive_lifespan():
    async def _run():
        async with main_module.lifespan(None):
            pass

    asyncio.run(_run())


class QdrantStartupSafetyTests(unittest.TestCase):
    def setUp(self):
        self._real_qdrant = main_module.qdrant
        self.addCleanup(setattr, main_module, "qdrant", self._real_qdrant)

    def test_existing_collection_is_preserved(self):
        fake = MagicMock()
        fake.collection_exists.return_value = True
        main_module.qdrant = fake

        _drive_lifespan()

        fake.collection_exists.assert_called_once()
        fake.create_collection.assert_not_called()

    def test_missing_collection_is_created_once(self):
        fake = MagicMock()
        fake.collection_exists.return_value = False
        main_module.qdrant = fake

        _drive_lifespan()

        fake.collection_exists.assert_called_once()
        fake.create_collection.assert_called_once()


if __name__ == "__main__":
    unittest.main()
