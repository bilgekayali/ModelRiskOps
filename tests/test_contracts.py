import json
from pathlib import Path
import unittest

import modelriskops

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(modelriskops.__version__, "0.1.0")

    def test_schema_is_strict_and_version_pinned(self):
        schema = json.loads((ROOT / "schemas/model-record.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["properties"]["schema_version"]["const"], "modelriskops.model-record.v1")
        self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
