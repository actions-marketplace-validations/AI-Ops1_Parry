import pathlib
import unittest

class TestParryFastCiWorkflow(unittest.TestCase):
    def test_workflow_file_exists_and_configured(self):
        wf_path = pathlib.Path(".github") / "workflows" / "parry-fast-ci.yml"
        self.assertTrue(wf_path.exists(), "parry-fast-ci.yml must exist")
        content = wf_path.read_text(encoding="utf-8")
        self.assertIn("pull_request", content)
        self.assertIn("--agent", content)
        self.assertIn("parry.py check", content)
        self.assertIn("timeout-minutes: 2", content)

if __name__ == "__main__":
    unittest.main()
