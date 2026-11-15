import io
import unittest
from unittest.mock import patch
from parry import format_agent_feedback, Finding, main

class TestParryAgentMode(unittest.TestCase):
    def test_format_agent_feedback(self):
        finding = Finding(
            rule_id="PARRY-HAL-JS001",
            category="hallucination",
            severity="error",
            language="javascript",
            file_path="src/index.js",
            line=12,
            column=5,
            enclosing_symbol="getData",
            fingerprint="abc1234",
            message="Deprecated substr() used",
            suggestion="Use .slice()",
            prompt_injection_patch="Replace .substr() with .slice()"
        )
        output = format_agent_feedback([finding])
        self.assertIn("PARRY_AGENT_REPAIR", output)
        self.assertIn("src/index.js:12:5", output)
        self.assertIn("PARRY-HAL-JS001", output)
        self.assertIn("Replace .substr() with .slice()", output)

    def test_format_agent_feedback_empty_when_clean(self):
        output = format_agent_feedback([])
        self.assertEqual(output.strip(), "[OK] PARRY_AGENT_CLEAN: 0 issues detected.")

    @patch("sys.argv", ["parry.py", "check", "test_parry_agent_mode.py", "--agent"])
    def test_cli_agent_flag_accepted(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            try:
                code = main()
            except SystemExit as exc:
                code = exc.code
        self.assertIn(code, (0, 1))

if __name__ == "__main__":
    unittest.main()
