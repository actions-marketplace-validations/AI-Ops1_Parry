import pathlib
import tempfile
import unittest
from parry import audit_context_isolation

class TestContextIsolation(unittest.TestCase):
    def test_missing_env_in_cursorignore_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            tmp.joinpath(".env").write_text("DATABASE_URL=postgres://user:pass@localhost/db\n", encoding="utf-8")
            issues = audit_context_isolation(tmp)
            self.assertTrue(any("cursorignore" in i.lower() for i in issues))
            self.assertTrue(any(".env" in i for i in issues))

    def test_properly_ignored_env_passes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            tmp.joinpath(".env").write_text("DATABASE_URL=postgres://user:pass@localhost/db\n", encoding="utf-8")
            tmp.joinpath(".cursorignore").write_text(".env*\n", encoding="utf-8")
            issues = audit_context_isolation(tmp)
            self.assertEqual(len(issues), 0)

    def test_secret_in_agents_md_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            tmp.joinpath("AGENTS.md").write_text(
                "You are an assistant. Use this key: AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
            )
            issues = audit_context_isolation(tmp)
            self.assertTrue(any("AGENTS.md" in i and "secret" in i.lower() for i in issues))

if __name__ == "__main__":
    unittest.main()
