import pathlib
import tempfile
import unittest
from parry import scan_source
from ide_hooks import install_git_pre_push_hook

class TestOneWayDoors(unittest.TestCase):
    def test_detect_force_push_in_script(self):
        code = "git push --force origin main"
        findings = scan_source(code, "deploy.sh", "shell")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-GATE-ONEWAY", rule_ids)
        finding = next(f for f in findings if f.rule_id == "PARRY-GATE-ONEWAY")
        self.assertEqual(finding.severity, "error")
        self.assertIn("One-Way Door", finding.message)

    def test_detect_destructive_sql_drop(self):
        code = "DROP TABLE users CASCADE;"
        findings = scan_source(code, "cleanup.sql", "sql")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-GATE-ONEWAY", rule_ids)

    def test_detect_force_push_in_python_subprocess(self):
        code = "subprocess.run(['git', 'push', '-f', 'origin', 'main'])"
        findings = scan_source(code, "deploy.py", "python")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-GATE-ONEWAY", rule_ids)

    def test_safe_push_and_safe_query_pass(self):
        code = "git push origin feat/new-login"
        findings = scan_source(code, "deploy.sh", "shell")
        rule_ids = [f.rule_id for f in findings]
        self.assertNotIn("PARRY-GATE-ONEWAY", rule_ids)

    def test_install_git_pre_push_hook(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = pathlib.Path(tmpdir) / ".git" / "hooks"
            git_dir.mkdir(parents=True)
            action = install_git_pre_push_hook(tmpdir)
            hook_file = git_dir / "pre-push"
            self.assertTrue(hook_file.exists())
            content = hook_file.read_text(encoding="utf-8")
            self.assertIn("parry.py", content)
            self.assertEqual(action.status, "create")

if __name__ == "__main__":
    unittest.main()
