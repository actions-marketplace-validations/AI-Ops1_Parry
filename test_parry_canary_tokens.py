import unittest
from parry import is_canary_token, scan_source

class TestCanaryTokens(unittest.TestCase):
    def test_identify_canary_aws_key(self):
        canary = "AKIACANARY0123456789"
        self.assertTrue(is_canary_token(canary))

    def test_identify_canary_domain_webhook(self):
        canary_url = "http://canarytokens.com/traffic/tags/sample/contact.php"
        self.assertTrue(is_canary_token(canary_url))

    def test_canary_tagged_separately_from_real_leak(self):
        code = 'AWS_KEY = "AKIACANARY0123456789"  # canary-token'
        findings = scan_source(code, "config.py", "python")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-CANARY", rule_ids)
        self.assertNotIn("PARRY-SEC-PY005", rule_ids)

    def test_real_aws_key_still_flagged_as_real_leak(self):
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = scan_source(code, "config.py", "python")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-PY005", rule_ids)
        self.assertNotIn("PARRY-SEC-CANARY", rule_ids)

if __name__ == "__main__":
    unittest.main()
