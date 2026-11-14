import unittest
from unittest.mock import patch, MagicMock
import pathlib
import sys
import tempfile
import io

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import parry


class TestWeb3AndWebhookFeatures(unittest.TestCase):
    def test_webhook_url_ssrf_validation(self):
        # Disallowed: HTTP
        self.assertFalse(parry.validate_webhook_url("http://hooks.slack.com/services/xxx"))
        # Disallowed: localhost & loopback
        self.assertFalse(parry.validate_webhook_url("https://localhost/webhook"))
        self.assertFalse(parry.validate_webhook_url("https://127.0.0.1:8000/webhook"))
        self.assertFalse(parry.validate_webhook_url("https://0.0.0.0/webhook"))
        # Disallowed: RFC1918 Private Ranges
        self.assertFalse(parry.validate_webhook_url("https://10.0.1.5/webhook"))
        self.assertFalse(parry.validate_webhook_url("https://192.168.1.1/webhook"))
        self.assertFalse(parry.validate_webhook_url("https://172.16.0.1/webhook"))
        # Disallowed: AWS/GCP cloud metadata service
        self.assertFalse(parry.validate_webhook_url("https://169.254.169.254/latest/meta-data"))
        self.assertFalse(parry.validate_webhook_url("https://metadata.google.internal/computeMetadata/v1/"))
        # Disallowed: Malformed
        self.assertFalse(parry.validate_webhook_url(""))
        self.assertFalse(parry.validate_webhook_url("not-a-url"))

        # Allowed: Valid HTTPS webhooks
        self.assertTrue(parry.validate_webhook_url("https://webhook.example.com/services/slack-notifications"))
        self.assertTrue(parry.validate_webhook_url("https://webhook.example.com/api/webhooks/discord-alerts"))

    def test_send_team_webhook_alert_blocks_ssrf(self):
        findings = [
            parry.Finding(
                rule_id="PARRY-WEB3-RS001",
                category="security",
                severity="error",
                language="rust",
                file_path="src/lib.rs",
                line=42,
                column=1,
                enclosing_symbol="process_instruction",
                fingerprint="fp123",
                message="Anchor missing signer validation check",
                suggestion="Add Signer<'info> constraint",
            )
        ]
        # Should return False immediately without network attempt when SSRF detected
        result = parry.send_team_webhook_alert("https://127.0.0.1:9090/alert", "protocol-vault", findings)
        self.assertFalse(result)

    @patch("urllib.request.urlopen")
    def test_send_team_webhook_alert_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        findings = [
            parry.Finding(
                rule_id="PARRY-WEB3-RS001",
                category="security",
                severity="error",
                language="rust",
                file_path="src/lib.rs",
                line=42,
                column=1,
                enclosing_symbol="process_instruction",
                fingerprint="fp123",
                message="Anchor missing signer validation check",
                suggestion="Add Signer<'info> constraint",
            )
        ]
        result = parry.send_team_webhook_alert(
            "https://webhook.example.com/services/team-alerts",
            "protocol-vault",
            findings,
            pr_ref="refs/pull/42/merge",
        )
        self.assertTrue(result)
        mock_urlopen.assert_called_once()

    def test_format_web3_audit_deliverable(self):
        findings = [
            parry.Finding(
                rule_id="PARRY-WEB3-RS001",
                category="security",
                severity="error",
                language="rust",
                file_path="programs/vault/src/lib.rs",
                line=35,
                column=1,
                enclosing_symbol="deposit",
                fingerprint="fp123",
                message="Anchor missing signer validation on vault authority",
                suggestion="Add Signer<'info> account constraint",
                prompt_injection_patch="Enforce signer validation constraint on authority account",
            ),
            parry.Finding(
                rule_id="PARRY-SEC-SOL001",
                category="security",
                severity="error",
                language="solidity",
                file_path="contracts/Pool.sol",
                line=88,
                column=1,
                enclosing_symbol="withdraw",
                fingerprint="fp456",
                message="State update after external call risks reentrancy",
                suggestion="Apply Checks-Effects-Interactions ordering",
            )
        ]

        report = parry.format_web3_audit_deliverable(findings, "solana-liquidity-pool", 12)
        self.assertIn("# Web3 Protocol AI Safety Audit Deliverable", report)
        self.assertIn("solana-liquidity-pool", report)
        self.assertIn("Protocol Safety Score", report)
        self.assertIn("Solana Anchor Privileges & CPI", report)
        self.assertIn("EVM Reentrancy & Access Control", report)
        self.assertIn("PARRY-WEB3-RS001", report)
        self.assertIn("PARRY-SEC-SOL001", report)
        self.assertIn("https://parry.scopeledger.net/web3", report)
        self.assertIn("img.shields.io/badge/Parry%20AI%20Safety", report)

    def test_cli_web3_audit_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = pathlib.Path(tmpdir) / "token.sol"
            test_file.write_text(
                "pragma solidity ^0.8.0;\ncontract Token {\n    function transfer(address to) public {\n        // ... existing code ...\n    }\n}\n",
                encoding="utf-8"
            )

            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                exit_code = parry.main(["check", str(test_file), "--web3-audit"])

            output = stdout_buf.getvalue()
            self.assertIn("# Web3 Protocol AI Safety Audit Deliverable", output)
            self.assertIn("Protocol Safety Score", output)
            self.assertIn("PARRY-ANT-000", output)


if __name__ == "__main__":
    unittest.main()
