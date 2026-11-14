#!/usr/bin/env python3
"""
Unit tests for GitHub Action, PR Shield Markdown formatting, SARIF, exclusions, and sticky PR comments.
"""

import io
import json
import pathlib
import tempfile
import unittest
import urllib.error
from unittest import mock

import parry
import pr_shield_action


class _FakeHttpResponse:
    def __init__(self, payload: object) -> None:
        self._data = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


class TestParryActionAndPrShield(unittest.TestCase):
    def test_pr_comment_markdown_clean_and_sanitized_findings(self) -> None:
        clean_md = parry.format_pr_comment_markdown([], scanned_count=4, elapsed_ms=1.25)
        self.assertIn(parry.PR_SHIELD_MARKER, clean_md)
        self.assertIn("Clean AST Diff", clean_md)
        self.assertIn("4", clean_md)

        malicious_finding = parry.Finding(
            rule_id="PARRY-HAL-TS002",
            category="hallucination",
            severity="error",
            language="typescript",
            file_path="src/<script>bad|file.ts",
            line=12,
            column=3,
            enclosing_symbol="init",
            fingerprint="abcdef1234567890",
            message="Deprecated <img onerror=alert(1)> Buffer()",
            suggestion="Use `Buffer.alloc(32)` | safe",
            prompt_injection_patch="Replace `new Buffer(32)` with `Buffer.alloc(32)`",
        )
        dirty_md = parry.format_pr_comment_markdown([malicious_finding], scanned_count=1, elapsed_ms=2.4)
        self.assertIn(parry.PR_SHIELD_MARKER, dirty_md)
        self.assertIn("Deflected 1 Issue(s)", dirty_md)
        self.assertNotIn("<script>", dirty_md)
        self.assertNotIn("<img", dirty_md)
        self.assertIn("&lt;script&gt;", dirty_md)
        self.assertIn("\\|", dirty_md)

    def test_sarif_output_and_fail_on_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            ignored = root / "node_modules" / "pkg.ts"
            ignored.parent.mkdir(parents=True)
            ignored.write_text("const a = new Buffer(8);\n", encoding="utf-8")

            warn_file = root / "sort.ts"
            warn_file.write_text("const s = [10, 2].sort();\n", encoding="utf-8")
            sarif_out = root / "out" / "results.sarif"

            # --fail-on error should exit 0 when only warning exists, while still writing SARIF
            code_err_only = parry.main(
                [
                    "check",
                    str(root),
                    "--format",
                    "sarif",
                    "--output",
                    str(sarif_out),
                    "--fail-on",
                    "error",
                ]
            )
            self.assertEqual(code_err_only, 0)
            self.assertTrue(sarif_out.is_file())
            sarif = json.loads(sarif_out.read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "PARRY-LOG-TS001")

            # --fail-on warning should exit 1
            code_warn = parry.main(["check", str(root), "--format", "json", "--fail-on", "warning"])
            self.assertEqual(code_warn, 1)

            # --exclude removes sort.ts so exit is 0
            code_excl = parry.main(["check", str(root), "--exclude", "sort.ts"])
            self.assertEqual(code_excl, 0)

    def test_diff_base_rejects_flag_injection(self) -> None:
        with self.assertRaises(ValueError):
            parry.get_changed_files_from_git("--exec=whoami")

    def test_sticky_pr_comment_creates_updates_and_handles_readonly_fork(self) -> None:
        calls = []

        def fake_create_opener(req: object, timeout: int = 15) -> _FakeHttpResponse:
            calls.append((req.get_method(), req.full_url, req.data))
            if req.get_method() == "GET":
                return _FakeHttpResponse([])
            return _FakeHttpResponse({"id": 99})

        status = pr_shield_action.post_or_update_pr_comment(
            "AI-Ops1/Parry", 42, "tok", f"{parry.PR_SHIELD_MARKER}\nhello", opener=fake_create_opener
        )
        self.assertEqual(status, "created")
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[1][0], "POST")

        # Update existing sticky comment instead of duplicating
        patch_calls = []

        def fake_update_opener(req: object, timeout: int = 15) -> _FakeHttpResponse:
            patch_calls.append((req.get_method(), req.full_url))
            if req.get_method() == "GET":
                return _FakeHttpResponse([{"id": 777, "body": f"{parry.PR_SHIELD_MARKER}\nold"}])
            return _FakeHttpResponse({"id": 777})

        status_upd = pr_shield_action.post_or_update_pr_comment(
            "AI-Ops1/Parry", 42, "tok", f"{parry.PR_SHIELD_MARKER}\nnew", opener=fake_update_opener
        )
        self.assertEqual(status_upd, "updated")
        self.assertEqual(patch_calls[1], ("PATCH", "https://api.github.com/repos/AI-Ops1/Parry/issues/comments/777"))

        # Fork PR read-only 403 does not fail CI
        def fake_403_opener(req: object, timeout: int = 15) -> _FakeHttpResponse:
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", None, io.BytesIO(b""))

        status_403 = pr_shield_action.post_or_update_pr_comment(
            "AI-Ops1/Parry", 42, "tok", "body", opener=fake_403_opener
        )
        self.assertEqual(status_403, "skipped-readonly")

    def test_run_action_end_to_end_step_summary_outputs_and_pr_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            bad_ts = root / "app.ts"
            bad_ts.write_text("const b = new Buffer(32);\n", encoding="utf-8")

            event_path = root / "event.json"
            event_path.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "number": 19,
                            "head": {"repo": {"full_name": "AI-Ops1/demo-repo"}},
                        }
                    }
                ),
                encoding="utf-8",
            )
            summary_path = root / "summary.md"
            output_path = root / "outputs.txt"
            sarif_path = root / "parry.sarif"

            def fake_opener(req: object, timeout: int = 15) -> _FakeHttpResponse:
                if req.get_method() == "GET":
                    return _FakeHttpResponse([])
                return _FakeHttpResponse({"id": 501})

            with mock.patch("sys.stdout", new_callable=io.StringIO):
                code = pr_shield_action.run_action(
                    env={
                        "INPUT_PATHS": str(bad_ts),
                        "INPUT_FAIL_ON": "error",
                        "INPUT_COMMENT_PR": "true",
                        "INPUT_SARIF_OUTPUT": str(sarif_path),
                        "INPUT_GITHUB_TOKEN": "ghs_test_token",
                        "GITHUB_EVENT_PATH": str(event_path),
                        "GITHUB_REPOSITORY": "AI-Ops1/demo-repo",
                        "GITHUB_STEP_SUMMARY": str(summary_path),
                        "GITHUB_OUTPUT": str(output_path),
                    },
                    opener=fake_opener,
                )

            self.assertEqual(code, 1)
            self.assertTrue(sarif_path.is_file())
            self.assertIn("PARRY-HAL-TS002", summary_path.read_text(encoding="utf-8"))
            outputs_text = output_path.read_text(encoding="utf-8")
            self.assertIn("findings-count=1", outputs_text)
            self.assertIn("errors-count=1", outputs_text)
            self.assertIn("comment-status=created", outputs_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
