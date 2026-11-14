"""Automated tests for IDE/MCP/hook bootstrapping, git --staged, post-edit, and <20ms MCP latency."""

import io
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

import ide_hooks
import parry


REPO_DIR = pathlib.Path(__file__).resolve().parent


class TestParryIdeHooksAndMcpLatency(unittest.TestCase):
    def test_dry_run_makes_no_disk_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = pathlib.Path(tmp) / "workspace"
            home = pathlib.Path(tmp) / "home"
            (ws / ".git" / "hooks").mkdir(parents=True)
            home.mkdir(parents=True)

            actions = ide_hooks.install_ide_hooks(
                ide="all",
                scope="workspace",
                workspace=ws,
                user_home=home,
                install_pre_commit=True,
                install_post_edit=True,
                install_instructions=True,
                dry_run=True,
            )
            self.assertTrue(any(a.ide == "codex" and a.status == "create" for a in actions))
            self.assertTrue(any(a.kind == "pre-commit" and a.status == "create" for a in actions))
            self.assertFalse((ws / ".mcp.json").exists())
            self.assertFalse((ws / ".claude" / "settings.json").exists())
            self.assertFalse((ws / ".cursor" / "mcp.json").exists())
            self.assertFalse((ws / ".windsurf" / "mcp.json").exists())
            self.assertFalse((ws / ".gemini" / "settings.json").exists())
            self.assertFalse((ws / ".codex" / "config.toml").exists())
            self.assertFalse((ws / ".git" / "hooks" / "pre-commit").exists())
            self.assertFalse((ws / "CLAUDE.md").exists())

    def test_non_destructive_idempotent_install_all_five_ides_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = pathlib.Path(tmp) / "workspace"
            home = pathlib.Path(tmp) / "home"
            (ws / ".git" / "hooks").mkdir(parents=True)
            (ws / ".claude").mkdir(parents=True)
            (ws / ".cursor").mkdir(parents=True)
            (ws / ".windsurf").mkdir(parents=True)
            (ws / ".gemini").mkdir(parents=True)
            (ws / ".codex").mkdir(parents=True)
            home.mkdir(parents=True)

            # Pre-seed existing unrelated settings & rules that must survive untouched
            (ws / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"postgres": {"command": "pg-mcp"}}}),
                encoding="utf-8",
            )
            (ws / ".claude" / "settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {"allow": ["Read"]},
                        "hooks": {
                            "PostToolUse": [
                                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo ok"}]}
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            (ws / ".gemini" / "settings.json").write_text(
                json.dumps({"theme": "Dark", "mcpServers": {"docs": {"command": "docs-mcp"}}}),
                encoding="utf-8",
            )
            (ws / ".codex" / "config.toml").write_text(
                'model = "o3"\n\n[mcp_servers.existing]\ncommand = "echo"\n',
                encoding="utf-8",
            )
            (ws / "CLAUDE.md").write_text("# Team Rules\n- Keep functions small.\n", encoding="utf-8")
            (ws / ".cursorrules").write_text("# Existing Cursor rule\n- Use strict TS.\n", encoding="utf-8")
            (ws / ".git" / "hooks" / "pre-commit").write_text(
                "#!/usr/bin/env sh\necho custom-lint\n", encoding="utf-8"
            )

            first = ide_hooks.install_ide_hooks(
                ide="all",
                scope="workspace",
                workspace=ws,
                user_home=home,
                install_pre_commit=True,
                install_post_edit=True,
                install_instructions=True,
                dry_run=False,
            )
            self.assertFalse(any(a.status == "error" for a in first))

            # Verify existing keys survived and Parry entries added
            claude_mcp = json.loads((ws / ".mcp.json").read_text(encoding="utf-8"))
            self.assertIn("postgres", claude_mcp["mcpServers"])
            self.assertEqual(claude_mcp["mcpServers"]["parry"]["args"][-1], "mcp")

            claude_settings = json.loads((ws / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(claude_settings["permissions"], {"allow": ["Read"]})
            self.assertEqual(len(claude_settings["hooks"]["PostToolUse"]), 2)
            self.assertTrue(
                any("post-edit" in str(item) for item in claude_settings["hooks"]["PostToolUse"])
            )

            gemini_cfg = json.loads((ws / ".gemini" / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(gemini_cfg["theme"], "Dark")
            self.assertIn("docs", gemini_cfg["mcpServers"])
            self.assertIn("parry", gemini_cfg["mcpServers"])

            cursor_mcp = json.loads((ws / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
            windsurf_mcp = json.loads((ws / ".windsurf" / "mcp.json").read_text(encoding="utf-8"))
            self.assertIn("parry", cursor_mcp["mcpServers"])
            self.assertIn("parry", windsurf_mcp["mcpServers"])

            codex_toml = (ws / ".codex" / "config.toml").read_text(encoding="utf-8")
            self.assertIn('model = "o3"', codex_toml)
            self.assertIn("[mcp_servers.existing]", codex_toml)
            self.assertIn("[mcp_servers.parry]", codex_toml)

            claude_md = (ws / "CLAUDE.md").read_text(encoding="utf-8")
            self.assertIn("# Team Rules", claude_md)
            self.assertIn("parry_verify_code", claude_md)

            cursor_rules = (ws / ".cursorrules").read_text(encoding="utf-8")
            self.assertIn("# Existing Cursor rule", cursor_rules)
            self.assertIn("parry_verify_code", cursor_rules)

            pre_commit = (ws / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
            self.assertIn("echo custom-lint", pre_commit)
            self.assertIn("check --staged", pre_commit)

            # Second run must be strictly idempotent
            second = ide_hooks.install_ide_hooks(
                ide="all",
                scope="workspace",
                workspace=ws,
                user_home=home,
                install_pre_commit=True,
                install_post_edit=True,
                install_instructions=True,
                dry_run=False,
            )
            self.assertTrue(all(a.status == "unchanged" for a in second), f"Expected all unchanged, got: {second}")
            claude_settings_after = json.loads((ws / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(claude_settings_after["hooks"]["PostToolUse"]), 2)

    def test_user_scope_targets_home_and_invalid_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = pathlib.Path(tmp) / "workspace"
            home = pathlib.Path(tmp) / "home"
            ws.mkdir(parents=True)
            (home / ".cursor").mkdir(parents=True)
            broken = "{not valid json"
            (home / ".cursor" / "mcp.json").write_text(broken, encoding="utf-8")

            actions = ide_hooks.install_ide_hooks(
                ide="all",
                scope="user",
                workspace=ws,
                user_home=home,
                install_pre_commit=False,
                install_post_edit=True,
                install_instructions=False,
                dry_run=False,
            )
            cursor_err = [a for a in actions if a.ide == "cursor"][0]
            self.assertEqual(cursor_err.status, "error")
            self.assertEqual((home / ".cursor" / "mcp.json").read_text(encoding="utf-8"), broken)

            self.assertTrue((home / ".claude.json").exists())
            self.assertTrue((home / ".claude" / "settings.json").exists())
            self.assertTrue((home / ".codeium" / "windsurf" / "mcp_config.json").exists())
            self.assertTrue((home / ".gemini" / "settings.json").exists())
            self.assertTrue((home / ".codex" / "config.toml").exists())

    def test_git_staged_scan_and_post_edit_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "ci@parry.test"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Parry CI"], cwd=repo, check=True, capture_output=True)

            target = repo / "sort_nums.ts"
            target.write_text("export const ok = [1, 2].sort((a, b) => a - b);\n", encoding="utf-8")
            subprocess.run(["git", "add", "sort_nums.ts"], cwd=repo, check=True, capture_output=True)

            # Mutate working tree (unstaged) to contain bug: --staged must still see clean staged index!
            target.write_text("export const bug = [10, 2].sort();\n", encoding="utf-8")
            clean_proc = subprocess.run(
                [sys.executable, str(REPO_DIR / "parry.py"), "check", "--staged"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clean_proc.returncode, 0, clean_proc.stdout + clean_proc.stderr)

            # Post-edit on the working-tree buggy file via Claude PostToolUse stdin JSON returns 2
            hook_payload = json.dumps({"tool_input": {"file_path": str(target)}})
            hook_proc = subprocess.run(
                [sys.executable, str(REPO_DIR / "parry.py"), "post-edit"],
                input=hook_payload,
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(hook_proc.returncode, 2)
            self.assertIn("PARRY-LOG-TS001", hook_proc.stderr)

            # Now stage the buggy file: --staged catches it with exit 1
            subprocess.run(["git", "add", "sort_nums.ts"], cwd=repo, check=True, capture_output=True)
            dirty_proc = subprocess.run(
                [sys.executable, str(REPO_DIR / "parry.py"), "check", "--staged", "--format", "json"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(dirty_proc.returncode, 1)
            parsed = json.loads(dirty_proc.stdout)
            self.assertEqual(parsed[0]["rule_id"], "PARRY-LOG-TS001")

    def test_parry_init_ide_and_mcp_sub_20ms_latency(self) -> None:
        # 1. Verify CLI init --ide windsurf --dry-run runs cleanly
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = parry.main(["init", "--ide", "windsurf", "--dry-run", tmp])
            self.assertEqual(rc, 0)
            self.assertIn("[DRY-RUN]", buf.getvalue())

        # 2. Verify realistic single-file MCP latency < 20ms p95 for parry_verify_code and parry_fix_code
        py_sample = "\n".join(
            ["from datetime import datetime", "def stamp():", "    return datetime.utcnow()"]
            + [f"def helper_{i}(x: int) -> int:\n    return x + {i}" for i in range(30)]
        )
        ts_sample = "\n".join(
            ["const raw = new Buffer(64);", "const sorted = [10, 2, 1].sort();"]
            + [f"export function calc{i}(n: number): number {{ return n * {i}; }}" for i in range(30)]
        )
        rs_sample = "\n".join(
            ["async fn poll_it() { std::thread::sleep(std::time::Duration::from_millis(5)); }"]
            + [f"pub fn step_{i}(v: i32) -> i32 {{ v + {i} }}" for i in range(30)]
        )

        # Warm up once
        parry.handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "tools/call",
                "params": {"name": "parry_verify_code", "arguments": {"language": "python", "code": py_sample}},
            }
        )

        timings_ms: list[float] = []
        samples = [
            ("python", "parry_verify_code", "app.py", py_sample),
            ("python", "parry_fix_code", "app.py", py_sample),
            ("typescript", "parry_verify_code", "app.ts", ts_sample),
            ("typescript", "parry_fix_code", "app.ts", ts_sample),
            ("rust", "parry_verify_code", "lib.rs", rs_sample),
        ]
        for idx in range(20):
            lang, tool, fpath, code = samples[idx % len(samples)]
            t0 = time.perf_counter()
            resp = parry.handle_mcp_request(
                {
                    "jsonrpc": "2.0",
                    "id": idx + 1,
                    "method": "tools/call",
                    "params": {
                        "name": tool,
                        "arguments": {"language": lang, "file_path": fpath, "code": code},
                    },
                }
            )
            elapsed = (time.perf_counter() - t0) * 1000.0
            timings_ms.append(elapsed)
            self.assertIsNotNone(resp)
            content_text = resp["result"]["content"][0]["text"]
            self.assertTrue(len(content_text) > 2)

        timings_ms.sort()
        p95_ms = timings_ms[int(len(timings_ms) * 0.95) - 1]
        self.assertLess(p95_ms, 20.0, f"Expected MCP p95 < 20ms, observed {p95_ms:.2f}ms ({timings_ms})")


if __name__ == "__main__":
    unittest.main()
