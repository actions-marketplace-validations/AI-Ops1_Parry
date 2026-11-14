"""Zero-dependency IDE MCP, post-edit hook, git pre-commit, and agent rules bootstrapper for Parry."""

from dataclasses import asdict, dataclass
import json
import os
import pathlib
import shlex
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


IDE_NAMES: Tuple[str, ...] = ("claude", "cursor", "windsurf", "gemini", "codex")

RULE_MD_START = "<!-- parry-guardrails:start -->"
RULE_MD_END = "<!-- parry-guardrails:end -->"
HASH_BLOCK_START = "# >>> parry-guardrails >>>"
HASH_BLOCK_END = "# <<< parry-guardrails <<<"
TOML_BLOCK_START = "# >>> parry-mcp >>>"
TOML_BLOCK_END = "# <<< parry-mcp <<<"


@dataclass
class BootstrapAction:
    """Represents one planned or applied configuration/hook file change."""

    ide: str
    kind: str
    path: str
    status: str  # "create" | "update" | "unchanged" | "skip" | "error"
    detail: str
    preview: Optional[str] = None


def _default_parry_script() -> str:
    return pathlib.Path(__file__).resolve().parent.joinpath("parry.py").as_posix()


def _default_python_executable() -> str:
    return pathlib.Path(sys.executable).resolve().as_posix() if sys.executable else "python3"


def _toml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _upsert_marker_block(
    existing: Optional[str],
    block_body: str,
    start_marker: str,
    end_marker: str,
    preserve_header_only: bool = False,
) -> Tuple[str, str]:
    """Insert or replace a marker-delimited block without disturbing surrounding content."""
    full_block = f"{start_marker}\n{block_body.rstrip()}\n{end_marker}"
    if existing is None or not existing.strip():
        return full_block + "\n", "create"

    normalized = existing.replace("\r\n", "\n")
    s_idx = normalized.find(start_marker)
    e_idx = normalized.find(end_marker)
    if s_idx != -1 and e_idx != -1 and e_idx > s_idx:
        after_end = e_idx + len(end_marker)
        updated = normalized[:s_idx] + full_block + normalized[after_end:]
        if not updated.endswith("\n"):
            updated += "\n"
        status = "unchanged" if updated == normalized else "update"
        return updated, status

    if preserve_header_only:
        stripped = normalized.rstrip("\n")
        return stripped + "\n\n" + full_block + "\n", "update"

    stripped = normalized.rstrip("\n")
    return stripped + "\n\n" + full_block + "\n", "update"


def build_agent_rules_markdown() -> str:
    """Return canonical AI coding-agent instructions for CLAUDE.md / GEMINI.md / AGENTS.md."""
    return "\n".join(
        [
            "## Parry Zero-Slop Verification Guardrails",
            "",
            "Before concluding any code edit in Python, TypeScript, JavaScript, or Rust:",
            "1. Verify every imported package exists in `package-lock.json`, `Cargo.lock`, `uv.lock`, or `requirements.txt`.",
            "2. Call MCP tools `parry_verify_code` and `parry_fix_code` (or run `python parry.py check <file> --fix`).",
            "3. Never leave placeholder stubs (`TODO`, `pass`, truncation comments) or un-comparatored numeric `.sort()`.",
        ]
    )


def build_flat_rules_text() -> str:
    """Return line-oriented rules text for .cursorrules and .windsurfrules."""
    return "\n".join(
        [
            "# Parry AI Verification Rules",
            "- Verify all external packages against lockfiles before importing.",
            "- Call `parry_verify_code` / `parry_fix_code` via MCP (or `python parry.py check <file> --fix`) before finalizing edits.",
            "- Never emit truncation placeholders, bare `except: pass`, or un-comparatored `.sort()` calls.",
        ]
    )


def _parry_mcp_entry(python_exe: str, parry_script: str) -> Dict[str, Any]:
    return {
        "command": python_exe,
        "args": [parry_script, "mcp"],
    }


def _parry_post_edit_command(python_exe: str, parry_script: str) -> str:
    return f"{shlex.quote(python_exe)} {shlex.quote(parry_script)} post-edit"


def _patch_json_file(
    target: pathlib.Path,
    mutator: Callable[[Dict[str, Any]], None],
    dry_run: bool,
) -> Tuple[str, str, Optional[str]]:
    """Safely parse existing JSON object, apply mutator, and return (status, detail, preview)."""
    if target.is_symlink():
        raise ValueError(f"Refusing to mutate symlink target: {target}")
    existed = target.exists()
    original_raw = ""
    if existed:
        original_raw = target.read_text(encoding="utf-8")
        if original_raw.strip():
            try:
                loaded = json.loads(original_raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {target}: {exc}") from exc
            if not isinstance(loaded, dict):
                raise ValueError(f"Expected JSON object at root of {target}.")
        else:
            loaded = {}
    else:
        loaded = {}

    before_canonical = json.dumps(loaded, indent=2, sort_keys=False) + "\n"
    mutator(loaded)
    after_canonical = json.dumps(loaded, indent=2, sort_keys=False) + "\n"

    if existed and after_canonical == (original_raw.replace("\r\n", "\n") if original_raw.strip() else before_canonical):
        return "unchanged", "Already configured cleanly.", after_canonical

    status = "update" if existed else "create"
    if not dry_run:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(after_canonical, encoding="utf-8")
    detail = f"{'Would update' if dry_run else 'Updated' if existed else 'Created'} JSON config."
    return status, detail, after_canonical


def _merge_mcp_servers(data: Dict[str, Any], python_exe: str, parry_script: str) -> None:
    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("Expected 'mcpServers' to be a JSON object.")
    servers["parry"] = _parry_mcp_entry(python_exe, parry_script)


def _merge_claude_post_tool_use_hook(
    data: Dict[str, Any], python_exe: str, parry_script: str
) -> None:
    hooks_root = data.setdefault("hooks", {})
    if not isinstance(hooks_root, dict):
        raise ValueError("Expected 'hooks' to be a JSON object.")
    post_list = hooks_root.setdefault("PostToolUse", [])
    if not isinstance(post_list, list):
        raise ValueError("Expected 'hooks.PostToolUse' to be a JSON array.")

    cmd = _parry_post_edit_command(python_exe, parry_script)
    desired_entry = {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [{"type": "command", "command": cmd}],
    }

    for idx, item in enumerate(post_list):
        if isinstance(item, dict) and any(
            isinstance(h, dict) and "parry.py" in str(h.get("command", "")) and "post-edit" in str(h.get("command", ""))
            for h in (item.get("hooks") or [])
        ):
            post_list[idx] = desired_entry
            return
    post_list.append(desired_entry)


def _configure_codex_toml(
    target: pathlib.Path, python_exe: str, parry_script: str, dry_run: bool
) -> Tuple[str, str, str]:
    existing = target.read_text(encoding="utf-8") if target.exists() else None
    toml_block = "\n".join(
        [
            "[mcp_servers.parry]",
            f"command = {_toml_quote(python_exe)}",
            f"args = [{_toml_quote(parry_script)}, {_toml_quote('mcp')}]",
        ]
    )
    updated, status = _upsert_marker_block(
        existing, toml_block, TOML_BLOCK_START, TOML_BLOCK_END
    )
    if status != "unchanged" and not dry_run:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(updated, encoding="utf-8")
    detail = "Already configured cleanly." if status == "unchanged" else f"{'Would ' + status if dry_run else status.capitalize() + 'd'} Codex MCP config."
    return status, detail, updated


def _apply_instruction_file(
    target: pathlib.Path,
    body: str,
    start_marker: str,
    end_marker: str,
    dry_run: bool,
) -> Tuple[str, str, str]:
    existing = target.read_text(encoding="utf-8") if target.exists() else None
    updated, status = _upsert_marker_block(existing, body, start_marker, end_marker)
    if status != "unchanged" and not dry_run:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(updated, encoding="utf-8")
    detail = "Already configured cleanly." if status == "unchanged" else f"{'Would ' + status if dry_run else status.capitalize() + 'd'} instructions file."
    return status, detail, updated


def _resolve_ide_selection(ide: str) -> List[str]:
    normalized = ide.strip().lower()
    if normalized == "all":
        return list(IDE_NAMES)
    if normalized not in IDE_NAMES:
        raise ValueError(
            f"Unsupported IDE '{ide}'. Choose one of: {', '.join(IDE_NAMES)}, all."
        )
    return [normalized]


def _instruction_spec(ide: str, workspace: pathlib.Path) -> Tuple[pathlib.Path, str, str, str]:
    mapping: Dict[str, Tuple[str, str, str, str]] = {
        "claude": ("CLAUDE.md", build_agent_rules_markdown(), RULE_MD_START, RULE_MD_END),
        "gemini": ("GEMINI.md", build_agent_rules_markdown(), RULE_MD_START, RULE_MD_END),
        "codex": ("AGENTS.md", build_agent_rules_markdown(), RULE_MD_START, RULE_MD_END),
        "cursor": (".cursorrules", build_flat_rules_text(), HASH_BLOCK_START, HASH_BLOCK_END),
        "windsurf": (".windsurfrules", build_flat_rules_text(), HASH_BLOCK_START, HASH_BLOCK_END),
    }
    rel, body, start_m, end_m = mapping[ide]
    return workspace / rel, body, start_m, end_m


def _mcp_config_target(ide: str, scope: str, workspace: pathlib.Path, home: pathlib.Path) -> pathlib.Path:
    if scope == "user":
        user_map: Dict[str, pathlib.Path] = {
            "claude": home / ".claude.json",
            "cursor": home / ".cursor" / "mcp.json",
            "windsurf": home / ".codeium" / "windsurf" / "mcp_config.json",
            "gemini": home / ".gemini" / "settings.json",
            "codex": home / ".codex" / "config.toml",
        }
        return user_map[ide]
    ws_map: Dict[str, pathlib.Path] = {
        "claude": workspace / ".mcp.json",
        "cursor": workspace / ".cursor" / "mcp.json",
        "windsurf": workspace / ".windsurf" / "mcp.json",
        "gemini": workspace / ".gemini" / "settings.json",
        "codex": workspace / ".codex" / "config.toml",
    }
    return ws_map[ide]


def _claude_settings_target(scope: str, workspace: pathlib.Path, home: pathlib.Path) -> pathlib.Path:
    base = home if scope == "user" else workspace
    return base / ".claude" / "settings.json"


def install_git_pre_commit_hook(
    workspace: pathlib.Path,
    python_exe: str,
    parry_script: str,
    dry_run: bool = False,
) -> BootstrapAction:
    """Install or update a non-destructive git pre-commit hook running `parry check --staged`."""
    git_dir = workspace / ".git"
    if not git_dir.is_dir():
        return BootstrapAction(
            ide="git",
            kind="pre-commit",
            path=str(git_dir / "hooks" / "pre-commit"),
            status="skip",
            detail="No .git directory found in workspace; skipping git pre-commit hook.",
        )

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_body = "\n".join(
        [
            f"{shlex.quote(python_exe)} {shlex.quote(parry_script)} check --staged",
        ]
    )

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        updated, status = _upsert_marker_block(
            existing, hook_body, HASH_BLOCK_START, HASH_BLOCK_END
        )
    else:
        shebang_doc = f"#!/usr/bin/env sh\nset -e\n\n{HASH_BLOCK_START}\n{hook_body}\n{HASH_BLOCK_END}\n"
        updated = shebang_doc
        status = "create"

    if status != "unchanged" and not dry_run:
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(updated, encoding="utf-8")
        if os.name != "nt":
            os.chmod(hook_path, 0o755)

    detail = (
        "Already configured cleanly."
        if status == "unchanged"
        else f"{'Would ' + status if dry_run else status.capitalize() + 'd'} git pre-commit hook."
    )
    return BootstrapAction(
        ide="git",
        kind="pre-commit",
        path=str(hook_path),
        status=status,
        detail=detail,
        preview=updated,
    )


def install_ide_hooks(
    ide: str = "all",
    scope: str = "workspace",
    workspace: Optional[pathlib.Path] = None,
    user_home: Optional[pathlib.Path] = None,
    python_executable: Optional[str] = None,
    parry_script_path: Optional[str] = None,
    install_pre_commit: bool = True,
    install_post_edit: bool = True,
    install_instructions: bool = False,
    dry_run: bool = False,
) -> List[BootstrapAction]:
    """Non-destructively configure Parry MCP, hooks, and optional rules across one or all AI IDEs."""
    if scope not in ("workspace", "user"):
        raise ValueError(f"Unsupported scope '{scope}'. Use 'workspace' or 'user'.")

    ws = (workspace or pathlib.Path.cwd()).resolve()
    home = (user_home or pathlib.Path.home()).resolve()
    python_exe = python_executable or _default_python_executable()
    parry_script = parry_script_path or _default_parry_script()

    actions: List[BootstrapAction] = []
    for selected_ide in _resolve_ide_selection(ide):
        mcp_target = _mcp_config_target(selected_ide, scope, ws, home)
        try:
            if selected_ide == "codex":
                status, detail, preview = _configure_codex_toml(
                    mcp_target, python_exe, parry_script, dry_run
                )
            else:
                status, detail, preview = _patch_json_file(
                    mcp_target,
                    lambda data: _merge_mcp_servers(data, python_exe, parry_script),
                    dry_run,
                )
            actions.append(
                BootstrapAction(
                    ide=selected_ide,
                    kind="mcp-config",
                    path=str(mcp_target),
                    status=status,
                    detail=detail,
                    preview=preview,
                )
            )
        except ValueError as exc:
            actions.append(
                BootstrapAction(
                    ide=selected_ide,
                    kind="mcp-config",
                    path=str(mcp_target),
                    status="error",
                    detail=str(exc),
                )
            )

        if selected_ide == "claude" and install_post_edit:
            settings_target = _claude_settings_target(scope, ws, home)
            try:
                status, detail, preview = _patch_json_file(
                    settings_target,
                    lambda data: _merge_claude_post_tool_use_hook(
                        data, python_exe, parry_script
                    ),
                    dry_run,
                )
                actions.append(
                    BootstrapAction(
                        ide="claude",
                        kind="post-edit-hook",
                        path=str(settings_target),
                        status=status,
                        detail=detail,
                        preview=preview,
                    )
                )
            except ValueError as exc:
                actions.append(
                    BootstrapAction(
                        ide="claude",
                        kind="post-edit-hook",
                        path=str(settings_target),
                        status="error",
                        detail=str(exc),
                    )
                )

        if install_instructions:
            rule_path, body, start_m, end_m = _instruction_spec(selected_ide, ws)
            status, detail, preview = _apply_instruction_file(
                rule_path, body, start_m, end_m, dry_run
            )
            actions.append(
                BootstrapAction(
                    ide=selected_ide,
                    kind="instructions",
                    path=str(rule_path),
                    status=status,
                    detail=detail,
                    preview=preview,
                )
            )

    if install_pre_commit:
        actions.append(
            install_git_pre_commit_hook(ws, python_exe, parry_script, dry_run=dry_run)
        )

    return actions


def extract_post_edit_path(stdin_text: str, explicit_path: Optional[str] = None) -> Optional[pathlib.Path]:
    """Resolve edited file path from CLI argument or Claude Code PostToolUse stdin JSON."""
    if explicit_path:
        return pathlib.Path(explicit_path)
    raw = stdin_text.strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        fpath = tool_input.get("file_path") or tool_input.get("path")
        if isinstance(fpath, str) and fpath.strip():
            return pathlib.Path(fpath.strip())
    direct = payload.get("file_path")
    if isinstance(direct, str) and direct.strip():
        return pathlib.Path(direct.strip())
    return None


def actions_to_dict_list(actions: Sequence[BootstrapAction]) -> List[Dict[str, Any]]:
    """Convert BootstrapAction sequence into JSON-serializable dictionaries."""
    return [asdict(a) for a in actions]
