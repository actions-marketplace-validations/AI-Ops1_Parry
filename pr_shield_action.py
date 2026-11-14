#!/usr/bin/env python3
"""
Parry PR Shield GitHub Action Runner (Zero third-party dependencies, Python 3.9+ stdlib).
Scans configured paths or PR changed files, emits SARIF 2.1.0 and GitHub Step Summaries,
and maintains a sticky PR Shield comment via GitHub REST API.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

import parry

REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def parse_input_list(raw: Optional[str]) -> List[str]:
    """Split comma/whitespace/newline-separated GitHub Action inputs cleanly."""
    if not raw:
        return []
    return [item.strip() for item in re.split(r"[\s,]+", raw.strip()) if item.strip()]


def load_event_payload(event_path: Optional[str]) -> Dict[str, Any]:
    """Load GITHUB_EVENT_PATH JSON payload safely."""
    if not event_path:
        return {}
    p = pathlib.Path(event_path)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def detect_pr_number(event_payload: Dict[str, Any]) -> Optional[int]:
    """Extract Pull Request number from GitHub Actions event payload."""
    pr = event_payload.get("pull_request")
    if isinstance(pr, dict) and isinstance(pr.get("number"), int) and pr["number"] > 0:
        return pr["number"]
    issue = event_payload.get("issue")
    if (
        isinstance(issue, dict)
        and isinstance(issue.get("pull_request"), dict)
        and isinstance(issue.get("number"), int)
        and issue["number"] > 0
    ):
        return issue["number"]
    return None


def is_fork_pull_request(event_payload: Dict[str, Any], repository: str) -> bool:
    """Return True when pull_request originates from a fork repository."""
    pr = event_payload.get("pull_request")
    if not isinstance(pr, dict):
        return False
    head_repo = pr.get("head", {}).get("repo") if isinstance(pr.get("head"), dict) else None
    if not isinstance(head_repo, dict):
        return False
    full_name = head_repo.get("full_name")
    return bool(full_name and repository and full_name.lower() != repository.lower())


def _github_api_request(
    url: str,
    token: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    opener: Optional[Callable[..., Any]] = None,
) -> Any:
    if not url.startswith("https://api.github.com/"):
        raise ValueError(f"Refusing non-GitHub API URL: {url}")

    body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=body_bytes,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Parry-PR-Shield/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if body_bytes is not None else {}),
        },
    )
    open_fn = opener or urllib.request.urlopen
    with open_fn(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def post_or_update_pr_comment(
    repository: str,
    pr_number: int,
    token: str,
    body: str,
    opener: Optional[Callable[..., Any]] = None,
) -> str:
    """
    Create or update the single sticky Parry PR Shield comment on a pull request.
    Returns 'created' | 'updated' | 'skipped-readonly' | 'skipped-no-token'.
    """
    if not token:
        return "skipped-no-token"
    if not REPO_SLUG_RE.match(repository) or pr_number <= 0:
        raise ValueError(f"Invalid repository ({repository!r}) or PR number ({pr_number!r})")

    list_url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments?per_page=100"
    try:
        comments = _github_api_request(list_url, token, method="GET", opener=opener)
        existing_id: Optional[int] = None
        if isinstance(comments, list):
            for c in comments:
                if isinstance(c, dict) and parry.PR_SHIELD_MARKER in (c.get("body") or ""):
                    cid = c.get("id")
                    if isinstance(cid, int) and cid > 0:
                        existing_id = cid
                        break

        if existing_id is not None:
            patch_url = f"https://api.github.com/repos/{repository}/issues/comments/{existing_id}"
            _github_api_request(patch_url, token, method="PATCH", payload={"body": body}, opener=opener)
            return "updated"

        create_url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"
        _github_api_request(create_url, token, method="POST", payload={"body": body}, opener=opener)
        return "created"
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404):
            print(
                f"[WARN] Skipping PR Shield comment on {repository}#{pr_number} (HTTP {exc.code} — likely read-only fork PR token).",
                file=sys.stderr,
            )
            return "skipped-readonly"
        raise


def write_github_output(output_path: Optional[str], values: Dict[str, Any]) -> None:
    """Write key=value outputs to GITHUB_OUTPUT safely."""
    if not output_path:
        return
    p = pathlib.Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        for k, v in values.items():
            clean_val = str(v).replace("\n", " ").replace("\r", " ")
            fh.write(f"{k}={clean_val}\n")


def write_step_summary(summary_path: Optional[str], markdown_body: str) -> None:
    """Append Markdown summary to GITHUB_STEP_SUMMARY."""
    if not summary_path:
        return
    p = pathlib.Path(summary_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(markdown_body + "\n")


def run_action(env: Optional[Dict[str, str]] = None, opener: Optional[Callable[..., Any]] = None) -> int:
    """Execute Parry AST scan, SARIF export, Step Summary, and sticky PR comment workflow."""
    cfg = env if env is not None else dict(os.environ)

    raw_paths = parse_input_list(cfg.get("INPUT_PATHS") or ".")
    if not raw_paths:
        raw_paths = ["."]
    exclude_patterns = parse_input_list(cfg.get("INPUT_EXCLUDE"))
    fail_on = (cfg.get("INPUT_FAIL_ON") or "warning").strip().lower()
    if fail_on not in ("error", "warning", "none"):
        fail_on = "warning"

    comment_pr = (cfg.get("INPUT_COMMENT_PR") or "true").strip().lower() != "false"
    changed_only = (cfg.get("INPUT_CHANGED_ONLY") or "false").strip().lower() == "true"
    sarif_output = (cfg.get("INPUT_SARIF_OUTPUT") or "").strip()
    baseline_file = pathlib.Path((cfg.get("INPUT_BASELINE") or ".parry-baseline.json").strip())
    token = (cfg.get("INPUT_GITHUB_TOKEN") or cfg.get("GITHUB_TOKEN") or "").strip()

    baseline_fps: set[str] = set()
    if baseline_file.is_file():
        try:
            data = json.loads(baseline_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                raw_fps = data.get("fingerprints", [])
                if isinstance(raw_fps, list):
                    baseline_fps = {str(fp) for fp in raw_fps if isinstance(fp, str) and re.match(r"^[a-f0-9]{64}$", fp)}
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Failed to parse baseline file {baseline_file}: {exc}", file=sys.stderr)

    changed_files: Optional[set[pathlib.Path]] = None
    if changed_only:
        base_ref = (cfg.get("GITHUB_BASE_REF") or "").strip()
        diff_target = f"origin/{base_ref}" if base_ref else "HEAD~1"
        try:
            changed_files = parry.get_changed_files_from_git(diff_target)
        except ValueError as exc:
            print(f"[WARN] Invalid diff ref {diff_target!r}: {exc}", file=sys.stderr)

    t0 = time.perf_counter()
    target_files = parry.collect_target_files(raw_paths, exclude_patterns, changed_files)
    all_findings: List[parry.Finding] = []
    for tf in target_files:
        all_findings.extend(parry.scan_file(tf, baseline_fps))
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    errors_count = sum(1 for f in all_findings if f.severity == "error")
    warnings_count = len(all_findings) - errors_count

    if sarif_output:
        sarif_path = pathlib.Path(sarif_output)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(parry.build_sarif_report(all_findings), indent=2) + "\n", encoding="utf-8")

    markdown_body = parry.format_pr_comment_markdown(all_findings, len(target_files), elapsed_ms)
    write_step_summary(cfg.get("GITHUB_STEP_SUMMARY"), markdown_body)

    event_payload = load_event_payload(cfg.get("GITHUB_EVENT_PATH"))
    repo_slug = (cfg.get("GITHUB_REPOSITORY") or "").strip()
    pr_number = detect_pr_number(event_payload)
    comment_status = "not-pr"

    if comment_pr and pr_number and repo_slug:
        if is_fork_pull_request(event_payload, repo_slug):
            comment_status = "skipped-fork"
            print(
                f"[INFO] Fork pull request detected ({repo_slug}#{pr_number}); skipping PR comment to stay compatible with read-only fork tokens."
            )
        else:
            comment_status = post_or_update_pr_comment(
                repo_slug, pr_number, token, markdown_body, opener=opener
            )

    write_github_output(
        cfg.get("GITHUB_OUTPUT"),
        {
            "findings-count": len(all_findings),
            "errors-count": errors_count,
            "warnings-count": warnings_count,
            "sarif-file": sarif_output if sarif_output else "",
            "comment-status": comment_status,
        },
    )

    if not all_findings:
        print(f"[OK] Parry PR Shield: 0 issues across {len(target_files)} file(s) ({elapsed_ms:.2f}ms).")
    else:
        for f in all_findings:
            print(f"[{f.rule_id}] ({f.severity}) {f.file_path}:{f.line}:{f.column} — {f.message}")
            if f.prompt_injection_patch:
                print(f"  +- Auto-Fix: {f.prompt_injection_patch}")

    return parry.compute_check_exit_code(all_findings, fail_on)


if __name__ == "__main__":
    sys.exit(run_action())
