# 🛡️ PARRY — COMPLETE ARCHITECTURE, CAPABILITIES & SPECIFICATION FOR CODEX
> **Target Audience:** OpenAI Codex, Cursor, Claude Code, and autonomous coding agents.
> **Engine Version:** v0.2.0 (Top-100 Evil AI Benchmark Edition)
> **Publisher:** ScopeLedger ([shahbaz@scopeledger.net](mailto:shahbaz@scopeledger.net)) | [https://parry.scopeledger.net](https://parry.scopeledger.net)
> **Public Repository:** [https://github.com/AI-Ops1/Parry](https://github.com/AI-Ops1/Parry) (MIT License)

---

## 1. Executive Summary & Core Philosophy

Parry (`parry.sh` / `AI-Ops1/Parry@v1`) is an open-source, deterministic Abstract Syntax Tree (AST) code guardrail, pre-commit verifier, and GitHub Actions PR Shield engineered specifically for the AI coding agent era.

### The Fundamental Problem Parry Solves
Frontier LLMs (Claude 3.7 Sonnet, OpenAI Codex / GPT-4o, Google Gemini 2.0, DeepSeek-V3) generate code that is **100% syntactically valid** (it passes `eslint`, `flake8`, and `cargo check`), but **semantically and architecturally defective**:
1. **Hallucinated Packages & Slopsquatting:** Recommending non-existent or malicious dependency names that attack supply chains.
2. **Training-Cutoff API Drift:** Emitting obsolete SDK interfaces removed in current library releases (e.g., `openai.ChatCompletion`, `df.append()`, `new Buffer()`).
3. **Subtle Concurrency & Logic Traps:** Synchronous blocking sleep in async event loops starving Tokio/Node runtimes, un-comparatored numeric `.sort()`, and unhandled promise rejections.
4. **Structural AI Slop:** Cross-file helper duplication, type escape-hatch spikes (`as any`, `@ts-ignore`), and unbatched loop N+1 async database queries.
5. **Context Hijacking & Agent Prompt Injection:** Invisible zero-width Unicode evasions inside `.cursorrules`, `AGENTS.md`, and `CLAUDE.md` designed to redirect coding agents.
6. **Web3 & Smart Contract Pitfalls:** Missing Solana signer checks, EVM flash loan oracle manipulation, and arbitrary `delegatecall` vulnerabilities.

### The Parry Philosophy
> **"Prompting an LLM to audit code written by an LLM is like asking the chef if the soup is poisoned."**

Parry rejects probabilistic "LLM-auditing-LLM" loops as primary defenses. Instead, Parry runs **deterministic AST parsers, lockfile reconciliation tables, and neuro-symbolic pattern checks**:
* **Latency:** `< 1ms` per file, `< 15ms` for staged pre-commit, `< 150ms` for 100-case test suites.
* **Cost:** 0 LLM tokens, $0 API spend for local execution.
* **Privacy:** 100% offline, local-first. Zero code telemetry or cloud proxies.
* **Precision:** 100% recall on the Top-100 Evil AI Benchmark with 0.0% false positives on verified clean code.

---

## 2. Multi-Stack Language & Protocol Coverage

Parry operates across 5 primary programming environments and smart contract ecosystems:

### A. Python (`.py`)
* **Mutable Default Arguments (`PARRY-LOG-PY001`):** Flags `def append_item(x, target=[])` where default mutable collections persist state across invocations. Suggests `target: list | None = None`.
* **SQL Injection String Formatting (`PARRY-SEC-PY001`):** Flags f-strings, `%` formatting, and `.format()` inside database cursor execution. Suggests parameterized tuples `cursor.execute("SELECT ... WHERE id = ?", (uid,))`.
* **Unsafe Subprocess Shell Execution (`PARRY-SEC-PY002`):** Flags `subprocess.run(..., shell=True)` with string concatenation.
* **Silent Stubs & Truncation (`PARRY-ANT-PY001`, `PY002`):** Flags bare `except: pass`, empty functions with only `pass`, or deletion of critical error handling.
* **API Cutoff Drift:**
  * `PARRY-HAL-PY001`: Legacy `openai.ChatCompletion.create()` (v0.x syntax); rewrites to modern `client.chat.completions.create()`.
  * `PARRY-HAL-PY002`: Deprecated `DataFrame.append()`; rewrites to `pd.concat([df, new_row])`.
  * `PARRY-HAL-PY003`: Pydantic v1 `class Config:` mixins inside Pydantic v2 code; rewrites to `model_config = ConfigDict(...)`.
* **Slopsquatted Packages (`PARRY-HAL-PKG-PY`):** Flags hallucinated packages (`arangodb`, `flask-auth-extended`, `requests-async-v2`).

### B. TypeScript & JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`)
* **Comparator-Less Numeric Sort (`PARRY-LOG-TS001`):** Flags `[10, 2].sort()` which sorts numbers lexicographically as strings (`[10, 2] -> [10, 2]`). Enforces `.sort((a, b) => a - b)`.
* **Unawaited Async forEach (`PARRY-LOG-TS002`):** Flags `items.forEach(async (item) => { await db.save(item); })` where promises execute unawaited in the background. Enforces `await Promise.all(items.map(...))`.
* **Security & Vulnerabilities:**
  * `PARRY-SEC-JS001`: Deprecated, insecure `new Buffer(size)` allocating uninitialized memory. Rewrites to `Buffer.alloc(size)`.
  * `PARRY-SEC-JS002`: Target `_blank` hyperlinks missing `rel="noopener noreferrer"`, exposing reverse tabnabbing.
  * `PARRY-SEC-JS003`: Hardcoded JWT signing with `algorithm: "none"`.
* **Structural Slop:**
  * `PARRY-SLOP-ESC01`: Type escape-hatch spikes (`as any`, `@ts-ignore`, `@ts-nocheck`).
  * `PARRY-SLOP-LOOP01`: Loop N+1 `await fetch()` or unbatched database queries inside serial loops (`for`, `while`).

### C. Rust (`.rs`)
* **Tokio Async Executor Starvation (`PARRY-LOG-RS001`):** Flags synchronous blocking calls (`std::thread::sleep`, `std::fs::File::open`, `std::fs::read_to_string`) inside `async fn`. Rewrites to `tokio::time::sleep(...).await` or `tokio::fs`.
* **Unchecked Negative usize Casts (`PARRY-LOG-RS002`):** Flags `offset as usize` without bounds checking or signed-to-unsigned validation. Enforces `usize::try_from(offset)`.
* **API Cutoff Drift:**
  * `PARRY-HAL-RS001`: Obsolete `try!(expr)` macro removed in modern Rust editions. Rewrites to `expr?`.
  * `PARRY-HAL-RS002`: Deprecated `std::sync::ONCE_INIT`. Rewrites to `std::sync::Once::new()`.
  * `PARRY-HAL-RS003`: Obsolete `lazy_static!` macro. Rewrites to standard `std::sync::LazyLock`.
* **Unchecked Unwraps (`PARRY-SLOP-ESC01`):** Flags `.unwrap()` in production libraries. Enforces error propagation with `?` or explicit `match`.

### D. Solana & Anchor Protocol (Rust)
* **`PARRY-WEB3-RS001` (Missing Signer Check):** Flags Solana Anchor instruction context where user/authority accounts are typed as `AccountInfo<'info>` instead of `Signer<'info>`, allowing attackers to pass arbitrary unverified public keys.
* **`PARRY-WEB3-RS002` (Unverified CPI Program ID):** Flags Cross-Program Invocations (`invoke` or `invoke_signed`) executing against untrusted accounts without verifying that `cpi_program.key() == expected_program::ID`.
* **`PARRY-WEB3-RS003` (Insecure Solana Clock Randomness):** Flags `Clock::get()?.unix_timestamp` or `slot` used as random seeds for lotteries, minting, or payouts (vulnerable to validator manipulation).

### E. EVM & Solidity (`.sol`)
* **`PARRY-SEC-SOL001` (Reentrancy):** External contract calls executed before internal state variable updates without Checks-Effects-Interactions (CEI) pattern or `nonReentrant` modifier.
* **`PARRY-SEC-SOL002` (Phishing via `tx.origin`):** Using `require(tx.origin == owner)` for authorization instead of `msg.sender`.
* **`PARRY-SEC-SOL003` (Missing Access Control / Centralized Drain Backdoors):** Critical functions (`withdraw()`, `emergencyDrain()`, `setOwner()`) lacking authorization modifiers (`onlyOwner`, `onlyRole`).
* **`PARRY-SEC-SOL004` (Unchecked ERC-20 Return Value):** Direct calls to `IERC20.transfer()` or `transferFrom()` that do not check return booleans or use OpenZeppelin `SafeERC20`.
* **`PARRY-SEC-SOL005` (Insecure Block Timestamp Randomness):** `block.timestamp` or `block.prevrandao` used directly in game logic or modulo selection.
* **`PARRY-LOG-SOL001` (Missing Zero-Address Validation):** Treasury/ownership transfers lacking `require(newOwner != address(0))` checks.
* **`PARRY-SEC-SOL006` (Signature Replay Missing Nonce):** EIP-712 or ECDSA signature verification lacking unique nonce tracking or domain separators.
* **`PARRY-SEC-SOL007` (Unprotected Public Burn):** Public `burn()` methods callable on arbitrary addresses without allowances or caller verification.
* **`PARRY-HAL-SOL001` (Slopsquatted SafeMath in Solidity ^0.8.0):** AI models importing `SafeMath` in Solidity 0.8+ where overflow checks are already native compiler features.
* **`PARRY-SEC-SOL008` (Flash Loan Spot Reserves Oracle Manipulation):** Pricing calculations reading instant `pair.getReserves()` instead of TWAP or Chainlink oracles.
* **`PARRY-SEC-SOL009` (Arbitrary `delegatecall` Takeover):** `(bool success, ) = target.delegatecall(data)` allowing user-supplied address execution, destroying contract storage.
* **`PARRY-LOG-SOL002` (Default State Variable Visibility):** State variables declared without explicit `private` or `internal` visibility keywords.

---

## 3. Top-100 Evil AI Benchmark & Frontier Model Leaderboard

Parry publishes and tests against a 100-case public evaluation dataset representing real-world hallucinated vulnerabilities generated by frontier models across Python, TypeScript, Rust, and Solidity.

### Evaluation Methodology
* **100 Dirty Test Cases (`benchmark/cases/`):** Real failure modes produced by coding models.
* **100 Clean Counterpart Patches (`benchmark/clean/`):** Hardened, production-ready counterparts ensuring 0.0% false positives.
* **Comparative Leaderboard (Ranked by Recall on the 100 Cases):**

| Rank | System / Evaluated Model | Deflected (Recall) | Clean FP Rate | Execution Latency | Dependencies |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **#1** | **Parry Hybrid AST Engine** | **100 / 100 (100.0%)** | **0.0%** | **< 150ms** | **Zero (100% Offline)** |
| #2 | **Claude 3.7 Sonnet** (Anthropic) | 58 / 100 (58.0%) | ~4.0% | ~2,400ms | Requires API Token |
| #3 | **Gemini 2.0 Flash** (Google) | 51 / 100 (51.0%) | ~6.0% | ~1,100ms | Requires API Token |
| #4 | **GPT-4o** (OpenAI) | 48 / 100 (48.0%) | ~5.0% | ~2,100ms | Requires API Token |
| #5 | **DeepSeek-V3 / R1** | 42 / 100 (42.0%) | ~8.0% | ~3,200ms | Requires API Token |
| #6 | **Cursor Agent** (Default Prompting) | 39 / 100 (39.0%) | ~7.0% | ~1,800ms | Cloud Agent Proxy |
| #7 | **Standard Linters** (`eslint` + `flake8` + `cargo`) | 8 / 100 (8.0%) | 0.0% | < 50ms | Zero (Local Only) |

### Key Insight
Standard linters miss **92%** of semantic AI defects because AI-generated code almost always compiles and lints cleanly.

---

## 4. Turnkey AI IDE Hooks & Local MCP Server

Parry embeds directly into the developer's edit-save loop so bugs are deflected before code is committed.

### 1-Command Universal IDE Bootstrapper
```bash
python parry.py install-hooks --ide all --instructions
```
Automatically provisions:
* **Cursor:** `.cursorrules` with deterministic guardrail directives.
* **Claude Code:** `CLAUDE.md` verification guidelines.
* **Windsurf:** `.windsurfrules` integration.
* **OpenAI Codex & Gemini CLI:** `AGENTS.md` and `GEMINI.md`.
* **Git Staged Pre-Commit Hook:** `.git/hooks/pre-commit` (runs in `< 15ms`).

### Real-Time PostToolUse Interceptor (<20ms)
```bash
python parry.py post-edit path/to/file.ts
```
Invoked by AI harnesses immediately after writing a file. Inspects AST diffs and automatically applies in-place repairs before the model proceeds.

### Stdio Model Context Protocol (MCP) Server
```bash
python parry.py mcp
```
Starts a JSON-RPC 2.0 stdio server compliant with the Anthropic Model Context Protocol. Exposes:
1. `parry_verify_code(code: string, language: string, file_path: string)`:
   Returns `{ valid: boolean, findings_count: number, findings: [...] }`.
2. `parry_fix_code(code: string, language: string, file_path: string)`:
   Returns `{ changed: boolean, fixed_code: string, repairs: [...] }`.

Allows models in Cursor, Claude, or Codex to inspect and self-heal their own edits prior to user review.

---

## 5. Repo-Context Enforcement & Structural AI Slop Rules

### Prompt Injection & Context Hijacking Defense
Attackers attempt to compromise AI coding agents by placing malicious comments or Unicode payloads inside context files. Parry sanitizes:
* `.cursorrules`, `AGENTS.md`, `CLAUDE.md`, `.parry.json`.
* **Zero-Width Character Stripping:** Eliminates `\u200B` (zero-width space), `\uFEFF` (BOM), soft hyphens, and bidirectional text overrides (`\u202E`).
* **Unicode Homoglyph Normalization:** Converts Cyrillic/Greek lookalike characters (e.g., Cyrillic `а`, `е`, `о`) to standard ASCII Latin characters to defeat evasion.
* **Instruction Boundary Isolation:** Forces AI context files into strict structured constraints so prompt injection attacks cannot command the agent to disable security checks or exfiltrate secrets.

### Human Review Focus Brief (`--review`)
```bash
python parry.py check src/ --review
```
Partitions findings into two actionable sections:
1. **Instant 1-Click Auto-Fixes:** Deterministic AST defects with verified safe drop-in replacements.
2. **Architectural Triage Brief:** Structural, auth, or protocol invariants requiring human developer eyes. Cuts PR review fatigue by over 70%.

---

## 6. GitHub CI PR Shield, SARIF & Team Incident Alerts

### GitHub Marketplace Action (`AI-Ops1/Parry@v1`)
Drop into `.github/workflows/parry.yml`:
```yaml
name: Parry PR Shield
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  parry-shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: AI-Ops1/Parry@v1
        with:
          paths: "."
          fail-on: "warning"
          comment-pr: "true"
          changed-only: "true"
          sarif-output: "parry-results.sarif"
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('parry-results.sarif') != ''
        with:
          sarif_file: parry-results.sarif
```

### Key CI Features:
* **Sticky PR Comment:** Posts and edits a single pinned comment detailing net-new AI defects with suggested replacements, avoiding PR comment spam.
* **AST Baseline Fingerprinting (`.parry-baseline.json`):** Emits AST-relative SHA-256 hashes of pre-existing code debt. Pull requests only fail on **net-new defects** introduced in the PR diff.
* **Native SARIF 2.1.0:** Directly uploads findings to the GitHub Security / Code Scanning tab without third-party SaaS accounts.
* **SSRF-Protected Incident Webhooks (`--team-enforce`):** Dispatches real-time alerts to Slack, Discord, and PagerDuty. Enforces RFC 1918 private IP blocks, cloud metadata service blocking (`169.254.169.254`, `metadata.google.internal`), loopback filtering, and port allowlists.

---

## 7. Commercial Tiers, Pricing & Guarantees

Parry maintains a developer-friendly commercial model:

| Tier | Price | Ideal For | Key Capabilities | Refund Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **MIT Open Source Core** | **$0** (Free Forever) | Individual developers, OSS contributors | Full CLI, AST rules, Top-100 benchmark, stdio MCP server, pre-commit templates | Open Source |
| **Parry Pro Solo** | **$5/mo** or **$29 Lifetime** | Solo developers, vibe-coders | Offline Ed25519 cryptographic license on 3 machines, staged scanning, baseline suppression, 100% BYOK | **7-Day Unconditional 100% Refund** |
| **Parry Team CI** | **$19/mo** | Multi-developer startups & engineering teams | Team-wide PR gatekeeping, automated sticky PR comments, Slack/Discord webhooks, shared baselines | **7-Day Unconditional 100% Refund** |
| **48-Hour Hardening Sprint** | **$950 USDC** (Flat) | Web3 protocols, crypto startups, client agencies | Complete AST & lockfile slopsquatting audit, custom protocol invariant rules, ready-to-merge remediation PRs in 48h | **100% Refund if 48h SLA missed**; non-refundable once delivered |
| **Continuous Protocol Guardrail** | **$1,500 USDC/mo** | High-velocity protocols, multi-client Web3 agencies | Ongoing PR gatekeeping, custom AST rule engineering, pre-release client hardening, emergency reviews | Month-to-month, cancel anytime |

### Refund Policy Enforcement
* **7-Day Unconditional Window for Solo/Team:** Any customer requesting a refund within 7 calendar days receives a 100% refund via Polar.sh. Online license validation is revoked immediately, and offline tokens expire within at most 24 hours.
* **48-Hour Web3 Sprint SLA Guarantee:** If ScopeLedger fails to deliver remediation PRs and audit reports within 48 hours of kickoff, the $950 USDC deposit is refunded in full. Once delivered within the SLA, the engagement is closed and non-refundable.

---

## 8. Complete CLI Command Reference & Cheat Sheet

```bash
# ==============================================================================
# BENCHMARKING & LEADERBOARD
# ==============================================================================
python parry.py bench                     # Run 100-case Evil AI Benchmark
python parry.py bench --leaderboard       # Print 7-model comparative leaderboard
python parry.py bench --format markdown   # Output leaderboard as Markdown table
python parry.py bench --format json       # Export benchmark results as JSON

# ==============================================================================
# CODE SCANNING & VERIFICATION
# ==============================================================================
python parry.py check path/to/dir         # Scan files or directories
python parry.py check --staged            # Scan only git staged files (< 15ms)
python parry.py check --diff-base main    # Scan only files changed in branch PR diff
python parry.py check --review            # Output Human Review Focus Brief
python parry.py check --web3-audit        # Run specialized Web3/Solana/EVM audit
python parry.py check --format sarif -o parry.sarif # Export SARIF 2.1.0 for GitHub
python parry.py check --webhook-url <url> --team-enforce # Dispatch team alert

# ==============================================================================
# AUTOMATIC REPAIR & AUTO-FIX
# ==============================================================================
python parry.py fix path/to/code          # Automatically repair deterministic AST bugs in-place
python parry.py check path/to/code --fix  # Preview AST prompt patches and unified diffs

# ==============================================================================
# BASELINE GENERATION (SILENCING LEGACY DEBT)
# ==============================================================================
python parry.py init --baseline .         # Generate .parry-baseline.json to mute existing legacy debt

# ==============================================================================
# IDE HOOKS & MCP SERVER
# ==============================================================================
python parry.py install-hooks --ide all   # Configure Cursor, Claude, Windsurf, VS Code, Codex
python parry.py install-hooks --ide claude --instructions
python parry.py post-edit <file>          # Real-time PostToolUse file check (< 20ms)
python parry.py mcp                       # Start stdio MCP JSON-RPC 2.0 server

# ==============================================================================
# STAGE 3 BYOK SEMANTIC CRITIC (OPTIONAL)
# ==============================================================================
python parry.py check src/ --provider gemini  # Uses GEMINI_API_KEY directly
python parry.py check src/ --provider claude  # Uses ANTHROPIC_API_KEY directly
python parry.py check src/ --provider codex   # Uses OPENAI_API_KEY directly
python parry.py check src/ --provider ollama  # Uses 100% local Ollama (OLLAMA_HOST)

# ==============================================================================
# WEB3 PROTOCOL TRIAGE & PROSPECTING
# ==============================================================================
python parry.py triage <github_url>       # Shallow-clone, scan, and emit Markdown report
python parry.py prospect --query "solana" # Auto-discover and triage public repositories
```

---

## 9. Integration Directives for Autonomous AI Agents

When acting as an AI pair programmer, agentic engineer, or automated CI worker:
1. **Zero Hallucinated Imports:** Before adding any `import` or `use` statement, verify the dependency exists in `package-lock.json`, `Cargo.lock`, `pyproject.toml`, or `uv.lock`.
2. **Zero Code Truncation:** Never emit comments like `// ... rest of code` or `# ... existing code`. Always output full, valid syntax.
3. **Run Parry Before Completion:** After modifying Python, TypeScript, JavaScript, Rust, or Solidity files, run `python parry.py check .` or call the `parry_verify_code` MCP tool.
4. **Fix All AST Errors:** If Parry flags any finding with severity `error` or `warning`, apply the suggested fix before declaring the task complete.
