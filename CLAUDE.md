# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`revkit` is a reusable toolkit for **authorized** Android APK reverse-engineering / pentesting engagements. It is not an application with source code to build — it's an analysis pipeline driven by Claude Code slash commands, organized so a new APK can be dropped in and run through the same procedure every time.

Pipeline: **jadx** (Java decompile + triage) → **Ghidra via MCP** (native `.so` analysis) → **Frida** (runtime bypass, scripts only — execution is manual/future phase).

Every analysis assumes scope/NDA authorization is already confirmed (see `docs/`). Treat target binaries and decompiled output as potentially sensitive client data.

## Commands (slash commands, not build tooling)

There is no build/lint/test suite — the "commands" are `.claude/commands/*.md` slash commands that drive the analysis workflow:

| Command | Purpose |
| --- | --- |
| `/rev-check <target>` | Pre-flight check: APK present, jadx/Java versions, Ghidra MCP connectivity |
| `/rev-jadx <target>` | Fully automatic: jadx decompile + Java triage → `triage.md`, `java_analysis.md` |
| `/rev-native <target>` | Ghidra MCP native `.so` analysis (iterates all `.so` targets) → `notes/native/<so>.md` |
| `/rev-report <target>` | Synthesizes all notes → `report.md`, updates `targets/INDEX.md` |
| `/rev-all <target>` | Runs the above in order, pausing only at the Ghidra manual gate |

Key operational rules (enforced by the command definitions themselves, not optional):
- `<target>` is always the folder name under `targets/` (e.g. `scn00`). Slash commands do **not** remember the target across invocations — it must be passed on every call (`/rev-native scn00`, not `/rev-native`).
- `/rev-all <target>` is invoked once; it internally runs check→jadx→native→report. Don't chain `/rev-check` + `/rev-jadx` manually after it.
- The **only manual intervention point** in the whole pipeline is Ghidra: a human must open the target `.so` in Ghidra's CodeBrowser (File → Import, then Analyze) before `/rev-native` can run. `rev-all` stops there and tells the user what to do next.
- `/rev-native` processes `.so` files one at a time, in priority order from `triage.md`'s checklist — whichever `.so` is currently open in CodeBrowser must match the next item in that checklist (verified by function count/symbols before proceeding).
- Only `arm64-v8a` is analyzed — other ABI folders (`armeabi-v7a`, `x86_64`) are duplicate compiles of the same logic and are skipped.

Running jadx directly (what `/rev-jadx` does under the hood):
```
jadx --no-res --no-debug-info -d targets/<target>/jadx-out/ targets/<target>/apk/<file>
```
`--no-res` skips resource decoding (faster, Java-only) but also means `.so` files won't be extracted — Ghidra input comes from `targets/<target>/unpacked/lib/arm64-v8a/` instead (or re-run without `--no-res`). Large multidex APKs that OOM: retry with `JAVA_OPTS=-Xmx4g`.

## Architecture: directory layout and data flow

```
revkit/
├─ .claude/commands/    /rev-* slash commands (the actual "code" of this repo)
├─ .mcp.json            Ghidra MCP connection (local mcp_bridge.exe, port 8765, stdio)
├─ docs/                Full workflow methodology (Korean) — read before changing pipeline behavior
└─ targets/
   ├─ INDEX.md          Cross-target summary table (committed)
   └─ <target>/
      ├─ apk/           original APK (gitignored)
      ├─ unpacked/      extracted APK incl. lib/arm64-v8a/*.so (gitignored)
      ├─ jadx-out/      jadx Java decompile output (gitignored)
      ├─ ghidra/        Ghidra project files (gitignored)
      ├─ frida/         hook scripts (committed)
      └─ notes/         analysis notes (committed) — the only durable output
         ├─ triage.md           loadLibrary/native scan + per-.so priority checklist (pending/done)
         ├─ java_analysis.md   call flow, server I/O, hardcoded secrets
         ├─ native/<so>.md     one file per .so analyzed (never merged)
         └─ report.md          final synthesized report
```

The pipeline is strictly a **one-way data funnel**: each stage's output file is the next stage's required input. `/rev-native` cannot run meaningfully without `triage.md`'s checklist; `/rev-report` reads every `notes/*.md` file that exists. If you're asked to resume or debug a stalled analysis, the `triage.md` checklist's `pending`/`done` status per `.so` is the source of truth for what's left — don't re-derive it from scratch.

`.gitignore` is the actual boundary of what's "safe" here: binaries, decompiled trees, and Ghidra projects are always excluded; only `targets/**/notes/`, `targets/**/frida/`, and `targets/INDEX.md` are committed exceptions. When writing or editing anything under `targets/`, keep that split — never write analysis conclusions outside `notes/`, and never assume a `jadx-out/` or `unpacked/` directory will still exist on a fresh checkout.

## MCP / Ghidra specifics

- Ghidra MCP connects only while **CodeBrowser is open with the target `.so` loaded** — closing it kills the bridge (port 8765 by default for this build, stdio transport via `mcp_bridge.exe`, not HTTP).
- Before trusting `mcp__ghidra__*` results: confirm the currently-open `.so` in CodeBrowser is the one the analysis note claims it is (match function count / symbols) — Ghidra silently keeps whatever was last opened.
- Rename/comment operations write directly to the Ghidra project DB — treat as a mutation requiring the project to already be backed up, and cross-check decompiler inference against the raw Listing/assembly (obfuscated security `.so`s produce plausible-looking wrong pseudocode).
- If `mcp__ghidra__*` tools are missing or return empty function lists, the fix is always on the Ghidra side (CodeBrowser open? Toggle Server on? plugin/bridge version matches Ghidra version?) — not something `/rev-native` can work around.

## Report structure convention

`report.md` (produced by `/rev-report`) always follows: metadata header (app/version/date/target `.so` list) → summary → target-selection rationale (from triage) → Java analysis → native analysis with explicit bypass points (which branch to flip) → next steps (Frida/SSL pinning/repackaging/secrets PoC) → defensive recommendations. Keep new reports in this shape so `targets/INDEX.md` links stay consistent across targets.
