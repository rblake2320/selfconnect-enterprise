# SelfConnect - Gemini Real-Agent Auth Blocker

**Date:** 2026-06-21  
**Verdict:** BLOCKED by provider authentication  
**Scope:** Gemini CLI participation in real-agent ladder tests.

## Command

```powershell
$env:CI='true'
gemini -p "Return exactly: SELFCONNECT_GEMINI_AUTH_CHECK_OK" --approval-mode yolo --skip-trust
```

## Result

Gemini CLI returned exit code `1` and reported:

```text
FatalAuthenticationError: Manual authorization is required but the current session is non-interactive.
Please run the Gemini CLI in an interactive terminal to log in, provide a GEMINI_API_KEY, or ensure Application Default Credentials are configured.
```

## Boundary

This is not a SelfConnect transport failure. It prevents Gemini from joining the real-agent ladder because the provider CLI cannot start non-interactively without one of:

- an interactive Gemini login already completed for this Windows user,
- `GEMINI_API_KEY`, or
- Google Application Default Credentials.

Codex and Claude real-agent ladders remain valid; Gemini remains excluded until the provider auth condition is fixed.
