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

## Fresh Recheck

Rechecked on 2026-06-21 with Gemini CLI `0.46.0` installed.

Command:

```powershell
python experiments\fabric_v2\real_agent_baseline.py --preflight-only --agents 3 --providers codex:1,claude:1,gemini:1 --timeout 90
```

Result:

| Field | Value |
|---|---|
| Run ID | `SC_PROVIDER_PREFLIGHT_20260621_023853` |
| Codex | ready |
| Claude | ready |
| Gemini | `provider_auth_required` |
| `GEMINI_API_KEY` | not present |
| `GOOGLE_APPLICATION_CREDENTIALS` | not present |
| `GOOGLE_CLOUD_PROJECT` | not present |
| `CLOUDSDK_CONFIG` | not present |

No raw provider logs or prompts are included in this evidence file.
