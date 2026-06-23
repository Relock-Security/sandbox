# Security

## What this tool does with your data

- **Your password is never handled by the harness.** You log in yourself, in a browser window the tool opens; your credentials go directly to the target app and never pass through this code.
- **Nothing is sent anywhere.** The only network activity is (1) Playwright downloading Chromium from Microsoft's CDN at install time, and (2) the browser navigating to the target URL you provide. No data is transmitted to Relock or any third party.
- **No session secrets are written to disk.** Captured cookies, tokens, and web storage exist only in memory for the duration of a run. The local `relock-assessment.json` records only metadata — target, tier, outcome, and the origin + path of the final URL (query strings and fragments are stripped, so URL-borne tokens are not recorded). The stolen material itself is never persisted.
- **Browser sessions are ephemeral.** Each run uses a fresh, in-memory browser context with no persistent profile, so logins and captured material do not survive the process.

All session-touching logic is contained in `attacks.mjs`. Read it before you run the tool.

## Authorized use

Use this only against applications and accounts that you own, control, and have permission to test. You are responsible for ensuring your testing is lawful and authorized.

## Reporting a vulnerability

Please report security issues privately — do not open a public issue.

- Email: hi@relock.security
- Or use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability).
