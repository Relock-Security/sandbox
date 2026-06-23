# Relock Harness

A session-replay test harness. It does exactly what an attacker does **after** they steal a session: it copies the material a browser holds once you're logged in, loads it into a separate, fresh browser, and tries to use it.

It is the same engine behind the Relock sandbox demos and the self-assessment — point it at the sandbox to watch the attacks fail, or at your own app to measure your exposure.

> **Authorized use only.** Run this only against applications and accounts that you own, control, and have permission to test. Relock takes no responsibility for illegitimate use.

## Two guarantees

- **It never handles your password.** The harness opens a browser; *you* log in there, directly with the app. The harness only ever touches what exists after login — the session material — never your credentials.
- **It sends nothing anywhere.** Everything runs on your machine. Results are written only to a local `./relock-assessment.json`.

## What it does, in order

1. You give it a target URL (defaults to the Relock sandbox).
2. You pick an attack tier:
   - **T1 — Cookie Replay** — the entire cookie store (pass-the-cookie).
   - **T2 — Session Hijack** — all cookies + `localStorage` + `sessionStorage` (the full infostealer dump).
   - **T3 — Identity Impersonation** — T2 plus your reproduced device fingerprint (the IMPaaS technique).
3. It opens a browser; you log in.
4. It captures the material for that tier — and shows you exactly what it took.
5. It opens a fresh browser with none of your material, injects what was captured, and navigates to the target.
6. You inspect the result. Against a protected app the attacker is rejected; against an unprotected one it lands in your session.
7. Reset and run the next tier.

## Install & run

Requires Node 18+.

**Run straight from GitHub (no clone):**

```bash
npx github:Relock-Security/sandbox#v0.1.0
npx playwright install chromium # first time only — downloads the browser (~150MB)
```

**Or clone and run (recommended if you want to read the source first):**

```bash
git clone https://github.com/Relock-Security/sandbox.git
cd sandbox
npm install                     # installs Playwright + downloads its Chromium
npm start                       # or:  node index.mjs
```

> **Heads-up on install:** `npm install` runs a `postinstall` step that downloads Chromium (~150 MB) through Playwright's own installer. If your environment blocks postinstall scripts (e.g. `npm ci --ignore-scripts`), run `npx playwright install chromium` manually afterward — the harness will also prompt you to if the browser is missing.

## Read before you run

All session-touching logic is in **`attacks.mjs`** — `capture()` and `replay()`, in plain Playwright, fully commented. `index.mjs` is only the terminal flow around it. Read `attacks.mjs` first; there is nothing hidden elsewhere.

## Reading the results

Results depend on the security and observability controls the target app has in place, so a block is not by itself proof of binding-grade protection — it may be a coarser, partial control. The harness only records what happened; to capture results over time and compare them, use the Relock self-assessment dashboard. Note that the attacker runs from your own machine and IP, which removes the network as a variable.

## Security & data

See [SECURITY.md](SECURITY.md) for exactly what the tool touches, what it records (metadata only — never your session material), what leaves your machine (nothing, beyond the browser visiting your target), and how to report a vulnerability.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Relock Inc.
