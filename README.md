# Relock Harness

A session-replay test harness. It does exactly what an attacker does **after** they steal a session: it copies the material a browser holds once you're logged in, loads it into a separate, fresh browser, and tries to use it.

It is the same engine behind the Relock sandbox demos and the self-assessment — point it at the sandbox to watch the attacks fail, or at your own app to measure your exposure.

> **Authorized use only.** Run this only against applications and accounts that you own, control, and have permission to test. Relock takes no responsibility for illegitimate use.

## Two guarantees

- **It never handles your password.** The harness opens a browser; *you* log in there, directly with the app. The harness only ever touches what exists after login — the session material — never your credentials.
- **It sends nothing anywhere.** Everything runs on your machine. Results are written only to a local `relock-assessment.json` (on your Desktop, or the folder you launched from if there's no Desktop), and the path is printed when it's written.

## What it does, in order

1. You give it a target URL (defaults to the Relock sandbox).
2. You pick an attack tier:
   - **T1 — Cookie Replay** — your cookies only, replayed from a different-looking device.
   - **T2 — Session Hijack** — all cookies + `localStorage` + `sessionStorage` (the full infostealer dump), from a different-looking device.
   - **T3 — Identity Impersonation** — the same material as T2, replayed from this machine, so the device fingerprint natively matches yours (the IMPaaS case).
3. It opens a browser; you log in.
4. It captures the material for that tier — and shows you exactly what it took.
5. It opens a fresh browser with none of your material, injects what was captured, and navigates to the target.
6. You inspect the result. Against a protected app the attacker is rejected; against an unprotected one it lands in your session.
7. Reset and run the next tier.

## Testing modes

The harness asks, before anything else, how you're testing:

- **One machine (automated).** Capture and replay on the same computer. T1/T2 are scrambled to look like a different, plausible device; T3 runs natively so the fingerprint matches the victim. Fast, fully automated, nothing sensitive written to disk. The trade-off: T1/T2 still carry this machine's real canvas/TLS/IP and Playwright's automation signals, which can trip bot/device detection a real remote attacker wouldn't — so blocks can be false positives.
- **Two machines (export / import).** Log in and `captureForExport` on machine A → move the `relock-export.json` file to machine B → replay there. On B, T1/T2 use B's *own native* fingerprint (a genuinely different device, no spoof artifacts); T3 spoofs A's captured fingerprint onto B. More faithful T1/T2; the T3 spoof is Playwright-grade, so it may underperform versus a real anti-detect browser against strong device intelligence. **This mode writes live session material to disk** — see the warning below.

**Recommended mix for a rigorous assessment:** run **T1/T2 in two-machine mode** (most realistic remote-attacker conditions) and **T3 in one-machine mode** (a perfect, artifact-free fingerprint match). Each mode is strongest on those tiers.

> **⚠ Two-machine export writes secrets to disk.** The export is a timestamped `relock-export-*.json` written to your Desktop (or the folder you launched from), and it contains live cookies, tokens, and storage — effectively full access to the account you logged into. The harness prints the exact path. Use it **only with throwaway accounts created for testing**, move it over a trusted channel, and delete it after import (the import flow offers to, and auto-suggests the newest export file). It is git-ignored so it can't be committed.

## Install & run

Requires Node 18+.

**Run straight from GitHub (no clone):**

```bash
npx github:Relock-Security/sandbox#v0.2.0
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

## Attack tiers

The tiers escalate along two axes: how much material is stolen, and how favorable the device conditions are for the attacker. Read them as a **ladder** — the difference between adjacent tiers is what tells you where a defense sits.

| Tier | Scenario | Exfiltrated material | Device context | A success implies |
|---|---|---|---|---|
| **T1** | Cookie Replay | Cookies only | **Modified** — a different, plausible device | A stolen cookie alone is replayable; no storage- or device-based binding |
| **T2** | Session Hijack | Cookies + `localStorage` + `sessionStorage` | **Modified** — a different, plausible device | The full infostealer dump is replayable; binding isn't tied to where the token is stored (read against T1) |
| **T3** | Identity Impersonation | Same as T2 | **Matched** — the victim's own fingerprint (replayed from the same machine) | No binding survives even a perfect-fingerprint, same-device replay — the easiest case for an attacker |

For T1/T2 the harness presents a randomly chosen, internally-consistent device profile (see `fingerprints.mjs`) so the app sees an *unfamiliar* device — isolating whether the stolen material alone is enough. T3 applies no spoof: it replays from a second browser profile on the same machine, so the device fingerprint natively matches yours.

## How to read a result

- A **T1/T2 success** means the material is replayable from an unfamiliar device — a genuine exposure.
- A **T1/T2 block** may be device- or risk-based detection — but note the spoof is coherent only on the *string* signals (UA, platform, screen, WebGL strings), not the canvas/WebGL *pixel* hash or the TLS/JA3 signature, so a determined fingerprinter can still tell it's the same underlying machine. Treat a block as "something caught a different-looking device," not proof of a specific control.
- **T3 is a lower bound, not a worst case.** Because it runs on the same machine, T3 hands the app a *perfect* fingerprint and a *matched* IP — the easiest possible conditions. So a **T3 success means "vulnerable even to the easy case,"** and a **T3 block is a strong result** (it stopped even a perfect match). A real remote IMPaaS attack on different hardware/network would face *more* friction, not less — this harness never overstates an attacker's success.
- **Automation note:** the replay browser is driven by Playwright, which anti-bot systems can detect. A block can therefore mean "caught automation," not "stopped the replay." This affects all three tiers roughly equally, so the **deltas between tiers stay the most reliable signal** even if absolute pass/fail rates are noisy.

## Deeper testing

To remove the confounds above, in order of impact:

1. **Run the replay manually in a normal browser** (import the cookies/storage by hand) — removes the automation/bot signal that can cause false blocks. Highest value.
2. **Run T1/T2 from a different physical machine** — a real, different device with no spoof artifacts at all.
3. **Run T3 from a different machine** with progressively better device-matching (e.g. an anti-detect browser) — this models real IMPaaS, which is *harder* than the same-machine case here.
4. **Vary the network/egress** (a different location, residential or mobile) to exercise IP/geo and impossible-travel signals. Note the legal/ToS implications of residential proxy services before using them.

*(Two-machine mode automates the export/import handoff for 2–3; manual import into a real browser, step 1, is still the way to remove the automation signal entirely.)*

## Security & data

See [SECURITY.md](SECURITY.md) for exactly what the tool touches, what it records (metadata only — never your session material), what leaves your machine (nothing, beyond the browser visiting your target), and how to report a vulnerability.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Relock Inc.
