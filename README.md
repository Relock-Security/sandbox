# Relock Harness

A session-replay harness. It simulates three real-world attack scenarios — a stolen session replayed from an attacker's device, and, at the top tier, from a device made to look like yours — and lets you see whether an app stops them.

It is the same engine behind the Relock sandbox and the self-assessment: point it at the sandbox (available at https://sandbox.relock.security) to watch the attacks fail, or at your own app to measure your exposure.

> **Authorized use only.** Run this only against applications and accounts that you own, control, and have permission to test. Relock takes no responsibility for illegitimate use.

## Two guarantees

- **It never handles your password.** The harness opens a browser; *you* log in there, directly with the app. The harness only ever touches what exists after login — the session material — never your credentials.
- **It sends nothing anywhere.** Everything runs on your machine(s). One-machine mode writes nothing to disk. To record and compare results, use the hosted self-assessment tool at `https://relock.security/self-assessment`.

## What it does, in order

1. You give it a target URL (defaults to the Relock sandbox).
2. You pick an attack tier:
   - **T1 — Cookie Replay** — your cookies only, replayed from an attacker's device.
   - **T2 — Session Hijack** — your cookies + `localStorage` + `sessionStorage`, replayed from an attacker's device.
   - **T3 — Identity Impersonation (IMPaaS)** — the same material as T2, replayed from a device that looks like yours.
3. It opens a browser; you log in.
4. It captures the material for that tier — and shows you exactly what it took.
5. It opens a fresh browser with none of your material, injects what was captured, and navigates to the target.
6. You inspect the result. Against a protected app the attacker is rejected; against an unprotected one it lands in your session.
7. Reset and run the next tier.

## Testing modes

The harness offers two testing modes — one entirely local, and one that calls for the use of two different machines:

- **One machine.** Capture and replay on the same computer. T1 and T2 will use a synthetic attacker's fingerprint to look like a different device; T3 matches your fingerprint natively. The trade-off: T1/T2 still carry this machine's real canvas/TLS/IP and Playwright's automation signals, which can trip bot/device detection a real remote attacker wouldn't — so blocks can be false positives.
- **Two machines (manual export / import).** Log in and `captureForExport` on machine A → move the `relock-export-<domain>.json` file to machine B → replay there. On B, T1/T2 use B's *own native* fingerprint (a genuinely different device, no spoof artifacts); T3 spoofs A's captured fingerprint onto B. More faithful T1/T2; the T3 spoof is Playwright-grade, so it may underperform versus a real anti-detect browser against strong device intelligence. **This mode writes live session material to disk** — see the warning below.

**Recommended mix for a rigorous assessment:** run **T1/T2 in two-machine mode** (most realistic remote-attacker conditions) and **T3 in one-machine mode** (a perfect, artifact-free fingerprint match). Each mode is strongest on those tiers.

> **⚠ Two-machine export writes secrets to disk.** The export is a `relock-export-<domain>.json` file written to your Desktop (or the folder you launched from), and it contains live cookies, tokens, and storage — effectively full access to the account you logged into. The harness prints the exact path. One file per domain covers all three tiers (the tier is chosen at import). Use it **only with throwaway accounts created for testing**, move it over a trusted channel, and delete it after import (the import flow lists the export files it finds so you can pick one, and offers to delete it when you're done). It is git-ignored so it can't be committed.

## Install & run

Requires Node 18+.

**Run straight from GitHub (no clone):**

```bash
npx playwright install chromium # first time only — downloads the browser (~150MB)
npx github:Relock-Security/sandbox#v0.3.0
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

## More about attack tiers

The tiers escalate along two axes: how much material is stolen, and how favorable the device conditions are for the attacker. Read them as a **ladder** — the difference between adjacent tiers is what tells you where a defense sits.

| Tier | Scenario | Exfiltrated material | Attacker's device | If attack succeeds | Stopped by |
|---|---|---|---|---|---|
| **T1** | Cookie Replay | Cookies only | Different | Likely no session-level protection | Most session risk signals and above |
| **T2** | Session Hijack | Cookies + `localStorage` + `sessionStorage` | Different | Limited or no device risk-based defenses | Robust device fingerprinting and above |
| **T3** | Identity Impersonation | Same as T2 | Matched | No device binding | Strong session binding only |

**Automation note:** the replay browser is driven by Playwright, which anti-bot systems can detect. A block can therefore mean "caught automation," not "stopped the replay." This affects all three tiers roughly equally, so the **deltas between tiers stay the most reliable signal** even if absolute pass/fail rates are noisy.

## Deeper testing

For a deeper dive into your apps' session security, consider introducing the following steps into the process:

1. **Run the replay manually in a normal browser** (import the cookies/storage by hand) — removes the automation/bot signal that can cause false blocks. Highest value.
2. **Run T1/T2 from a different physical machine** — a real, different device with no spoof artifacts at all.
3. **Run T3 from a different machine** with progressively better device-matching (e.g. an anti-detect browser) — this models real IMPaaS, which is *harder* than the same-machine case here.
4. **Vary the network/egress** (a different location, residential or mobile) to exercise IP/geo and impossible-travel signals. Note the legal/ToS implications of residential proxy services before using them.

*(Two-machine mode automates the export/import handoff for 2–3; manual import into a real browser, step 1, is still the way to remove the automation signal entirely.)*

## Security & data

See [SECURITY.md](SECURITY.md) for exactly what the tool touches, what leaves your machine (nothing, beyond the browser visiting your target — plus, in two-machine mode, the export file you move yourself), and how to report a vulnerability.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Relock Inc.
