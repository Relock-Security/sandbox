#!/usr/bin/env node
// index.mjs — Relock session-replay harness (terminal UI + flow)
// The security-relevant logic lives in ./attacks.mjs — read that file.

import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { chromium } from 'playwright';
import { TIERS, capture, summarize, replay } from './attacks.mjs';

const SANDBOX_URL = 'https://relock.security';
const RESULTS_FILE = './relock-assessment.json';

// ── tiny ANSI helpers (no dependencies, so the file stays auditable) ──
const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  cyan: '\x1b[36m', green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', gray: '\x1b[90m',
};
const RULE = '─'.repeat(68);
const rl = readline.createInterface({ input, output });

const out = (s = '') => output.write(s + '\n');
const title = (s) => { out(); out(C.bold + '  ' + s + C.reset); out('  ' + C.gray + RULE + C.reset); };
const body = (s) => out(s.split('\n').map((l) => '  ' + l).join('\n'));
const pause = async (msg = 'Press Enter') => { await rl.question('\n  ' + C.dim + msg + C.reset + ' '); };
const ask = async (q) => (await rl.question('  ' + q + ' ')).trim();

// ── results (local only — nothing is ever sent) ──
function record(entry) {
  let all = [];
  if (existsSync(RESULTS_FILE)) { try { all = JSON.parse(readFileSync(RESULTS_FILE, 'utf8')); } catch (e) {} }
  all.push({ at: new Date().toISOString(), ...entry });
  writeFileSync(RESULTS_FILE, JSON.stringify(all, null, 2));
}

async function main() {
  // ── Screen 0 ──
  title('relock-harness                                                 v0.1');
  body(`A session-replay test harness.

It does what an attacker does after they steal a session: it copies the
material a browser holds once you're logged in, loads it into a separate
browser, and tries to use it.

Two things it does NOT do:
 ${C.green}•${C.reset} It never handles your password. You log in yourself, in a window it
   opens — your credentials go straight to the app, never through this
   harness. It only touches what exists ${C.bold}after${C.reset} login.
 ${C.green}•${C.reset} It sends nothing anywhere. Everything runs on this machine.

You'll run up to three attacks, T1 → T3, each more thorough than the last.`);
  await pause('Press Enter to begin');

  let browser = null;
  let outerQuit = false;

  // Clean up the launched browser if the user interrupts mid-run.
  process.on('SIGINT', async () => {
    try { if (browser) await browser.close(); } catch (e) {}
    out('\n  ' + C.dim + 'Interrupted — browser closed.' + C.reset);
    process.exit(130);
  });

  while (!outerQuit) {
    // ── Screen 1: target ──
    title('Target application');
    body('Which app should we test?\n\nEnter a URL, or press Enter for the default.');
    out();
    body(`${C.dim}default →${C.reset} ${SANDBOX_URL}   ${C.dim}(the Relock sandbox)${C.reset}`);
    let target = await ask('›');
    if (!target) target = SANDBOX_URL;
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

    const isSandbox = new URL(target).host.includes('relock.security');
    out();
    if (isSandbox) {
      body(`Target: ${C.bold}${target}${C.reset}\n${C.green}This is a Relock-protected app — expect every attack to be blocked.${C.reset}`);
    } else {
      body(`Target: ${C.bold}${target}${C.reset}\n${C.yellow}This is your app. The results may vary depending on the security and\nobservability measures in place. Use the Relock self-assessment dashboard\nto easily capture and compare them (available at: https://relock.security/self-assessment).${C.reset}\n\n${C.dim}You should only use this harness on applications and accounts that you\nown, control, and have permission to test. Relock does not take\nresponsibility for illegitimate use.${C.reset}`);
    }

    // launch one browser; the logged-in window is kept open across tiers
    if (!browser) {
      try {
        browser = await chromium.launch({ headless: false });
      } catch (err) {
        if (/Executable doesn't exist|playwright install/i.test(err.message)) {
          out('\n  ' + C.red + "Chromium isn't installed yet." + C.reset);
          out('  Run this once, then start the harness again:\n');
          out('    ' + C.cyan + 'npx playwright install chromium' + C.reset + '\n');
          rl.close();
          process.exit(1);
        }
        throw err;
      }
    }
    let victimCtx = null;
    let victimPage = null;
    let loggedIn = false;

    let changeTarget = false;
    while (!changeTarget && !outerQuit) {
      // ── Screen 2: choose attack ──
      title('Choose an attack');
      for (const k of ['T1', 'T2', 'T3']) {
        const t = TIERS[k];
        body(`${C.bold}${t.id}${C.reset}  ${t.name.padEnd(22)} ${C.dim}${t.blurb}${C.reset}`);
      }
      out();
      body('Each tier defeats a defense the one before it could not. Run them in order\nto test the progressive response of your security measures.');
      const choice = (await ask('\n  Type T1, T2 or T3   ·   c change target   ·   q quit\n  ›')).toUpperCase();

      if (choice === 'Q') { outerQuit = true; break; }
      if (choice === 'C') { changeTarget = true; break; }
      if (!TIERS[choice]) { body(`${C.red}Unknown option.${C.reset}`); continue; }
      const tier = TIERS[choice];

      // ── Screen 3: log in (once per target) ──
      if (!loggedIn) {
        title(`${tier.id} · ${tier.name}`);
        body(`Opening a browser window now.

Log in there, exactly as you normally would. Your credentials never reach
this harness — you're authenticating directly with the app.

When you're fully logged in and can see your account, come back here and
press Enter.`);
        victimCtx = await browser.newContext();
        victimPage = await victimCtx.newPage();
        await victimPage.goto(target, { waitUntil: 'domcontentloaded' }).catch(() => {});
        await pause('Press Enter once you are logged in');
        loggedIn = true;
      }

      // ── Screen 4: capture ──
      title('Capturing session material…');
      const loot = await capture(victimPage, victimCtx, tier.id);
      body('Copied from your logged-in browser:\n');
      for (const line of summarize(loot)) body('  ' + C.cyan + '• ' + line + C.reset);
      await pause('Press Enter to replay this material from a different, fresh browser');

      // ── Screen 5: replay ──
      title('Replaying…');
      body(`Opening a second, clean browser — a different "device" with none of your
material — injecting what was stolen, and navigating to the target.`);
      if (tier.id === 'T3') body(`${C.dim}The fresh browser is also spoofed to match your captured fingerprint.${C.reset}`);
      body(`
This attacker runs on your machine, so it shares your IP — deliberately.
That removes the network as a variable and isolates one question: does the
stolen session work somewhere it shouldn't?`);
      const res = await replay(browser, target, loot);

      // ── Screen 6: result ──
      title('Result');
      const hint = `${C.dim}Signal: ${res.finalUrl}${C.reset}`;
      if (isSandbox) {
        body(`Attacker window: ${C.green}${C.bold}REJECTED${C.reset} ${C.green}(expected).${C.reset}\n${hint}`);
        record({ target, tier: tier.id, mode: 'sandbox', outcome: 'blocked', finalUrl: res.finalUrl });
      } else {
        body(`Inspect the attacker window now. ${C.dim}(hint below — confirm by eye)${C.reset}\n${hint}`);
        const reached = (await ask(`\n  Did the attacker window reach your account? ${C.dim}[y/n]${C.reset}`)).toLowerCase().startsWith('y');
        out();
        if (reached) {
          body(`Attacker window: ${C.red}${C.bold}LOGGED IN AS YOU.${C.reset}`);
          record({ target, tier: tier.id, mode: 'self-test', outcome: 'SUCCEEDED', finalUrl: res.finalUrl });
        } else {
          body(`Attacker window: rejected.`);
          record({ target, tier: tier.id, mode: 'self-test', outcome: 'blocked', finalUrl: res.finalUrl });
        }
        body(`\n${C.dim}Recorded to ${RESULTS_FILE} — local only, nothing sent.${C.reset}`);
      }

      await pause('Press Enter to reset and run another tier');

      // ── Screen 7: reset ──
      await res.attacker.close();
      title('Reset complete — attacker window closed.');
      body('Run another tier, change target, or quit (next screen).');
    }

    // changing target: tear down the victim/browser session
    if (changeTarget) { try { await browser.close(); } catch (e) {} browser = null; }
  }

  // ── Exit ──
  title('Done.');
  body(`Results saved locally to ${RESULTS_FILE} — nothing was sent.

Next:
 ${C.cyan}›${C.reset} See it in a live app          →  https://relock.security
 ${C.cyan}›${C.reset} See how the industry held up  →  https://relock.security/session-security-report-2026
 ${C.cyan}›${C.reset} Take it to your team          →  ${RESULTS_FILE}   ${C.dim}(on your machine)${C.reset}`);
  out();
  try { if (browser) await browser.close(); } catch (e) {}
  rl.close();
}

main().catch((err) => { console.error('\n  ' + C.red + 'Error: ' + err.message + C.reset); process.exit(1); });
