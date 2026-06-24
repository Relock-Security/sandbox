#!/usr/bin/env node
// index.mjs — Relock session-replay harness (terminal UI + flow)
// The security-relevant logic lives in ./attacks.mjs — read that file.

import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { writeFileSync, readFileSync, existsSync, unlinkSync, readdirSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';
import { TIERS, capture, captureForExport, summarize, replay, sliceLoot, deviceFromCapture } from './attacks.mjs';
import { pickDevice } from './fingerprints.mjs';

const SANDBOX_URL = 'https://relock.security';

// Write outputs somewhere findable: the Desktop if it exists, else the
// directory the harness was launched from. This matters most under `npx`,
// where the code runs from a temp cache but files should not.
const OUT_DIR = (() => {
  const desktop = path.join(os.homedir(), 'Desktop');
  try { if (existsSync(desktop)) return desktop; } catch (e) {}
  return process.cwd();
})();
const RESULTS_FILE = path.join(OUT_DIR, 'relock-assessment.json');
const newExportPath = () =>
  path.join(OUT_DIR, `relock-export-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
// Find the most recent export file (Desktop first, then cwd) to default the import prompt.
const newestExport = () => {
  let best = null;
  for (const dir of [OUT_DIR, process.cwd()]) {
    let files = [];
    try { files = readdirSync(dir).filter((f) => /^relock-export.*\.json$/.test(f)); } catch (e) {}
    for (const f of files) {
      const full = path.join(dir, f);
      try { const m = statSync(full).mtimeMs; if (!best || m > best.m) best = { full, m }; } catch (e) {}
    }
  }
  return best ? best.full : null;
};

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
const norm = (u) => (/^https?:\/\//i.test(u) ? u : 'https://' + u);
const isSandboxUrl = (u) => { try { return new URL(u).host.includes('relock.security'); } catch { return false; } };

let activeBrowser = null;
process.on('SIGINT', async () => {
  try { if (activeBrowser) await activeBrowser.close(); } catch (e) {}
  out('\n  ' + C.dim + 'Interrupted — browser closed.' + C.reset);
  process.exit(130);
});

async function launch() {
  try { activeBrowser = await chromium.launch({ headless: false }); return activeBrowser; }
  catch (err) {
    if (/Executable doesn't exist|playwright install/i.test(err.message)) {
      out('\n  ' + C.red + "Chromium isn't installed yet." + C.reset);
      out('  Run this once, then start the harness again:\n');
      out('    ' + C.cyan + 'npx playwright install chromium' + C.reset + '\n');
      rl.close(); process.exit(1);
    }
    throw err;
  }
}

function record(entry) {
  let all = [];
  if (existsSync(RESULTS_FILE)) { try { all = JSON.parse(readFileSync(RESULTS_FILE, 'utf8')); } catch (e) {} }
  all.push({ at: new Date().toISOString(), ...entry });
  writeFileSync(RESULTS_FILE, JSON.stringify(all, null, 2));
}

function chooseTierScreen() {
  title('Choose an attack');
  for (const k of ['T1', 'T2', 'T3']) {
    const t = TIERS[k];
    body(`${C.bold}${t.id}${C.reset}  ${t.name.padEnd(22)} ${C.dim}${t.blurb}${C.reset}`);
  }
  out();
  body('Each tier defeats a defense the one before it could not. Run them in order\nto test the progressive response of your security measures.');
}

async function showResult(res, tierId, target, mode) {
  title('Result');
  const hint = `${C.dim}Signal: ${res.finalUrl}${C.reset}`;
  if (isSandboxUrl(target)) {
    body(`Attacker window: ${C.green}${C.bold}REJECTED${C.reset} ${C.green}(expected).${C.reset}\n${hint}`);
    record({ mode, target, tier: tierId, device: res.device, outcome: 'blocked', finalUrl: res.finalUrl });
  } else {
    body(`Inspect the attacker window now. ${C.dim}(hint below — confirm by eye)${C.reset}\n${hint}`);
    const reached = (await ask(`\n  Did the attacker window reach your account? ${C.dim}[y/n]${C.reset}`)).toLowerCase().startsWith('y');
    out();
    if (reached) {
      body(`Attacker window: ${C.red}${C.bold}LOGGED IN AS YOU.${C.reset}`);
      record({ mode, target, tier: tierId, device: res.device, outcome: 'SUCCEEDED', finalUrl: res.finalUrl });
    } else {
      body(`Attacker window: rejected.`);
      record({ mode, target, tier: tierId, device: res.device, outcome: 'blocked', finalUrl: res.finalUrl });
    }
    body(`\n${C.dim}Recorded to ${RESULTS_FILE} — local only, nothing sent.${C.reset}`);
  }
}

// ── ONE-MACHINE MODE ───────────────────────────────────────────────────────
async function oneMachine() {
  const browser = await launch();
  let quit = false;
  while (!quit) {
    title('Target application');
    body(`Which app should we test?\n\nEnter a URL, or press Enter for the default.`);
    out();
    body(`${C.dim}default →${C.reset} ${SANDBOX_URL}   ${C.dim}(the Relock sandbox)${C.reset}`);
    let target = norm((await ask('›')) || SANDBOX_URL);
    out();
    if (isSandboxUrl(target)) {
      body(`Target: ${C.bold}${target}${C.reset}\n${C.green}A Relock-protected app — expect every attack to be blocked.${C.reset}`);
    } else {
      body(`Target: ${C.bold}${target}${C.reset}\n${C.yellow}This is your app. Results vary with the controls in place. Use only on\napplications and accounts you own, control, and have permission to test.${C.reset}`);
    }

    let victimCtx = null, victimPage = null, loggedIn = false, changeTarget = false;
    while (!changeTarget && !quit) {
      chooseTierScreen();
      const choice = (await ask('\n  Type T1, T2 or T3   ·   c change target   ·   q quit\n  ›')).toUpperCase();
      if (choice === 'Q') { quit = true; break; }
      if (choice === 'C') { changeTarget = true; break; }
      if (!TIERS[choice]) { body(`${C.red}Unknown option.${C.reset}`); continue; }
      const tier = TIERS[choice];
      const device = tier.id === 'T3' ? null : pickDevice();

      if (!loggedIn) {
        title(`${tier.id} · ${tier.name}`);
        body(`Opening a browser window now.\n\nLog in there, exactly as you normally would. Your credentials never reach\nthis harness — you're authenticating directly with the app.\n\nWhen you're fully logged in, come back here and press Enter.`);
        victimCtx = await browser.newContext();
        victimPage = await victimCtx.newPage();
        await victimPage.goto(target, { waitUntil: 'domcontentloaded' }).catch(() => {});
        await pause('Press Enter once you are logged in');
        loggedIn = true;
      }

      title('Capturing session material…');
      const loot = await capture(victimPage, victimCtx, tier.id);
      body('Copied from your logged-in browser:\n');
      for (const line of summarize(loot)) body('  ' + C.cyan + '• ' + line + C.reset);
      await pause('Press Enter to replay this material from a different, fresh browser');

      title('Replaying…');
      if (device) {
        body(`Attacker device: ${C.bold}${device.label}${C.reset}\nA different, plausible machine — so the only thing under test is whether the\nstolen ${tier.id === 'T1' ? 'cookie' : 'material'} is enough, not whether your fingerprint matched.`);
      } else {
        body(`Attacker device: ${C.bold}this machine (native)${C.reset}\nA different browser profile on the same computer, so the fingerprint already\nmatches yours — the IMPaaS case, and the easiest condition for an attacker.`);
      }
      body(`\n${C.dim}Note: the attacker shares this machine's IP and automation profile. See the\nREADME for removing those confounds in deeper testing.${C.reset}`);
      const res = await replay(browser, target, loot, device);

      await showResult(res, tier.id, target, 'one-machine');
      await pause('Press Enter to reset and run another tier');
      await res.attacker.close();
      title('Reset complete — attacker window closed.');
      body('Run another tier, change target, or quit (next screen).');
    }
    if (changeTarget) { try { if (victimCtx) await victimCtx.close(); } catch (e) {} }
  }
  try { await browser.close(); } catch (e) {}
}

// ── TWO-MACHINE: EXPORT SIDE ────────────────────────────────────────────────
async function exportSide() {
  const browser = await launch();
  let again = true;
  while (again) {
    title('Export side — capture a session');
    body(`Which app are you capturing? Enter a URL, or press Enter for the default.`);
    out();
    body(`${C.dim}default →${C.reset} ${SANDBOX_URL}`);
    const target = norm((await ask('›')) || SANDBOX_URL);
    out();
    const dest = newExportPath();
    body(`${C.yellow}⚠  This saves live session material — cookies, tokens, storage — to:\n${dest}\nThat file is effectively full access to the account you log into. Use ONLY a\nthrowaway account created for testing, never a real or sensitive one. Move it\nover a trusted channel and delete it when done.${C.reset}`);
    const ok = (await ask('\n  Continue with a test account? [y/n]')).toLowerCase().startsWith('y');
    if (!ok) { again = false; break; }

    title('Log in');
    body(`Opening a browser window. Log in to ${C.bold}${target}${C.reset} with your TEST account.\nYour credentials never reach this harness.\n\nWhen you're logged in, come back here and press Enter.`);
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(target, { waitUntil: 'domcontentloaded' }).catch(() => {});
    await pause('Press Enter once you are logged in');

    const bundle = await captureForExport(page, ctx);
    writeFileSync(dest, JSON.stringify(bundle, null, 2));
    await ctx.close();

    title('Exported.');
    body(`Session material written to:\n${C.bold}${dest}${C.reset}\n\nNext:\n ${C.cyan}›${C.reset} Move this file to your second machine over a trusted channel.\n ${C.cyan}›${C.reset} There: run the harness → Two machines → Import side → point it at the file.\n ${C.cyan}›${C.reset} Delete the file when you're done.`);
    again = (await ask('\n  Export another app? [y/n]')).toLowerCase().startsWith('y');
  }
  try { await browser.close(); } catch (e) {}
}

// ── TWO-MACHINE: IMPORT SIDE ────────────────────────────────────────────────
async function importSide() {
  title('Import side — replay a captured session');
  const guess = newestExport();
  const promptDefault = guess || path.join(OUT_DIR, 'relock-export.json');
  const filePath = (await ask(`Path to the export file ${C.dim}[${promptDefault}]${C.reset}\n  ›`)) || promptDefault;
  if (!existsSync(filePath)) { body(`${C.red}No file at ${filePath}.${C.reset}`); return; }
  let bundle;
  try { bundle = JSON.parse(readFileSync(filePath, 'utf8')); }
  catch (e) { body(`${C.red}Couldn't parse ${filePath}: ${e.message}${C.reset}`); return; }
  if (!bundle.cookies && !bundle.localStorage) { body(`${C.red}That file doesn't look like a Relock export.${C.reset}`); return; }

  const target = bundle.target || bundle.origin;
  out();
  body(`Loaded: ${C.bold}${bundle.origin}${C.reset}   ${C.dim}captured ${bundle.exportedAt || 'unknown time'}${C.reset}`);
  if (isSandboxUrl(target)) body(`${C.green}A Relock-protected app — expect every attack to be blocked.${C.reset}`);
  else body(`${C.yellow}Replay only against accounts you own and are authorized to test.${C.reset}`);

  const browser = await launch();
  let quit = false;
  while (!quit) {
    chooseTierScreen();
    const choice = (await ask('\n  Type T1, T2 or T3   ·   q quit\n  ›')).toUpperCase();
    if (choice === 'Q') { quit = true; break; }
    if (!TIERS[choice]) { body(`${C.red}Unknown option.${C.reset}`); continue; }
    const tier = TIERS[choice];
    const loot = sliceLoot(bundle, tier.id);
    const device = tier.id === 'T3' ? deviceFromCapture(bundle.fingerprint) : null;

    title('Replaying…');
    if (tier.id === 'T3') {
      body(`Attacker device: ${C.bold}victim's captured fingerprint, spoofed onto this machine${C.reset}\nThe IMPaaS case across real machines. ${C.dim}Note: this is a Playwright-grade\nspoof — weaker than a purpose-built anti-detect browser, so strong device\nintelligence may catch it where a real top-tier operator would not.${C.reset}`);
    } else {
      body(`Attacker device: ${C.bold}this machine (its own native fingerprint)${C.reset}\nA genuinely different device from the victim — the faithful "remote attacker\nwith stolen ${tier.id === 'T1' ? 'cookies' : 'material'}" case.`);
    }
    const res = await replay(browser, target, loot, device);
    await showResult(res, tier.id, target, 'two-machine');
    await pause('Press Enter to run another tier');
    await res.attacker.close();
  }
  try { await browser.close(); } catch (e) {}

  if (existsSync(filePath)) {
    const del = (await ask(`\n  Delete the export file (${filePath}) now? ${C.dim}[y/n]${C.reset}`)).toLowerCase().startsWith('y');
    if (del) { try { unlinkSync(filePath); body(`${C.dim}Deleted.${C.reset}`); } catch (e) {} }
  }
}

// ── MAIN ─────────────────────────────────────────────────────────────────
async function main() {
  title('relock-harness                                                 v0.2');
  body(`A session-replay test harness. It does what an attacker does after they steal\na session: it copies the material a browser holds once you're logged in, loads\nit into a separate browser, and tries to use it.\n\n ${C.green}•${C.reset} It never handles your password — you log in yourself.\n ${C.green}•${C.reset} It sends nothing anywhere. Everything runs on your machine(s).`);
  await pause('Press Enter to begin');

  title('How are you testing?');
  body(`${C.bold}1${C.reset}  One machine ${C.dim}— capture and replay on this computer. Fast, fully automated.${C.reset}\n   ${C.dim}T1/T2 are scrambled to look like a different device; T3 matches natively.${C.reset}\n\n${C.bold}2${C.reset}  Two machines ${C.dim}— capture on one computer, replay on another (via a file).${C.reset}\n   ${C.dim}More faithful T1/T2 (a real second device); writes session material to disk.${C.reset}\n\n${C.dim}Recommended mix: run T1/T2 two-machine (most realistic) and T3 one-machine\n(cleanest fingerprint match). See the README.${C.reset}`);
  const mode = (await ask('\n  Type 1 or 2  ·  q quit\n  ›')).toLowerCase();

  if (mode === '1') {
    await oneMachine();
  } else if (mode === '2') {
    title('Two-machine mode');
    body(`Is this the machine where you'll log in, or the one where you'll replay?\n\n${C.bold}e${C.reset}  Export side  ${C.dim}— log in here; save the session material to a file.${C.reset}\n${C.bold}i${C.reset}  Import side  ${C.dim}— load a file captured elsewhere and run the attacks.${C.reset}`);
    const side = (await ask('\n  Type e or i  ·  q quit\n  ›')).toLowerCase();
    if (side === 'e') await exportSide();
    else if (side === 'i') await importSide();
  }

  title('Done.');
  body(`Results (one-machine / import) are saved locally to ${RESULTS_FILE} — nothing sent.\n\nNext:\n ${C.cyan}›${C.reset} See it in a live app          →  https://relock.security\n ${C.cyan}›${C.reset} See how the industry held up  →  https://relock.security/session-security-report-2026\n ${C.cyan}›${C.reset} Take it to your team          →  ${RESULTS_FILE}`);
  out();
  try { if (activeBrowser) await activeBrowser.close(); } catch (e) {}
  rl.close();
}

main().catch((err) => { console.error('\n  ' + C.red + 'Error: ' + err.message + C.reset); process.exit(1); });
