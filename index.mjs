#!/usr/bin/env node
// index.mjs — Relock session-replay harness (terminal UI + flow)
// The security-relevant logic lives in ./attacks.mjs — read that file.

import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { writeFileSync, readFileSync, existsSync, unlinkSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';
import { TIERS, capture, captureForExport, summarize, replay, sliceLoot, deviceFromCapture } from './attacks.mjs';
import { pickDevice } from './fingerprints.mjs';

const SANDBOX_URL = 'https://relock.security';

// Write exports somewhere findable: the Desktop if it exists, else the
// directory the harness was launched from (matters under `npx`).
const OUT_DIR = (() => {
  const desktop = path.join(os.homedir(), 'Desktop');
  try { if (existsSync(desktop)) return desktop; } catch (e) {}
  return process.cwd();
})();

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

// The three attack scenarios, worded identically for the intro and the picker.
const tierLines = () => [
  `${C.bold}Tier 1: Cookie replay${C.reset} — ${TIERS.T1.blurb}`,
  `${C.bold}Tier 2: Session hijacking${C.reset} — ${TIERS.T2.blurb}`,
  `${C.bold}Tier 3: Identity impersonation (IMPaaS)${C.reset} — ${TIERS.T3.blurb}`,
];

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

function tierPicker() {
  title('Choose an attack');
  for (const l of tierLines()) body(l);
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
      body(`Target: ${C.bold}${target}${C.reset}   ${C.dim}(a Relock-protected app)${C.reset}`);
    } else {
      body(`Target: ${C.bold}${target}${C.reset}\n${C.yellow}Use only on applications and accounts you own, control, and have permission to test.${C.reset}`);
    }

    let victimCtx = null, victimPage = null, loggedIn = false, changeTarget = false;
    while (!changeTarget && !quit) {
      tierPicker();
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
      body(`Attacker device: ${C.bold}${device ? device.label : 'this machine (native)'}${C.reset}`);
      if (device) {
        body(`\n${C.dim}Note: The attacker browser uses a synthetic fingerprint above, but still\nshares this machine's IP and automation profile. See the README for removing\nthose confounds in deeper testing.${C.reset}`);
      } else {
        body(`\n${C.dim}Note: The attacker browser uses this machine's native fingerprint, and shares\nits IP and automation profile. See the README for removing those confounds in\ndeeper testing.${C.reset}`);
      }
      const res = await replay(browser, target, loot, device);
      body(`\nInspect the attacker window now.   ${C.dim}${target}${C.reset}`);
      await pause('Press Enter to run another tier');
      await res.attacker.close();
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
    const host = (() => { try { return new URL(target).host.replace(/[^a-zA-Z0-9.-]/g, '_'); } catch { return 'export'; } })();
    const dest = path.join(OUT_DIR, `relock-export-${host}.json`);
    out();
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
    body(`Session material written to:\n${C.bold}${dest}${C.reset}\n\nThis one file covers all three tiers — choose the tier on the import side.\n\nNext:\n ${C.cyan}›${C.reset} Move this file to your second machine over a trusted channel.\n ${C.cyan}›${C.reset} There: run the harness → Two machines → Import side → choose the file.\n ${C.cyan}›${C.reset} Delete the file when you're done.`);
    again = (await ask('\n  Export another app? [y/n]')).toLowerCase().startsWith('y');
  }
  try { await browser.close(); } catch (e) {}
}

// List export bundles we can see (Desktop first, then the launch dir).
function listExports() {
  const seen = new Set(); const list = [];
  for (const dir of [OUT_DIR, process.cwd()]) {
    let files = [];
    try { files = readdirSync(dir).filter((f) => /^relock-export.*\.json$/.test(f)); } catch (e) {}
    for (const f of files) { const full = path.join(dir, f); if (!seen.has(full)) { seen.add(full); list.push(full); } }
  }
  return list;
}

// ── TWO-MACHINE: IMPORT SIDE ────────────────────────────────────────────────
async function importSide() {
  title('Import side — replay a captured session');
  const found = listExports();
  if (found.length) {
    body('Export files I can see:\n');
    found.forEach((f, i) => body(`  ${C.bold}${i + 1}${C.reset}  ${f}`));
    out();
  } else {
    body(`${C.dim}No export files found on the Desktop or here. Drop one in below.${C.reset}\n`);
  }
  const ans = await ask(`Drop the export file here (or paste its path)${found.length ? ', or type its number' : ''}:\n  ›`);
  let filePath = ans;
  const n = parseInt(ans, 10);
  if (found.length && Number.isInteger(n) && n >= 1 && n <= found.length) filePath = found[n - 1];
  filePath = filePath.replace(/^['"]|['"]$/g, '').trim();
  if (!filePath) { body(`${C.red}Nothing selected.${C.reset}`); return; }
  if (!existsSync(filePath)) { body(`${C.red}No file at ${filePath}.${C.reset}`); return; }

  let bundle;
  try { bundle = JSON.parse(readFileSync(filePath, 'utf8')); }
  catch (e) { body(`${C.red}Couldn't parse ${filePath}: ${e.message}${C.reset}`); return; }
  if (!bundle.cookies && !bundle.localStorage) { body(`${C.red}That file doesn't look like a Relock export.${C.reset}`); return; }

  const target = bundle.target || bundle.origin;
  out();
  body(`Loaded: ${C.bold}${bundle.origin}${C.reset}   ${C.dim}captured ${bundle.exportedAt || 'unknown time'}${C.reset}`);
  if (!isSandboxUrl(target)) body(`${C.yellow}Replay only against accounts you own and are authorized to test.${C.reset}`);

  const browser = await launch();
  let quit = false;
  while (!quit) {
    tierPicker();
    const choice = (await ask('\n  Type T1, T2 or T3   ·   q quit\n  ›')).toUpperCase();
    if (choice === 'Q') { quit = true; break; }
    if (!TIERS[choice]) { body(`${C.red}Unknown option.${C.reset}`); continue; }
    const tier = TIERS[choice];
    const loot = sliceLoot(bundle, tier.id);
    const device = tier.id === 'T3' ? deviceFromCapture(bundle.fingerprint) : null;

    title('Replaying…');
    body(`Attacker device: ${C.bold}${tier.id === 'T3' ? "victim's captured fingerprint, spoofed onto this machine" : 'this machine (its own native fingerprint)'}${C.reset}`);
    if (tier.id === 'T3') {
      body(`\n${C.dim}Note: a Playwright-grade fingerprint spoof — strong device intelligence may\nflag it. The replay is also automation-driven. See the README.${C.reset}`);
    } else {
      body(`\n${C.dim}Note: the replay is automation-driven, which some bot defenses detect. See\nthe README.${C.reset}`);
    }
    const res = await replay(browser, target, loot, device);
    body(`\nInspect the attacker window now.   ${C.dim}${target}${C.reset}`);
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
  title('relock-harness                                                 v0.3');
  body(`A session-replay harness. It simulates three real-world attack scenarios:\n`);
  for (const l of tierLines()) body(l);
  body(`\nImportant considerations before you start:\n ${C.green}•${C.reset} It never handles your password — you log in yourself.\n ${C.green}•${C.reset} It sends nothing anywhere. Everything runs on your machine(s).\n ${C.green}•${C.reset} To record your results, use our tool at https://relock.security/self-assessment`);
  await pause('Press Enter to begin');

  title('How are you testing?');
  body(`${C.bold}1${C.reset}  One machine\n   ${C.dim}Capture and replay on this computer in a fresh browser instance. T1 and T2\n   will use a synthetic attacker's fingerprint to look like a different device.\n   T3 matches your fingerprint natively.${C.reset}\n\n${C.bold}2${C.reset}  Two machines\n   ${C.dim}Capture on one computer, replay on another (via a file import). T1 and T2\n   more faithful to real-world conditions, as there is a real second device.\n   T3 passes your device's fingerprint.${C.reset}\n\n${C.dim}Recommended mix: T1/T2 two-machine (most realistic), T3 one-machine.${C.reset}`);
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

  title('Explore Relock resources about how to stop attacks on an active session.');
  body(` ${C.cyan}›${C.reset} See Relock defenses live          →  https://sandbox.relock.security\n ${C.cyan}›${C.reset} See how the industry held up       →  https://relock.security/session-security-report-2026\n ${C.cyan}›${C.reset} Conduct a deeper self-assessment   →  https://relock.security/self-assessment`);
  out();
  try { if (activeBrowser) await activeBrowser.close(); } catch (e) {}
  rl.close();
}

main().catch((err) => { console.error('\n  ' + C.red + 'Error: ' + err.message + C.reset); process.exit(1); });
