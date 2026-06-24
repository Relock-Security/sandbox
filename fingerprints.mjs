// fingerprints.mjs
// ─────────────────────────────────────────────────────────────────────────
// A small library of CURATED, internally-consistent desktop device profiles.
//
// Used to make the T1/T2 attacker context look like a *different, plausible
// machine* — so those tiers test whether the stolen material alone is enough,
// without handing the app the victim's own fingerprint.
//
// Coherence is the point: within each profile, the UA, platform, screen,
// WebGL strings, languages, and timezone all agree, the way they would on a
// real device. What we CANNOT make coherent from JavaScript is the canvas /
// WebGL *pixel* hash (it comes from the real GPU) or the TLS/JA3 signature.
// So these profiles defeat naive fingerprinting, not Pro-grade device
// intelligence — which is sufficient for their job here. See README.
//
// The Chrome version is filled in at runtime from the real browser, so the
// UA stays current and consistent with the Chromium actually running.
// ─────────────────────────────────────────────────────────────────────────

const WIN_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome} Safari/537.36';
const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome} Safari/537.36';

export const DEVICES = [
  {
    label: 'Windows 11 · Intel Iris Xe · 1920×1080',
    uaTemplate: WIN_UA, platform: 'Win32', uaPlatform: 'Windows', uaPlatformVersion: '15.0.0',
    languages: ['en-US', 'en'], locale: 'en-US', timezoneId: 'America/New_York',
    screen: { width: 1920, height: 1080 }, viewport: { width: 1920, height: 945 }, deviceScaleFactor: 1,
    hardwareConcurrency: 8, deviceMemory: 8,
    webgl: { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x0000A7A0) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  },
  {
    label: 'Windows 11 · NVIDIA RTX 3060 · 2560×1440',
    uaTemplate: WIN_UA, platform: 'Win32', uaPlatform: 'Windows', uaPlatformVersion: '15.0.0',
    languages: ['en-US', 'en'], locale: 'en-US', timezoneId: 'America/Chicago',
    screen: { width: 2560, height: 1440 }, viewport: { width: 2560, height: 1305 }, deviceScaleFactor: 1,
    hardwareConcurrency: 12, deviceMemory: 16,
    webgl: { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  },
  {
    label: 'Windows 10 · AMD Radeon RX 6600 · 1920×1080',
    uaTemplate: WIN_UA, platform: 'Win32', uaPlatform: 'Windows', uaPlatformVersion: '10.0.0',
    languages: ['en-GB', 'en'], locale: 'en-GB', timezoneId: 'Europe/London',
    screen: { width: 1920, height: 1080 }, viewport: { width: 1920, height: 945 }, deviceScaleFactor: 1,
    hardwareConcurrency: 16, deviceMemory: 16,
    webgl: { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 6600 (0x000073FF) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  },
  {
    label: 'macOS · Apple M1 · 1440×900',
    uaTemplate: MAC_UA, platform: 'MacIntel', uaPlatform: 'macOS', uaPlatformVersion: '14.5.0',
    languages: ['en-US', 'en'], locale: 'en-US', timezoneId: 'America/Los_Angeles',
    screen: { width: 1440, height: 900 }, viewport: { width: 1440, height: 789 }, deviceScaleFactor: 2,
    hardwareConcurrency: 8, deviceMemory: 8,
    webgl: { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)' },
  },
  {
    label: 'macOS · Apple M2 Pro · 1728×1117',
    uaTemplate: MAC_UA, platform: 'MacIntel', uaPlatform: 'macOS', uaPlatformVersion: '14.5.0',
    languages: ['de-DE', 'de', 'en'], locale: 'de-DE', timezoneId: 'Europe/Berlin',
    screen: { width: 1728, height: 1117 }, viewport: { width: 1728, height: 1003 }, deviceScaleFactor: 2,
    hardwareConcurrency: 12, deviceMemory: 16,
    webgl: { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Pro, Unspecified Version)' },
  },
  {
    label: 'Windows 11 · Intel UHD 630 · 1366×768',
    uaTemplate: WIN_UA, platform: 'Win32', uaPlatform: 'Windows', uaPlatformVersion: '15.0.0',
    languages: ['en-US', 'en'], locale: 'en-US', timezoneId: 'America/New_York',
    screen: { width: 1366, height: 768 }, viewport: { width: 1366, height: 641 }, deviceScaleFactor: 1,
    hardwareConcurrency: 4, deviceMemory: 8,
    webgl: { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  },
];

export const pickDevice = () => DEVICES[Math.floor(Math.random() * DEVICES.length)];
