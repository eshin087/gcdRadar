/**
 * What the check scripts share for the live layer (lib/live/shape.ts): a
 * record no built page exists for, and the pieces of a stubbed sweep file.
 * The page fetches "<Worker>/v1/live/<name>"; scripts/lib/browser.mjs
 * stubHost answers it from here.
 */

export const WORKER = "gcd-ai-radar-internet.eshin087.workers.dev";
export const LIVE_VERSION = 3;
export const FRESH_SLUG = "check-script-fresh-record";
export const FRESH_SOURCE = "https://example.com/check-script-fresh-record";
const DAY_MS = 86_400_000;

/** A sweep three minutes ago, with a fresh list that reaches back past the build: the file the page should swap in. */
export function sweepHead(builtSweep, now = Date.now()) {
  const sweep = new Date(now - 3 * 60_000).toISOString();
  return { v: LIVE_VERSION, sweep, fresh_since: new Date(Math.min(now - 3 * DAY_MS, Date.parse(builtSweep) - 1000)).toISOString() };
}

/** A record created a minute before the sweep: newer than any build, so it has no page. */
export function freshRecord(sweep) {
  const created = new Date(Date.parse(sweep) - 60_000).toISOString();
  return {
    slug: FRESH_SLUG,
    id: "AIR-2026-9999",
    title: "Check script: a record newer than the build",
    summary: "A record the check script made up, created after the site was built, so no page exists for it. The page must open it in a drawer and never link to a missing page.",
    action: "Nothing to do: this record exists only inside the check.",
    lane: "patch",
    severity: 4,
    patch_status: "unpatched",
    cvss: 9.8,
    cve_ids: ["CVE-2026-999999"],
    products: ["Check"],
    first_reported: created.slice(0, 10),
    created_at: created,
    sources: [{ publisher: "Example", title: "The made-up primary source", url: FRESH_SOURCE }],
  };
}

/** The sweep labels, by where they sit (the page's own inside <main>, the site header's above it): text, the sweep named, the state. */
export const READ_LABELS = `(() => Object.fromEntries([...document.querySelectorAll('[data-sweep-state]')].map((e) => [e.closest('main') ? 'page' : 'header', { text: e.textContent.trim(), sweep: e.dataset.sweep, state: e.dataset.sweepState, title: e.title }])))()`;

/** Where the made-up record's links lead, whether any still points at its missing page, and what a click on the first one does. */
export const CLICK_FRESH = `async (slug) => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const before = location.pathname;
  const marked = [...document.querySelectorAll('a[data-fresh-slug="' + slug + '"]')];
  const res = {
    links: marked.length,
    hrefs: [...new Set(marked.map((a) => a.getAttribute('href')))],
    newTab: marked.every((a) => a.target === '_blank'),
    toMissingPage: document.querySelectorAll('a[href^="/incidents/' + slug + '"]').length,
  };
  if (!marked.length) return res;
  marked[0].dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }));
  for (let i = 0; i < 40 && !document.querySelector('[role="dialog"] [data-fresh-record]'); i++) await sleep(100);
  const d = document.querySelector('[role="dialog"] [data-fresh-record]');
  res.drawer = d ? { slug: d.dataset.freshRecord, title: d.querySelector('h2')?.textContent ?? '', sources: [...d.querySelectorAll('ol a')].map((a) => a.getAttribute('href')), pageLinks: d.querySelectorAll('a[href^="/incidents/"]').length } : null;
  res.stayed = location.pathname === before;
  window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
  await sleep(250);
  res.closed = !document.querySelector('[role="dialog"]');
  return res;
}`;
