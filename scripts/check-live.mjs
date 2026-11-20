#!/usr/bin/env node
/**
 * Checks the live page in a real browser: every counter equals live.json,
 * every lane tab lists as many rows as it says, the lanes sum to the live
 * counter, the AI-only switch keeps only AI rows, each counter link opens an
 * archive view with the same count, the first calendar day opens the records
 * reported that day, the live tags agree with the rows, and no page scrolls
 * sideways on a phone. These loads block the Worker, so the board reads as
 * built. Then the live layer, with the Worker stubbed: a sweep newer than the
 * build replaces the board, the label says when it was checked, a record
 * with no page yet opens in a drawer and never links to the missing page,
 * and with the Worker down the board keeps its snapshot and says its age.
 * Zero dependencies (scripts/lib/browser.mjs).
 *
 *   npm run build
 *   node scripts/check-live.mjs                 # serves ./out on a free port
 *   node scripts/check-live.mjs --url https://gcdradar.vercel.app
 *
 * Options: --dir <out dir>  --browser <chrome or edge executable>  --port <n>  --verbose
 */
import { blockHosts, call, collectErrors, evaluate, launch, navigate, openSite, parseArgs, sleep, stubHost } from "./lib/browser.mjs";
import { CLICK_FRESH, FRESH_SLUG, FRESH_SOURCE, READ_LABELS, WORKER, freshRecord, sweepHead } from "./lib/live-stub.mjs";

const args = parseArgs(process.argv.slice(2));
const verbose = Boolean(args.verbose);
/** The page with the live board: /live since the home page became the statistics desk. */
const PATH = typeof args.path === "string" ? args.path : "/live";
const LIVE_READY = `document.querySelector('[data-live-board][data-live-ready="1"]')`;
const ARCHIVE_READY = `(() => { const s = document.querySelector('[data-archive-status]'); return s && /\\d/.test(s.textContent) && !/loading/.test(s.textContent); })()`;

const checks = [];
function check(name, ok, detail) {
  checks.push({ name, ok, detail });
  if (verbose || !ok) console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? `: ${detail}` : ""}`);
}

async function toggleLane(client, key) {
  const ok = await call(client, `(key) => { const g = document.querySelector('[role="radiogroup"][aria-label="Lane"]'); const b = g && [...g.querySelectorAll('[role="radio"]')].find((x) => x.textContent.trim().toLowerCase().startsWith(key)); if (!b) return false; b.click(); return true; }`, key);
  if (!ok) throw new Error(`no lane tab ${key}`);
  await sleep(250);
  // open every "show N more" so the rows can be counted
  for (let i = 0; i < 10; i++) {
    const more = await evaluate(client, `(() => { const b = [...document.querySelectorAll('[data-live-board] button')].find((x) => /^show \\d+ more$/.test(x.textContent.trim())); if (!b) return false; b.click(); return true; })()`);
    if (!more) break;
    await sleep(150);
  }
}

const ROWS = `[...document.querySelectorAll('[data-live-board] [data-row]')].map((r) => ({ lane: r.dataset.lane, state: r.dataset.state, ai: r.dataset.ai, tags: (r.dataset.tags || "").split(" ").filter(Boolean) }))`;

async function run(client, base) {
  await client.send("Page.enable");
  await client.send("Runtime.enable");
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  const live = await fetch(`${base}/live.json`).then((r) => r.json());
  // the board as built: the live layer (components/live/useLive.ts) gets no answer
  await blockHosts(client, [WORKER]);
  await navigate(client, `${base}${PATH}`, LIVE_READY);

  // counters against live.json
  const counters = await evaluate(client, `Object.fromEntries([...document.querySelectorAll('[data-counter]')].map((e) => [e.dataset.counter, Number(e.dataset.value)]))`);
  for (const [key, expected] of [["live", live.counters.live], ["critical", live.counters.critical], ["unpatched", live.counters.unpatched], ["quiet", live.counters.quiet.days], ["ai", live.counters.ai]]) {
    check(`counter ${key}`, counters[key] === expected, `page ${counters[key]}, live.json ${expected}`);
  }

  // every lane tab lists what it says; the action lanes sum to the live counter
  const byKey = Object.fromEntries(live.boards.map((b) => [b.key, b]));
  const label = { patch: "patch now", breach: "breaches", supply_chain: "supply chain", all: "all", research: "research" };
  let actionSum = 0;
  for (const key of ["patch", "breach", "supply_chain", "all", "research"]) {
    await toggleLane(client, label[key]);
    const rows = await evaluate(client, ROWS);
    const tab = await evaluate(client, `Number((document.querySelector('[role="radiogroup"][aria-label="Lane"] [aria-checked="true"]')?.textContent.match(/(\\d+)\\s*$/) || [])[1])`);
    check(`lane ${key} rows`, rows.length === byKey[key].count && tab === byKey[key].count, `${rows.length} rows, tab ${tab}, live.json ${byKey[key].count}`);
    check(`lane ${key} every row live and in its lane`, rows.every((r) => r.state === "live" && (key === "all" ? ["patch", "breach", "supply_chain"].includes(r.lane) : r.lane === key)));
    if (key !== "all" && key !== "research") actionSum += rows.length;
  }
  check("action lanes sum to the live counter", actionSum === live.counters.live, `${actionSum} vs ${live.counters.live}`);

  // AI only, on the All tab
  await toggleLane(client, "all");
  await evaluate(client, `document.querySelector('[data-live-board] button[aria-pressed]').click()`);
  await sleep(250);
  const aiRows = await evaluate(client, ROWS);
  check("AI only keeps only AI rows", aiRows.every((r) => r.ai === "1") && aiRows.length === live.counters.ai, `${aiRows.length} rows, counter ${live.counters.ai}`);
  await evaluate(client, `document.querySelector('[data-live-board] button[aria-pressed]').click()`);
  await sleep(200);

  // live tags agree with the rows across the four lanes
  const allRows = [];
  for (const key of ["patch", "breach", "supply_chain", "research"]) {
    await toggleLane(client, label[key]);
    allRows.push(...(await evaluate(client, ROWS)));
  }
  for (const t of live.top_tags.slice(0, 5)) {
    const n = allRows.filter((r) => r.tags.includes(t.slug)).length;
    check(`live tag ${t.slug}`, n === t.live, `${n} rows, live.json ${t.live}`);
  }

  // each counter link opens an archive view with the same count
  const links = await evaluate(client, `[...document.querySelectorAll('a[data-counter]')].map((a) => [a.dataset.counter, a.getAttribute('href'), Number(a.dataset.value)])`);
  for (const [key, href, value] of links) {
    await navigate(client, `${base}${href}`, ARCHIVE_READY);
    const status = await evaluate(client, `document.querySelector('[data-archive-status]')?.textContent || ""`);
    const n = Number((status.match(/^([\d,]+)/) || [])[1]?.replace(/,/g, ""));
    check(`counter ${key} opens ${href}`, n === value, `archive "${status.trim()}", counter ${value}`);
  }

  // the first calendar day with a report opens the records first reported that day
  await navigate(client, `${base}${PATH}`, LIVE_READY);
  const day = await evaluate(client, `(() => { const r = document.querySelector('rect[role="button"]'); if (!r) return null; const m = r.getAttribute("aria-label").match(/^(.*?): (\\d+) reported/); return m ? { label: m[1], reported: Number(m[2]) } : null; })()`);
  if (day) {
    await evaluate(client, `document.querySelector('rect[role="button"]').dispatchEvent(new MouseEvent("click", { bubbles: true }))`);
    for (let i = 0; i < 100 && !(await evaluate(client, `location.pathname === "/incidents" && ${ARCHIVE_READY}`)); i++) await sleep(100);
    const status = await evaluate(client, `document.querySelector('[data-archive-status]')?.textContent || ""`);
    const n = Number((status.match(/^([\d,]+)/) || [])[1]?.replace(/,/g, ""));
    check(`calendar day ${day.label} opens its records`, n === day.reported, `archive "${status.trim()}", cell ${day.reported}`);
  } else check("calendar has a clickable day", false, "no rect[role=button]");

  // phones: nothing scrolls sideways
  await client.send("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 2, mobile: true });
  const firstTag = live.top_tags[0]?.slug ?? "rce";
  const firstRow = allRows.length ? await (async () => {
    await navigate(client, `${base}${PATH}`, LIVE_READY);
    return evaluate(client, `document.querySelector('[data-live-board] [data-row] a')?.getAttribute('href')`);
  })() : null;
  for (const p of ["/", PATH, "/incidents", "/tags", `/tags/${firstTag}`, firstRow, "/trends", "/about"].filter(Boolean)) {
    await navigate(client, `${base}${p}`);
    await sleep(400);
    const w = await evaluate(client, `({ scroll: document.documentElement.scrollWidth, inner: window.innerWidth })`);
    check(`no sideways scroll on ${p} at 375px`, w.scroll <= w.inner, `scrollWidth ${w.scroll}, innerWidth ${w.inner}`);
  }
}

/** The live layer on the board: a stubbed sweep with one record, newer than the build. */
async function checkLiveLayer(client, base) {
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  const AGE = "(just now|\\d+ (min|h|d) ago)";
  await blockHosts(client, [WORKER]);
  await navigate(client, `${base}${PATH}`, `${LIVE_READY} && document.querySelector('[data-sweep-state="built"]')`);
  const asBuilt = await evaluate(client, READ_LABELS);
  const builtSweep = asBuilt.page?.sweep;
  const builtLive = await evaluate(client, `Number(document.querySelector('[data-counter="live"]').dataset.value)`);
  check("without the Worker the board's label states the built data's age", asBuilt.page?.state === "built" && new RegExp(`^data from ${AGE}$`).test(asBuilt.page.text) && asBuilt.header?.text === asBuilt.page.text, JSON.stringify(asBuilt));

  const head = sweepHead(builtSweep);
  const fresh = freshRecord(head.sweep);
  const today = head.sweep.slice(0, 10);
  const row = { id: fresh.id, slug: fresh.slug, title: fresh.title, summary: fresh.summary, lane: "patch", type: "not_ai", ai: false, severity: 4, state: "live", patch_status: "unpatched", cvss: 9.8, products: ["Check"], cve_ids: fresh.cve_ids, cve_more: 0, action: fresh.action, since: today, since_precision: "day", first_reported: today, last_update: today, tags: [], disclosed: false };
  const empty = (key, label) => ({ key, label, count: 0, ai: 0, groups: [] });
  const view = {
    now: head.sweep,
    lastUpdated: head.sweep,
    boards: [{ key: "patch", label: "Patch now", count: 1, ai: 0, groups: [{ key: "unpatched", label: "No patch yet", rows: [row] }] }, empty("breach", "Breaches & attacks"), empty("supply_chain", "Supply chain"), empty("research", "Research")],
    counters: { live: 1, critical: 1, unpatched: 1, ai: 0, quiet: { days: 0, longest: null } },
    heatmap: { from: today.slice(0, 7), to: today, cells: {}, max: 0 },
    aiLens: { live: 0, month: today.slice(0, 7), topFamily: null },
    topTags: [],
  };
  let down = false;
  await blockHosts(client, []);
  await stubHost(client, WORKER, (url) => {
    if (url.pathname !== "/v1/live/board.json") return null;
    return down ? { status: 503, body: { error: "the live files are unavailable" } } : { body: { ...head, view, fresh: [fresh] } };
  });
  await navigate(client, `${base}${PATH}`, `${LIVE_READY} && document.querySelector('[data-sweep-state="live"]')`);
  await sleep(400);
  const swapped = await evaluate(client, `({ labels: ${READ_LABELS}, live: Number(document.querySelector('[data-counter="live"]').dataset.value), rows: [...document.querySelectorAll('[data-live-board] [data-row] a')].map((a) => a.dataset.freshSlug ?? a.getAttribute('href')) })`);
  check("a newer sweep: the board's label says when it was checked", swapped.labels.page?.state === "live" && swapped.labels.page.sweep === head.sweep && /^checked \d+ min ago$/.test(swapped.labels.page.text) && swapped.labels.header?.text === swapped.labels.page.text, JSON.stringify(swapped.labels));
  check("a newer sweep: the board is that sweep's", swapped.live === 1 && swapped.rows.includes(FRESH_SLUG), `live counter ${swapped.live}, rows ${swapped.rows.join(" ")}`);
  const clicked = await call(client, CLICK_FRESH, FRESH_SLUG);
  check("a record with no page links its source, never the missing page", clicked.links >= 1 && clicked.toMissingPage === 0 && clicked.hrefs.length === 1 && clicked.hrefs[0] === FRESH_SOURCE && clicked.newTab, JSON.stringify({ links: clicked.links, hrefs: clicked.hrefs, toMissingPage: clicked.toMissingPage }));
  check("a click on it opens the record in a drawer and stays on the board", clicked.drawer?.slug === FRESH_SLUG && clicked.drawer.pageLinks === 0 && clicked.stayed && clicked.closed, JSON.stringify(clicked.drawer));

  down = true;
  await navigate(client, `${base}${PATH}`, `${LIVE_READY} && document.querySelector('[data-sweep-state="built"]')`);
  const kept = await evaluate(client, `({ labels: ${READ_LABELS}, live: Number(document.querySelector('[data-counter="live"]').dataset.value) })`);
  check("the Worker down: the board keeps its snapshot and says its age", kept.labels.page?.state === "built" && kept.labels.page.sweep === builtSweep && kept.live === builtLive, JSON.stringify(kept));
  await stubHost(client, WORKER, null);
  await blockHosts(client, [WORKER]);
}

async function main() {
  const t0 = Date.now();
  const site = await openSite(args);
  const { client, close, exe } = await launch(args.browser);
  const errors = collectErrors(client);
  try {
    await run(client, site.base);
    await checkLiveLayer(client, site.base);
    const failed = checks.filter((c) => !c.ok);
    console.log(`\n${checks.length - failed.length}/${checks.length} live-page checks pass in ${((Date.now() - t0) / 1000).toFixed(1)} s · ${exe.split(/[\\/]/).pop()} · ${site.base}`);
    // a blocked or stubbed Worker request is the check's own doing, not a page error
    const real = errors.filter((e) => !/ERR_BLOCKED_BY_CLIENT|Failed to fetch|NetworkError/.test(e));
    if (real.length) console.log(`page errors (${real.length}):\n  ${[...new Set(real)].slice(0, 10).join("\n  ")}`);
    if (failed.length || real.length) process.exitCode = 1;
  } finally {
    await close();
    site.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
