#!/usr/bin/env node
/**
 * Checks the home page and the web half of /trends in a real browser against
 * the files they were built from.
 *
 * The home page (lib/panel): the hero's three numbers equal
 * /stats/panel.json and /stats/home.json; /stats/stack.json holds the
 * catalog (several hundred candidates, most urgent first, under its size
 * budget); My stack draws only the default products that need action, in
 * that order, each with why and the CVSS score behind it (its meter lit to
 * match, or "no score yet"), counts the rest, names the highest new critical
 * CVEs and opens a product's list; the news opens on the top stories as
 * panel.json ranks them, every row counting and naming the distinct
 * publishers of its own record (read from the record's JSON), the other
 * three tabs list their rows, and a row opens the quick look; Next due
 * leads with the nearest deadline as a countdown, lists the next ones with
 * the time left, CISA's window and the score, and opens every deadline
 * ahead; the week's six facts equal the counters and open their lists; the
 * radar carries the week's exploited records and draws; the hero's block
 * numeral is the KEV counter, lights that digit's cells, names the newest
 * products and opens the week's list; no text is under 12 px; a ?stack=
 * link applies, stores and recomputes the picks (an old key under its new
 * name), the rows drawn and the marks on the deadlines and the news; the
 * chooser lists the picks, the categories and what a search finds; a stack
 * of forty stays compact on a phone; the page is complete with motion on
 * and off; the HTML stays under its budget; nothing scrolls sideways on a
 * phone. These loads block the Worker, so the page reads as built; one more
 * load lets it through and expects either the live marker or the built
 * numbers. Then the live layer, with the Worker stubbed: a sweep newer than
 * the build is swapped in whole, the label says when it was checked and
 * never claims more than the data on screen, a record with no page yet
 * links its source and opens in a drawer, a number opens the list of the
 * same sweep, and with the Worker down or a foreign file the page keeps its
 * snapshot and states that snapshot's age.
 *
 * /trends: the counters, their drawers and the chart columns against
 * /stats/home.json, the radar scope's blips, and the three instruments that
 * moved there from the home page: attack types and the attack surface draw
 * one cell or square per count, the AI flow draws ceil(n / 2) ribbons per
 * role inside its box and the weak link one square per CVE with the
 * exploited ones red.
 *
 * Zero dependencies (scripts/lib/browser.mjs).
 *
 *   npm run build
 *   node scripts/check-home.mjs                 # serves ./out on a free port
 *   node scripts/check-home.mjs --url https://gcdradar.vercel.app
 *
 * Options: --dir <out dir>  --browser <chrome or edge>  --port <n>  --budget <KB, default 250>  --verbose
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { blockHosts, call, collectErrors, evaluate, launch, navigate, openSite, parseArgs, sleep, stubHost } from "./lib/browser.mjs";
import { CLICK_FRESH, FRESH_SLUG, FRESH_SOURCE, READ_LABELS, WORKER, freshRecord, sweepHead } from "./lib/live-stub.mjs";

const args = parseArgs(process.argv.slice(2));
const verbose = Boolean(args.verbose);
const BUDGET_KB = Number(args.budget ?? 250);
const HOME_READY = `document.querySelector('[data-instrument="week"] [data-line]') && document.querySelector('[data-news] li') && document.querySelector('#due')`;
/** The drawer lists' cap (lib/home.ts LIST_CAP). */
const LIST_CAP = 200;
const TRENDS_READY = `document.querySelectorAll('[data-counter]').length >= 6 && document.querySelector('[data-chart="kev-by-month"] rect') && document.querySelector('[data-instrument="ai"][data-built]')`;
const DAY_MS = 86_400_000;
/** The end of a deadline's UTC day. */
const dueEnd = (due) => Date.parse(`${due}T00:00:00Z`) + DAY_MS;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const shortDate = (iso) => `${Number(iso.slice(8, 10))} ${MONTHS[Number(iso.slice(5, 7)) - 1]}`;

const checks = [];
function check(name, ok, detail) {
  checks.push({ name, ok, detail });
  if (verbose || !ok) console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? `: ${detail}` : ""}`);
}

/**
 * Clicks an element, waits for the drawer's list, reads its count line, closes it. A ListDrawer
 * marks its state (components/ui/ListDrawer.tsx): `listed` is true once it shows rows or says it
 * has none, `error` holds a failed fetch's message.
 */
const OPEN_AND_READ = `async (sel, index) => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const all = document.querySelectorAll(sel);
  const el = all[index < 0 ? all.length + index : index];
  if (!el) return { missing: true };
  el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  for (let i = 0; i < 60; i++) {
    const d = document.querySelector('[role="dialog"]');
    if (d && !d.querySelector("[data-loading]") && (d.querySelector("ol > li, [data-empty], [data-error]") || /^0\\s/.test(d.querySelector("p.num")?.textContent ?? ""))) break;
    await sleep(150);
  }
  const d = document.querySelector('[role="dialog"]');
  const head = d?.querySelector("p.num")?.textContent.trim() ?? "";
  const res = {
    label: el.getAttribute("aria-label"),
    head,
    count: Number((head.match(/^(\\d+)\\s/) || [])[1]),
    rows: d ? d.querySelectorAll("ol > li").length : 0,
    listed: Boolean(d?.querySelector("ol > li, [data-empty]")),
    error: d?.querySelector("[data-error]")?.textContent ?? null,
    locked: document.documentElement.style.overflow === "hidden",
  };
  window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
  await sleep(250);
  res.closed = !document.querySelector('[role="dialog"]') && document.documentElement.style.overflow !== "hidden";
  return res;
}`;

async function openAndRead(client, selector, index = 0) {
  return evaluate(client, `(${OPEN_AND_READ})(${JSON.stringify(selector)}, ${index})`);
}

const num = (s) => Number(String(s ?? "").replace(/[^\d.-]/g, "") || NaN);

/** The most /stats/stack.json may weigh, in KB: several hundred candidates, written compactly. */
const STACK_FILE_KB = 160;
const STACK_MAX = 40;

/** A label's slug, the key a candidate has when the file leaves it out (lib/panel/picks.ts stackKey). */
const stackKey = (label) => label.normalize("NFKD").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

/** /stats/stack.json as the page works with it (lib/panel/picks.ts unpackStack): items and critical CVEs out of their tables, quiet fields filled in. */
function unpackStack(wire) {
  const items = wire.items.map(([kind, name, cves, date, due, cvss, open, href]) => ({ kind: kind === 0 ? "kev" : "record", name, cves, date, due: due || null, cvss, open: open || null, href: href || `https://nvd.nist.gov/vuln/detail/${cves[0] ?? ""}` }));
  const crits = wire.crits.map(([id, score, published, name]) => ({ id, score, published, name }));
  const candidates = wire.candidates.map((w) => ({
    key: w.key ?? stackKey(w.label), label: w.label, vendor: w.vendor ?? w.label, cat: wire.cats[w.c], level: w.v ? "vendor" : "product",
    n: w.n ?? 0, flag: w.flag ?? null, due: w.due ?? null, late: w.late ?? null, flagScore: w.fs ?? null, cvss: w.cvss ?? null, crit: w.crit ?? 0, tier: w.tier ?? 5, kev7: w.kev7 ?? [],
    items: (w.it ?? []).map((n) => items[n]), crits: (w.cr ?? []).map((n) => crits[n]), aka: w.aka ?? [], popular: Boolean(w.pop), tail: Boolean(w.tail),
  }));
  return { default: wire.default, aliases: wire.aliases, candidates };
}

/** The one order products are listed in (lib/panel/picks.ts byUrgency). */
function byUrgency(a, b) {
  const deadline = (a.late ?? a.due ?? "9999").localeCompare(b.late ?? b.due ?? "9999");
  const cvss = (b.cvss ?? -1) - (a.cvss ?? -1);
  return a.tier - b.tier || (a.tier === 2 ? deadline || cvss : cvss || deadline) || b.n - a.n || b.crit - a.crit || a.label.localeCompare(b.label, "en", { sensitivity: "base" });
}

/** The KEV additions of the 7 days that belong to the picks, once each (lib/panel/picks.ts stackMatches). */
function stackMatches(file, picks) {
  const out = new Map();
  for (const k of picks) for (const m of file.candidates.find((c) => c.key === k)?.kev7 ?? []) if (!out.has(m.cve)) out.set(m.cve, m);
  return [...out.values()];
}

/** The picks' items by CVE id and link, and the picks a row belongs to (lib/panel/picks.ts stackHits, rowStack). */
function stackHits(file, picks) {
  const hits = { cves: new Map(), hrefs: new Map() };
  const add = (m, key, label) => {
    const labels = m.get(key) ?? [];
    if (!labels.includes(label)) labels.push(label);
    m.set(key, labels);
  };
  for (const k of picks) {
    const c = file.candidates.find((x) => x.key === k);
    for (const it of c?.items ?? []) {
      for (const cve of it.cves) add(hits.cves, cve, c.label);
      add(hits.hrefs, it.href, c.label);
    }
  }
  return hits;
}
function rowStack(hits, row) {
  const out = [];
  for (const cve of row.cves ?? []) for (const l of hits.cves.get(cve) ?? []) if (!out.includes(l)) out.push(l);
  if (row.href) for (const l of hits.hrefs.get(row.href) ?? []) if (!out.includes(l)) out.push(l);
  return out;
}

/** How much of its lists the page shows (lib/panel/caps.ts, lib/panel/news.ts, components/hero/ExploitedWeek.tsx). */
const STACK_ROWS = 9;
const NEXT_DUE_ROWS = 6;
const NEWS_ROWS = 5;
const EXPLOITED_NAMES = 5;

/** The block numeral's digits (components/hero/BlockNumeral.tsx BLOCK_GLYPHS), for counting the cells a number lights. */
const BLOCK_GLYPHS = {
  0: "01110100011000110001100011000101110", 1: "00100011000010000100001000010001110", 2: "01110100010000100010001000100011111", 3: "11110000010000101110000010000111110", 4: "00010001100101010010111110001000010",
  5: "11111100001111000001000011000101110", 6: "00110010001000011110100011000101110", 7: "11111000010001000100010000100001000", 8: "01110100011000101110100011000101110", 9: "01110100011000101111000010001001100",
};
const litCells = (n) => String(n).split("").reduce((s, d) => s + [...BLOCK_GLYPHS[d]].filter((c) => c === "1").length, 0);

/** The products My stack draws: those with something exploited and still open (lib/panel/picks.ts tiers 1 to 3), in the order given. */
const urgentOf = (tiles) => tiles.filter((t) => t.tier <= 3 && t.flag);
const toneOf = (flag) => (!flag ? null : flag.startsWith("patch by ") || flag.startsWith("past due ") ? "due" : flag === "confirmed impact" ? "harm" : flag === "no patch yet" ? "open" : "partial");

/** How much of CISA's window is used (lib/panel/deadlines.ts windowUsed) as the meter's cells. */
function windowCells(r, now) {
  const start = Date.parse(`${r.added}T00:00:00Z`);
  const end = dueEnd(r.due);
  const used = end > start ? Math.min(1, Math.max(0, (now - start) / (end - start))) : 1;
  return Math.max(1, Math.round(used * 10));
}

/** The rows of a news list (lib/panel/news.ts newsList), with the labels a stack gives them. */
function newsList(news, tab, labels = (r) => r.stack) {
  if (tab === "top") return news.top.map((s) => news.rows.find((r) => r.slug === s)).filter(Boolean);
  if (tab === "breaches") return news.rows.filter((r) => r.lane === "breach");
  if (tab === "ai") return news.rows.filter((r) => r.type !== "not_ai");
  return news.rows.filter((r) => labels(r).length > 0);
}

const READ_STACK = `(() => {
  const box = document.querySelector('#stack [data-tiles]');
  const meter = (t) => (t.querySelector('[data-meter]') ? Number(t.querySelector('[data-meter]').dataset.meter) : null);
  return {
    ready: box?.dataset.stack ?? null, tiles: Number(box?.dataset.tiles), urgent: Number(box?.dataset.urgent),
    count: document.querySelector('#stack [data-stack-count]')?.textContent.replace(/\\s+/g, ' ').trim() ?? '',
    calm: Boolean(document.querySelector('#stack [data-stack-calm]')),
    rows: [...document.querySelectorAll('#stack [data-stack-tile]')].filter((t) => t.offsetParent !== null).map((t) => ({
      key: t.dataset.stackTile, n: Number(t.dataset.n), flag: t.dataset.flag, tier: Number(t.dataset.tier), crit: Number(t.dataset.crit),
      score: t.dataset.score === '' ? null : Number(t.dataset.score), shown: t.querySelector('[data-score]')?.textContent.trim() ?? null, none: Boolean(t.querySelector('[data-score-none]')),
      meter: meter(t), badge: t.querySelector('[data-stack-badge]')?.dataset.stackBadge ?? null, words: t.querySelector('[data-stack-badge]')?.textContent.trim() ?? '',
    })),
    crits: { total: Number(document.querySelector('#stack [data-stack-crits]')?.dataset.stackCrits ?? 0), named: [...document.querySelectorAll('#stack [data-stack-crit]')].map((b) => ({ id: b.dataset.stackCrit, text: b.textContent.replace(/\\s+/g, ' ').trim() })) },
  };
})()`;

const READ_NEWS = `(() => {
  const ol = document.querySelector('[data-news]');
  return {
    tab: ol?.dataset.news ?? null, count: Number(ol?.dataset.count), all: document.querySelector('[data-news-all]')?.textContent.replace(/\\s+/g, ' ').trim() ?? '',
    rows: [...(ol?.querySelectorAll('[data-row="news"]') ?? [])].map((r) => ({
      slug: r.dataset.slug, sources: Number(r.dataset.sources), ai: r.dataset.ai, href: r.querySelector('a')?.getAttribute('href') ?? null, title: r.querySelector('a')?.textContent.trim() ?? '',
      by: r.querySelector('[data-news-by]')?.textContent.trim() ?? '', said: r.textContent.replace(/\\s+/g, ' '), stack: r.querySelector('[data-stack-mark]')?.dataset.stackMark ?? '',
      ready: r.querySelector('[data-stack]')?.dataset.stack ?? null, impact: Boolean(r.querySelector('[data-news-impact]')), aiMark: Boolean(r.querySelector('[data-ai-mark]')),
    })),
  };
})()`;

const READ_DUE = `(() => {
  const s = document.querySelector('#due');
  if (!s) return null;
  const row = (r) => {
    const clock = r.querySelector('[data-countdown]');
    return {
      name: r.dataset.name, due: r.dataset.due, clock: clock ? { text: clock.textContent.trim(), shown: getComputedStyle(clock).visibility !== 'hidden' } : null,
      meter: Number(r.querySelector('[data-meter]')?.dataset.meter), score: r.querySelector('[data-score]') ? Number(r.querySelector('[data-score]').dataset.score) : null,
      stack: r.querySelector('[data-stack-mark]')?.dataset.stackMark ?? '', ready: r.querySelector('[data-stack]')?.dataset.stack ?? null, look: r.querySelector('[data-look]')?.dataset.look ?? null,
    };
  };
  const lead = s.querySelector('[data-lead]');
  const big = s.querySelector('[data-big-countdown]');
  return {
    count: Number(s.dataset.count), lead: lead ? { ...row(lead), big: big?.textContent ?? null, bigDue: big?.dataset.bigCountdown ?? null, fix: s.querySelector('[data-due-fix]')?.dataset.dueFix ?? null, fixWords: s.querySelector('[data-due-fix]')?.textContent.trim() ?? '' } : null,
    rows: [...s.querySelectorAll('[data-due-rows] [data-row="due"]')].map(row), more: s.querySelector('[data-due-more]')?.textContent.trim() ?? null,
  };
})()`;

/** Clicks a row's link, waits for the quick look, reads it, closes it. The click can be cancelled, as a real one can: the row's handler does. */
const OPEN_LOOK = `async (sel) => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const el = document.querySelector(sel);
  if (!el) return { missing: true };
  el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
  for (let i = 0; i < 60 && !document.querySelector('[role="dialog"] [data-quicklook-state="ready"], [role="dialog"] [data-quicklook-state="missing"]'); i++) await sleep(150);
  const q = document.querySelector('[role="dialog"] [data-quicklook]');
  const res = { wanted: el.dataset.look ?? null, target: q?.dataset.quicklook ?? null, state: q?.dataset.quicklookState ?? null, title: document.querySelector('[role="dialog"] h2')?.textContent.trim() ?? "", dialogs: document.querySelectorAll('[role="dialog"]').length, path: location.pathname };
  window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
  await sleep(250);
  res.closed = !document.querySelector('[role="dialog"]') && document.documentElement.style.overflow !== "hidden";
  return res;
}`;

async function checkHome(client, base, dir, home, panel, stackFile) {
  await blockHosts(client, [WORKER]);
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await navigate(client, `${base}/?final`, HOME_READY);

  if (!args.url) {
    const html = await readFile(path.join(dir, "index.html"));
    check(`index.html under ${BUDGET_KB} KB`, html.length <= BUDGET_KB * 1024, `${Math.round(html.length / 1024)} KB`);
  }

  // the hero's three numbers
  const v = await evaluate(client, `(() => { const p = document.querySelector('[data-verdict]'); return p && { cves: p.dataset.cves === "" ? null : Number(p.dataset.cves), stack: Number(p.dataset.stackMatch), noPatch: Number(p.dataset.noPatch), text: p.textContent }; })()`);
  check("verdict shows", Boolean(v), v?.text.slice(0, 80));
  check("verdict CVEs are the 24 h counter", v?.cves === home.counters.cves_24h, `page ${v?.cves}, home.json ${home.counters.cves_24h}`);
  check("verdict no-patch count is the list's length", v?.noPatch === panel.verdict.noFullPatch && panel.verdict.noFullPatch === panel.ledger.patch.length, `page ${v?.noPatch}, panel.json ${panel.verdict.noFullPatch} with ${panel.ledger.patch.length} records listed`);
  check("verdict stack count", v?.stack === panel.verdict.inStack, `page ${v?.stack}, panel.json ${panel.verdict.inStack}`);
  check("verdict reads its numbers", v?.text.includes(`${home.counters.cves_24h?.toLocaleString("en-US")}new CVEs in 24 h`) && v?.text.includes(`${panel.verdict.noFullPatch.toLocaleString("en-US")}exploited, no full patch`) && v?.text.includes("hit your stack this week"), v?.text.slice(0, 160));

  // the catalog behind My stack: several hundred candidates under unique keys, in the urgency order, the default among them
  {
    const keys = stackFile.candidates.map((c) => c.key);
    const sorted = [...stackFile.candidates].sort(byUrgency).map((c) => c.key);
    check(
      "stack.json holds the catalog: several hundred candidates, unique keys, most urgent first",
      keys.length >= 400 && new Set(keys).size === keys.length && keys.join(",") === sorted.join(",") && panel.stack.default.every((k) => keys.includes(k)),
      `${keys.length} candidates (${stackFile.candidates.filter((c) => c.tail).length} from CISA's list only), tiers ${[1, 2, 3, 4, 5].map((t) => stackFile.candidates.filter((c) => c.tier === t).length).join("/")}`,
    );
    check(`stack.json under ${STACK_FILE_KB} KB`, stackFile.bytes <= STACK_FILE_KB * 1024, `${(stackFile.bytes / 1024).toFixed(1)} KB`);
  }

  // My stack: only the products that need action, most urgent first, each with why and the score behind it
  const tiles = panel.stack.tiles;
  const urgent = urgentOf(tiles);
  const st = await evaluate(client, READ_STACK);
  check("the default stack is in the urgency order", tiles.map((t) => t.key).join(",") === [...tiles].sort(byUrgency).map((t) => t.key).join(",") && tiles.length <= 8, tiles.map((t) => `${t.key} ${t.tier}`).join(", "));
  check("My stack draws the products that need action and no quiet one", st.rows.map((r) => r.key).join(",") === urgent.slice(0, STACK_ROWS).map((t) => t.key).join(",") && st.calm === (urgent.length === 0), `page ${st.rows.map((r) => r.key).join(",") || "none"}; panel.json ${tiles.map((t) => `${t.key} ${t.tier}`).join(", ")}`);
  check("My stack counts its products and those that need action", st.tiles === tiles.length && st.urgent === urgent.length && st.count === `${tiles.length} ${tiles.length === 1 ? "product" : "products"} · ${urgent.length} need action`, `"${st.count}" for ${tiles.length} products, ${urgent.length} flagged`);
  for (const t of urgent.slice(0, STACK_ROWS)) {
    const p = st.rows.find((x) => x.key === t.key);
    const score = t.flagScore === null ? p?.none && p.score === null && p.shown === null && p.meter === null : p?.score === t.flagScore && Number(p.shown) === t.flagScore && p.meter === Math.max(1, Math.round(t.flagScore)) && !p.none;
    check(`stack row ${t.key}`, Boolean(p) && p.n === t.n && p.flag === t.flag && p.badge === toneOf(t.flag) && p.tier === t.tier && p.crit === t.crit && Boolean(score), `page "${p?.flag}" ${p?.badge} tier ${p?.tier} score ${p?.shown ?? (p?.none ? "no score yet" : "?")} meter ${p?.meter}; panel.json "${t.flag}" tier ${t.tier} flagScore ${t.flagScore}`);
  }
  {
    // the grey line under the rows: the stack's new critical CVEs by score, never below 9.0, each a CVE one of the tiles holds
    const held = new Map(tiles.flatMap((t) => (t.crits ?? []).map((c) => [c.id, c])));
    const scores = st.crits.named.map((c) => held.get(c.id)?.score ?? -1);
    const total = tiles.reduce((n, t) => n + t.crit, 0);
    check(
      "My stack names its highest new critical CVEs, score first",
      st.crits.total === total && st.crits.named.length === Math.min(4, new Set([...held.values()].map((c) => c.name)).size) && scores.every((s, i) => s >= 9 && (i === 0 || s <= scores[i - 1])) && st.crits.named.every((c) => c.text.startsWith(`${held.get(c.id)?.score.toFixed(1)} ${held.get(c.id)?.name}`)),
      `${st.crits.named.map((c) => c.text).join(" | ") || "none"}; ${st.crits.total} in all, panel.json ${total}`,
    );
  }
  const still = await evaluate(client, `({ dots: document.querySelectorAll(['#stack', '#news', '#due', '#week'].flatMap((s) => [s + ' .ascii-pulse', s + ' .live-dot']).join(',')).length, ticking: [...document.documentElement.classList].filter((c) => c.startsWith('pulse-')), waiting: document.querySelectorAll('main [data-num="wait"]').length })`);
  check("nothing on the page pulses, and no number waits to dissolve in", still.dots === 0 && still.ticking.length === 0 && still.waiting === 0, JSON.stringify(still));

  // a row opens the list it counts, with as many rows as its number
  if (urgent.length) {
    const t = urgent[0];
    const r = await openAndRead(client, "#stack [data-stack-tile]", 0);
    check("a stack row opens its list", r.count === t.n && r.rows === t.n && r.closed, `count line "${r.head?.slice(0, 48)}", ${r.rows} rows, ${t.key} n ${t.n}`);
  }

  // the news: four lists from one pool, each row with its sources named and counted
  const N = panel.news;
  const want = { top: newsList(N, "top"), breaches: newsList(N, "breaches"), ai: newsList(N, "ai"), stack: newsList(N, "stack") };
  const board = await fetch(`${base}/live.json`).then((r) => r.json());
  const liveAll = ["patch", "breach", "supply_chain", "research"].reduce((n, k) => n + (board.boards.find((b) => b.key === k)?.count ?? 0), 0);
  const top = await evaluate(client, READ_NEWS);
  check("news opens on the top stories, as panel.json ranks them", top.tab === "top" && top.rows.map((r) => r.slug).join(",") === want.top.slice(0, NEWS_ROWS).map((r) => r.slug).join(","), `${top.rows.length} rows: ${top.rows.map((r) => `${r.sources} ${r.slug.slice(0, 28)}`).join(" | ")}`);
  check("top stories run from the most sources down", top.rows.every((r, i) => i === 0 || r.sources <= top.rows[i - 1].sources), top.rows.map((r) => r.sources).join(" ≥ "));
  check("news links the live board with the number of live records", top.all.startsWith(`all ${liveAll.toLocaleString("en-US")} live`), `"${top.all}", live.json ${liveAll}`);
  for (const [i, r] of top.rows.entries()) {
    const w = want.top[i];
    // the record itself: its sources' distinct publishers are the row's count, and the names the row gives are its first
    const rec = await fetch(`${base}/data/incidents/${r.slug}.json`).then((x) => (x.ok ? x.json() : null));
    const pubs = rec ? [...new Set(rec.sources.map((s) => s.publisher))] : [];
    const by = `${pubs.slice(0, 4).join(" · ")}${pubs.length > 4 ? ` +${pubs.length - 4}` : ""}`;
    check(`news row ${i + 1} counts and names its record's sources`, Boolean(rec) && r.sources === pubs.length && r.sources === w.sources && r.by === by && r.title === rec.title && r.href === `/incidents/${r.slug}` && r.said.includes(`${pubs.length} ${pubs.length === 1 ? "source" : "sources"}`), `page ${r.sources} "${r.by}"; the record has ${pubs.length}: ${pubs.join(", ")}`);
    check(`news row ${i + 1} marks impact, the stack and AI as the record has them`, r.impact === w.severity >= 4 && r.stack === w.stack.join(",") && r.aiMark === (w.type !== "not_ai") && r.ai === (w.type !== "not_ai" ? "1" : "0"), `impact ${r.impact}/${w.severity >= 4}, stack "${r.stack}"/"${w.stack.join(",")}", AI ${r.aiMark}/${w.type}`);
  }
  for (const tab of ["breaches", "ai", "stack", "top"]) {
    await evaluate(client, `document.querySelector('[data-news-tab="${tab}"]').click()`);
    await sleep(250);
    const got = await evaluate(client, READ_NEWS);
    const heading = await evaluate(client, `document.querySelector('[data-news-tab][aria-selected="true"]')?.dataset.newsTab`);
    check(`news tab "${tab}" lists its rows`, got.tab === tab && heading === tab && got.count === want[tab].length && got.rows.map((r) => r.slug).join(",") === want[tab].slice(0, NEWS_ROWS).map((r) => r.slug).join(","), `${got.rows.length} of ${got.count} rows, panel.json ${want[tab].length}`);
  }
  check("the week's pool holds what its lists count", N.total >= N.rows.length && N.breaches >= want.breaches.length && N.ai >= want.ai.length && N.exploited >= N.impact && N.contacts.length === Math.min(48, N.exploited), `${N.rows.length} rows of ${N.total} records; ${N.breaches} breaches, ${N.ai} with AI, ${N.exploited} exploited, ${N.impact} with impact`);
  if (top.rows.length) {
    const r = await call(client, OPEN_LOOK, '[data-news] [data-row="news"] a');
    check("a news row opens the record's quick look on the page", r.target === top.rows[0].slug && r.state === "ready" && r.dialogs === 1 && r.path === "/" && r.title.length > 3 && r.closed, JSON.stringify(r));
  }

  // next due: CISA's deadlines still ahead, nearest first, the nearest as a countdown
  const L = panel.ledger;
  const alive = [...L.due, ...L.later].filter((r) => dueEnd(r.due) > Date.now());
  const due = await evaluate(client, READ_DUE);
  check("next due counts every deadline ahead", due?.count === alive.length, `page ${due?.count}, panel.json ${alive.length} (${L.due.length} this week, ${L.later.length} later)`);
  if (alive.length) {
    // days and hours from two days out, hours and minutes below that (lib/panel/dates.ts countdownParts)
    const mins = Math.floor((dueEnd(alive[0].due) - Date.now()) / 60_000);
    const far = mins >= 2880;
    const got = (due.lead?.big?.match(/\d+/g) ?? []).map(Number);
    const gotMins = far ? got[0] * 1440 + got[1] * 60 : got[0] * 60 + got[1];
    // the page's clock and this one read a moment apart, and the far form drops the minutes
    check("next due leads with the nearest deadline and its countdown", due.lead?.name === alive[0].name && due.lead.bigDue === alive[0].due && got.length === 2 && gotMins <= mins + 2 && gotMins >= mins - (far ? 62 : 2), `page "${due.lead?.name}" ${due.lead?.big}, panel.json "${alive[0].name}" due ${alive[0].due}, ${mins} min left`);
    check("the lead says patch where one is published, else what to do", due.lead?.fix === (alive[0].fix ? "patch" : "advice") && due.lead.fixWords.startsWith(alive[0].fix ? "patch" : "what to do"), `page "${due.lead?.fixWords}", panel.json fix ${alive[0].fix}`);
    const shown = alive.slice(1, 1 + NEXT_DUE_ROWS);
    check("next due lists the deadlines after it, in order", due.rows.map((r) => `${r.name}|${r.due}`).join(",") === shown.map((r) => `${r.name}|${r.due}`).join(","), `${due.rows.length} rows: ${due.rows.map((r) => r.name).join(" | ")}`);
    const all = [due.lead, ...due.rows];
    const wantRows = [alive[0], ...shown];
    check("next due shows each row's score", all.every((r, i) => r.score === wantRows[i].cvss), all.map((r, i) => `${r.score}/${wantRows[i].cvss}`).join(" "));
    // the page's clock and this one read a moment apart: a meter may differ by a cell at a boundary
    check("next due draws how much of CISA's window is used", all.every((r, i) => Math.abs(r.meter - windowCells(wantRows[i], Date.now())) <= 1 && r.meter >= 1 && r.meter <= 10), all.map((r, i) => `${r.meter}/${windowCells(wantRows[i], Date.now())}`).join(" "));
    check("next due says the time left once per due day, in days or hours", due.rows.every((r, i) => r.clock && /^\d+ (days?|h|min)$/.test(r.clock.text) && r.clock.shown === ((i === 0 ? alive[0].due : shown[i - 1].due) !== r.due)), due.rows.map((r) => `${r.clock?.shown ? r.clock.text : "·"}`).join(" "));
    check("next due marks the rows in the default stack", all.every((r, i) => r.stack === wantRows[i].stack.join(",")), all.map((r, i) => `"${r.stack}"/"${wantRows[i].stack.join(",")}"`).join(" "));
    const rest = alive.length - 1 - shown.length;
    check("next due says how many more there are", rest > 0 ? due.more === `${rest} more →` : due.more === null, `"${due.more}", ${rest} more in panel.json`);
    const r = await openAndRead(client, "#due [data-due-all]");
    check("next due: all opens every deadline ahead", r.count === alive.length && r.rows === alive.length && r.closed, `count line "${r.head?.slice(0, 48)}", ${r.rows} rows, panel.json ${alive.length}`);
    const q = await call(client, OPEN_LOOK, "#due [data-lead] [data-look]");
    check("a deadline opens its quick look on the page", q.target === q.wanted && q.state === "ready" && q.dialogs === 1 && q.path === "/" && q.closed, JSON.stringify(q));
  }

  // the week: six facts equal the counters, carry the site's levels, and their lists open
  const W = panel.week;
  const wk = await evaluate(client, `Object.fromEntries([...document.querySelectorAll('[data-week] [data-line]')].map((l) => [l.dataset.line, { value: l.querySelector('[data-value]')?.dataset.value ?? '', level: l.dataset.level || null, text: l.textContent.replace(/\\s+/g, ' ') }]))`);
  check("week: six facts", Object.keys(wk).join(",") === "published,critical,exploited,breaches,ai,patch-tuesday", Object.keys(wk).join(","));
  check("week published is the 7-day counter", num(wk.published?.value) === home.counters.cves_7d, `${wk.published?.value} vs ${home.counters.cves_7d}`);
  check("week critical is the 7-day counter", num(wk.critical?.value) === home.counters.critical_7d, `${wk.critical?.value} vs ${home.counters.critical_7d}`);
  check("week exploited is the 7-day KEV counter", num(wk.exploited?.value) === home.counters.kev_7d, `${wk.exploited?.value} vs ${home.counters.kev_7d}`);
  check("week breaches is the month's counter, with its accounts", num(wk.breaches?.value) === home.counters.breaches_month && (home.counters.breached_accounts_month === null || wk.breaches.text.includes(`${(home.counters.breached_accounts_month / 1e6).toFixed(1)} M accounts`)), `${wk.breaches?.value} vs ${home.counters.breaches_month}; "${wk.breaches?.text.trim()}"`);
  check("week AI is the roles' sum", num(wk.ai?.value) === W.ai.onAi + W.ai.usingAi && wk.ai?.text.includes(`of ${W.ai.total}`), `${wk.ai?.value} vs ${W.ai.onAi + W.ai.usingAi}`);
  check("week levels are panel.json's", wk.published?.level === String(W.published.level) && wk.exploited?.level === String(W.exploited.level), `published ${wk.published?.level}/${W.published.level}, exploited ${wk.exploited?.level}/${W.exploited.level}`);
  {
    const days = Math.round((Date.parse(`${W.patchTuesday}T00:00:00Z`) - Date.parse(`${home.generated_at.slice(0, 10)}T00:00:00Z`)) / DAY_MS);
    check("week counts the days to the next second Tuesday", num(wk["patch-tuesday"]?.value) === days && (days === 0 ? wk["patch-tuesday"].text.includes("today") : wk["patch-tuesday"].text.includes(shortDate(W.patchTuesday))), `"${wk["patch-tuesday"]?.text.trim()}", ${days} days to ${W.patchTuesday}`);
  }
  if (home.counters.cves_7d !== null) {
    const r = await openAndRead(client, '[data-week] [data-line="published"] button');
    check("week published opens its list", r.count === home.counters.cves_7d && r.rows > 0 && r.closed, `count line "${r.head?.slice(0, 40)}", ${r.rows} rows`);
  }
  if (home.counters.critical_7d !== null) {
    const r = await openAndRead(client, '[data-week] [data-line="critical"] button');
    check("week critical opens its list", r.count === home.counters.critical_7d && r.rows === Math.min(home.counters.critical_7d, LIST_CAP) && r.closed, `count line "${r.head?.slice(0, 40)}", ${r.rows} rows`);
  }
  if (home.counters.kev_7d) {
    const r = await openAndRead(client, '[data-week] [data-line="exploited"] button');
    check("week exploited opens its list", r.count === home.counters.kev_7d && r.rows === home.counters.kev_7d && r.closed, `count line "${r.head?.slice(0, 40)}", ${r.rows} rows`);
  }
  if (home.counters.breaches_month !== null) {
    const r = await openAndRead(client, '[data-week] [data-line="breaches"] button');
    check("week breaches opens the month's list", r.count === home.counters.breaches_month && r.listed && !r.error && r.rows === Math.min(home.counters.breaches_month, LIST_CAP) && r.closed, `count line "${r.head?.slice(0, 40)}", ${r.rows} rows${r.error ? `, error "${r.error}"` : ""}`);
  }
  const frames = await evaluate(client, `({ links: [...document.querySelectorAll('#week .hp-frame-ctl a, #news .hp-frame-ctl a')].map((a) => a.getAttribute('href')), titles: [...document.querySelectorAll('main .hp-frame')].map((f) => f.id + ':' + (f.querySelector('.hp-frame-title h2, .hp-frame-title [aria-selected="true"]')?.textContent.trim() ?? '')) })`);
  check("four sections, each titled on its line", frames.titles.join(",") === "stack:My stack,news:Top stories,due:Next due,week:This week", frames.titles.join(", "));
  check("the sections link the live board, the briefing and trends, never the data files", frames.links.includes("/live") && frames.links.includes("/trends") && frames.links.some((h) => h.startsWith("/briefing/")) && !frames.links.some((h) => /^\/(data|api|embed|stats|feed|llms|live\.json|changes)/.test(h)), frames.links.join(" "));

  // the radar scope: the week's exploited records as contacts, drawn by the glyph engine once it is on screen
  await evaluate(client, `document.querySelector('[data-radar]')?.scrollIntoView({ block: "center" })`);
  for (let i = 0; i < 50 && !(await evaluate(client, `Boolean(document.querySelector('[data-radar] canvas.is-live'))`)); i++) await sleep(200);
  const radar = await evaluate(client, `(() => { const r = document.querySelector('[data-radar]'); const b = r?.getBoundingClientRect(); return { contacts: Number(r?.dataset.radar), live: Boolean(r?.querySelector('canvas.is-live')), gl: Boolean(document.createElement('canvas').getContext('webgl2')), note: document.querySelector('[data-radar-note]')?.textContent.replace(/\\s+/g, ' ').trim() ?? '', w: Math.round(b?.width ?? 0), h: Math.round(b?.height ?? 0) }; })()`);
  check("the radar carries the week's exploited records, and its line says how many", radar.contacts === N.contacts.length && radar.note.includes(`${N.exploited} new exploited`) && (N.impact === 0 || radar.note.includes(`${N.impact} with confirmed impact`)), `${radar.contacts} contacts; "${radar.note}"`);
  check("the radar draws where WebGL2 is available, in the room kept for it", radar.w >= 280 && radar.h >= 140 && (radar.live || !radar.gl), JSON.stringify(radar));
  await evaluate(client, `window.scrollTo(0, 0)`);

  // the hero's middle: this week's KEV additions as a block numeral, the products behind them by name
  const ex = await evaluate(client, `(() => { const e = document.querySelector('[data-exploited]'); if (!e) return null; const cells = [...e.querySelectorAll('.hp-digit > i')]; return { value: e.dataset.value === "" ? null : Number(e.dataset.value), numeral: e.querySelector('[data-numeral]')?.dataset.numeral ?? null, cells: cells.length, amber: cells.filter((i) => i.classList.contains('x')).every((i) => getComputedStyle(i).backgroundColor === 'rgb(255, 179, 92)'), rows: [...e.querySelectorAll('[data-kev-row]')].map((r) => r.dataset.kevRow), text: e.textContent.replace(/\\s+/g, ' '), w: e.getBoundingClientRect().width }; })()`);
  check("hero exploited is the 7-day KEV counter", ex?.value === home.counters.kev_7d && ex.w > 200, `page ${ex?.value} (${Math.round(ex?.w ?? 0)} px), home.json ${home.counters.kev_7d}`);
  if (home.counters.kev_7d !== null) {
    const digits = String(home.counters.kev_7d);
    const lit = await evaluate(client, `document.querySelectorAll('[data-exploited] .hp-digit > i.x').length`);
    check("the block numeral draws the count: 35 cells a digit, the digit's cells lit in amber", ex.numeral === digits && ex.cells === 35 * digits.length && lit === litCells(digits) && ex.amber, `numeral "${ex.numeral}", ${ex.cells} cells, ${lit} lit, expected ${litCells(digits)}`);
    const band = W.exploited.band;
    check("hero exploited says what a typical week brings", !band || ex.text.includes(`typical week ${Math.round(band.p25)} to ${Math.round(band.p75)}`), ex.text.slice(0, 120));
  }
  const newest = panel.sieve.exploitedEntries.slice(0, EXPLOITED_NAMES).map((e) => e.cve);
  check("hero exploited names the week's newest products", ex?.rows.join(",") === newest.join(","), `page ${ex?.rows.join(",")}, panel.json ${newest.join(",")}`);
  if (home.counters.kev_7d) {
    const r = await openAndRead(client, "[data-exploited] button");
    check("hero exploited opens the week's list", r.count === home.counters.kev_7d && r.listed && r.rows === Math.min(home.counters.kev_7d, LIST_CAP) && r.closed, `count line "${r.head?.slice(0, 50)}", ${r.rows} rows, expected ${home.counters.kev_7d}`);
  }

  // every text on the page's sections is large enough to read
  const small = await evaluate(client, `[...document.querySelectorAll('main .hp-frame *, main [data-verdict] *, main [data-exploited] *')].filter((e) => e.offsetParent !== null && [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim()) && parseFloat(getComputedStyle(e).fontSize) < 12).map((e) => e.textContent.trim().slice(0, 24))`);
  check("no text in the hero or the sections is under 12 px", small.length === 0, small.slice(0, 6).join(" | ") || "all 12 px or larger");

  // a shared stack link applies, stores and recomputes: the verdict, the rows drawn, and the marks on the deadlines and the news
  const dueShown = alive.slice(0, 1 + NEXT_DUE_ROWS);
  const rowKeys = new Set([...dueShown.flatMap((r) => [...r.cves, r.href]), ...N.rows.flatMap((r) => [...r.cves, `/incidents/${r.slug}`])]);
  const covering = stackFile.candidates.find((c) => !panel.stack.default.includes(c.key) && (c.items ?? []).some((it) => rowKeys.has(it.href) || it.cves.some((cve) => rowKeys.has(cve))));
  // the picks: one that covers a row on the page, one hit this week, a quiet one, one with new criticals only, and one under a key that has since changed
  const quietOne = stackFile.candidates.find((c) => c.tier === 5 && !c.kev7.length && !c.tail);
  const critOnly = stackFile.candidates.find((c) => c.tier === 4 && !panel.stack.default.includes(c.key));
  const [oldKey, newKey] = Object.entries(stackFile.aliases).find(([, now]) => !panel.stack.default.includes(now)) ?? [];
  const picks = [...new Set([...(covering ? [covering.key] : []), ...stackFile.candidates.filter((c) => c.kev7.length).slice(0, 1).map((c) => c.key), ...(quietOne ? [quietOne.key] : []), ...(critOnly ? [critOnly.key] : []), ...(newKey ? [newKey] : [])])];
  const asLinked = picks.map((k) => (k === newKey ? oldKey : k));
  const cand = (k) => stackFile.candidates.find((c) => c.key === k);
  const inOrder = picks.map(cand).sort(byUrgency);
  const drawn = (list) => urgentOf(list).slice(0, STACK_ROWS).map((c) => c.key).join(",");
  const STACK_READY = `${HOME_READY} && document.querySelector('#stack [data-tiles][data-stack="ready"]')`;
  await navigate(client, `${base}/?final&stack=${asLinked.join(",")},not-a-product`, STACK_READY);
  const shared = await evaluate(client, `({ stack: ${READ_STACK}, stored: localStorage.getItem("gcd-radar:stack"), verdict: Number(document.querySelector('[data-verdict]').dataset.stackMatch), hidden: document.documentElement.classList.contains("stack-custom"), due: ${READ_DUE} })`);
  const expectMatch = stackMatches(stackFile, picks).length;
  check("?stack= applies the picks, an old key under its new name, and draws those that need action", shared.stack.tiles === picks.length && shared.stack.rows.map((r) => r.key).join(",") === drawn(inOrder) && shared.stack.urgent === urgentOf(inOrder).length, `${shared.stack.tiles} picks, drawn ${shared.stack.rows.map((r) => r.key).join(",") || "none"} for ${asLinked.join(",")}${oldKey ? ` (${oldKey} is ${newKey} now)` : ""}`);
  check("?stack= stores the picks", shared.stored === picks.join(","), String(shared.stored));
  check("a quiet product and one with new criticals only are counted, not drawn", [quietOne, critOnly].filter(Boolean).every((c) => !shared.stack.rows.some((r) => r.key === c.key)) && shared.stack.crits.total === inOrder.reduce((n, c) => n + c.crit, 0), `${shared.stack.count}; ${shared.stack.crits.total} new criticals in all`);
  if (shared.stack.crits.named.length) {
    // a named critical opens its product's list, where the new criticals sit apart from the exploited rows and uncoloured
    const id = shared.stack.crits.named[0].id;
    const drawer = await evaluate(client, `(async () => {
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      document.querySelector('#stack [data-stack-crit="${id}"]').click();
      for (let i = 0; i < 40 && !document.querySelector('[role="dialog"] [data-stack-crits]'); i++) await sleep(150);
      const d = document.querySelector('[role="dialog"]');
      const res = { title: d?.querySelector('h2')?.textContent.trim() ?? '', crits: Number(d?.querySelector('[data-stack-crits]')?.dataset.stackCrits), listed: [...(d?.querySelectorAll('[data-stack-crit]') ?? [])].map((li) => li.dataset.stackCrit), red: d?.querySelectorAll('[data-stack-crits] [data-tag], [data-stack-crits] [data-cvss-band], [data-stack-crits] [class*="text-live"], [data-stack-crits] [class*="bg-live"]').length ?? -1 };
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
      await sleep(250);
      return res;
    })()`);
    const owner = inOrder.find((c) => c.label === drawer.title);
    check("a named new critical opens its product's list, where they sit uncoloured", Boolean(owner) && drawer.crits === owner.crit && drawer.listed.includes(id) && drawer.listed.join(",") === owner.crits.map((c) => c.id).join(",") && drawer.red === 0, `${id} → "${drawer.title}": ${drawer.crits} with ${drawer.listed.length} listed; stack.json ${owner?.crit} with ${owner?.crits.length} kept`);
  }
  check("a shared stack recomputes the verdict", shared.verdict === expectMatch && !shared.hidden, `verdict ${shared.verdict}, expected ${expectMatch}`);
  const hits = stackHits(stackFile, picks);
  const dueMarks = dueShown.map((r) => rowStack(hits, { cves: r.cves, href: r.href }).join(","));
  const dueGot = shared.due?.lead ? [shared.due.lead, ...shared.due.rows] : [];
  check("a shared stack recomputes the marks on the deadlines", dueGot.length === dueShown.length && dueGot.every((r, i) => r.stack === dueMarks[i] && r.ready === "ready"), `page ${dueGot.map((r) => r.stack || "-").join("|")}, expected ${dueMarks.map((m) => m || "-").join("|")}`);
  {
    const mine = newsList(N, "stack", (r) => rowStack(hits, { cves: r.cves, href: `/incidents/${r.slug}` }));
    await evaluate(client, `document.querySelector('[data-news-tab="stack"]').click()`);
    await sleep(250);
    const got = await evaluate(client, READ_NEWS);
    check("a shared stack fills the news's own list", got.count === mine.length && got.rows.map((r) => r.slug).join(",") === mine.slice(0, NEWS_ROWS).map((r) => r.slug).join(",") && got.rows.every((r) => r.stack !== "" && r.ready === "ready"), `${got.count} rows, expected ${mine.length}${covering ? ` (${covering.key} covers a row)` : " (no candidate covers a row)"}`);
  }
  await navigate(client, `${base}/?final`, STACK_READY);
  const kept = await evaluate(client, `({ tiles: Number(document.querySelector('#stack [data-tiles]').dataset.tiles), rows: [...document.querySelectorAll('#stack [data-stack-tile]')].map((t) => t.dataset.stackTile).join(",") })`);
  check("the stored stack comes back without the link", kept.tiles === picks.length && kept.rows === drawn(inOrder), JSON.stringify(kept));

  // the chooser: the visitor's picks on top, every category with its count, search by name and by another name, a tick adds a product, clearing goes back to the default
  {
    const wanted = stackFile.candidates.find((c) => c.aka.length && !picks.includes(c.key) && !c.tail);
    const chooser = await evaluate(client, `(async () => {
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const type = async (text) => {
        const input = document.querySelector('[role="dialog"] input[type="search"]');
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, text);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        await sleep(200);
      };
      const rows = () => [...document.querySelectorAll('[role="dialog"] [data-chooser-view="search"] ol > li')].map((li) => li.dataset.chooserRow);
      const strip = () => ({ tiles: Number(document.querySelector('#stack [data-tiles]').dataset.tiles), rows: [...document.querySelectorAll('#stack [data-stack-tile]')].map((t) => t.dataset.stackTile).join(',') });
      [...document.querySelectorAll('#stack button')].find((b) => b.textContent.trim() === 'edit').click();
      for (let i = 0; i < 40 && !document.querySelector('[role="dialog"] [data-chooser-cat]'); i++) await sleep(150);
      const d = document.querySelector('[role="dialog"]');
      const res = {
        count: d.querySelector('[data-chooser-count]')?.textContent ?? '',
        mine: [...d.querySelectorAll('[data-chooser-view="mine"] ol > li')].map((li) => li.dataset.chooserRow),
        popular: d.querySelectorAll('[data-chooser-view="popular"]').length,
        cats: [...d.querySelectorAll('[data-chooser-cat]')].map((b) => [b.dataset.chooserCat, Number(b.dataset.count)]),
        order: d.querySelector('[data-chooser-order]')?.textContent ?? '',
        small: [...d.querySelectorAll('h2, h3, p, label, button, input, span')].filter((e) => e.textContent.trim() && parseFloat(getComputedStyle(e).fontSize) < 12).length,
      };
      await type(${JSON.stringify(wanted?.label.toLowerCase() ?? "")});
      res.byName = rows();
      res.marked = document.querySelector('[role="dialog"] [data-chooser-view="search"] mark')?.textContent ?? '';
      await type(${JSON.stringify(wanted?.aka[0] ?? "")});
      res.byOther = rows();
      await type('zzzz no such product');
      res.none = Boolean(document.querySelector('[role="dialog"] [data-empty]'));
      await type(${JSON.stringify(wanted?.label ?? "")});
      document.querySelector('[role="dialog"] [data-chooser-row="${wanted?.key}"] input')?.click();
      await sleep(300);
      res.ticked = strip();
      res.stored = localStorage.getItem("gcd-radar:stack");
      await type('');
      document.querySelector('[role="dialog"] [data-chooser-cat="${wanted?.cat}"]')?.click();
      await sleep(200);
      res.inCategory = document.querySelectorAll('[role="dialog"] [data-chooser-view="category"] ol > li').length;
      document.querySelector('[role="dialog"] [data-chooser-reset]')?.click();
      await sleep(300);
      res.cleared = strip();
      res.storedAfter = localStorage.getItem("gcd-radar:stack");
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
      await sleep(250);
      res.closed = !document.querySelector('[role="dialog"]');
      return res;
    })()`);
    const perCat = new Map();
    for (const c of stackFile.candidates) perCat.set(c.cat, (perCat.get(c.cat) ?? 0) + 1);
    check("chooser: the picks on top and the count line", chooser.count.startsWith(`${picks.length} of up to ${STACK_MAX} chosen`) && chooser.mine.join(",") === inOrder.map((c) => c.key).join(",") && chooser.popular === 0, `"${chooser.count}", mine ${chooser.mine.join(",")}`);
    check("chooser: every category with its count", chooser.cats.length === perCat.size && chooser.cats.every(([k, n]) => perCat.get(k) === n) && chooser.cats.reduce((n, [, x]) => n + x, 0) === stackFile.candidates.length, chooser.cats.map(([k, n]) => `${k} ${n}`).join(", "));
    check("chooser: says how the lists are ordered, in text no smaller than 12 px", chooser.order.startsWith("Most urgent first") && chooser.small === 0, `${chooser.small} elements under 12 px; "${chooser.order.slice(0, 60)}"`);
    if (wanted) {
      check("chooser: search finds a product by its name and by another name it goes by", chooser.byName[0] === wanted.key && chooser.marked.toLowerCase() === wanted.label.toLowerCase() && chooser.byOther.includes(wanted.key) && chooser.none, `"${wanted.label}" → ${chooser.byName.slice(0, 3).join(",")}; "${wanted.aka[0]}" → ${chooser.byOther.slice(0, 3).join(",")}; nothing found shown ${chooser.none}`);
      const withIt = [...picks, wanted.key].map(cand).sort(byUrgency);
      check("chooser: a tick adds the product to the stack and to the stored picks", chooser.ticked.tiles === picks.length + 1 && chooser.ticked.rows === drawn(withIt) && chooser.stored === [...picks, wanted.key].join(","), `${JSON.stringify(chooser.ticked)}; stored ${chooser.stored}`);
      check("chooser: a category opens its list", chooser.inCategory === perCat.get(wanted.cat), `${chooser.inCategory} rows, ${perCat.get(wanted.cat)} in ${wanted.cat}`);
    }
    check("chooser: clearing the choice brings the default back", chooser.cleared.tiles === tiles.length && chooser.cleared.rows === drawn(tiles) && chooser.storedAfter === null && chooser.closed, `${JSON.stringify(chooser.cleared)}; stored ${chooser.storedAfter}`);
  }

  // a stack as large as it gets: the link is capped at the limit and still fits the page on a phone, where the list is short until asked for more
  {
    const many = stackFile.candidates.filter((c) => !c.tail).slice(0, STACK_MAX + 6).map((c) => c.key);
    const url = `${base}/?final&stack=${many.join(",")}`;
    await client.send("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 2, mobile: true });
    await navigate(client, url, STACK_READY);
    const big = await evaluate(client, `({ tiles: Number(document.querySelector('#stack [data-tiles]').dataset.tiles), shown: [...document.querySelectorAll('#stack [data-stack-tile]')].filter((t) => t.offsetParent !== null).length, more: (() => { const b = document.querySelector('#stack [data-stack-more]'); return (b && [...b.querySelectorAll('span')].find((x) => x.offsetParent !== null) || b)?.textContent.trim() ?? null; })(), h: Math.round(document.querySelector('#stack').getBoundingClientRect().height), scroll: document.documentElement.scrollWidth, inner: window.innerWidth })`);
    const flagged = urgentOf(many.slice(0, STACK_MAX).map(cand)).length;
    check(`a stack of ${STACK_MAX} is the most a link applies, and stays compact on a phone`, big.tiles === STACK_MAX && big.shown === Math.min(5, flagged) && (flagged <= 5 || big.more === `+${flagged - 5} more`) && big.h < 700 && big.scroll <= big.inner && url.length < 2000, `${big.tiles} picks from ${many.length} keys, ${big.shown} of ${flagged} flagged shown, "${big.more}", ${big.h} px tall, link ${url.length} characters, scrollWidth ${big.scroll} of ${big.inner}`);
    await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  }
  await evaluate(client, `localStorage.removeItem("gcd-radar:stack")`);

  // motion: the page is final as rendered with or without it; under reduced motion the html has no motion class and the radar still shows a frame
  await navigate(client, `${base}/`, HOME_READY);
  const on = await evaluate(client, `({ motion: document.documentElement.classList.contains("motion"), verdict: document.querySelector('[data-verdict]')?.textContent.length ?? 0, hidden: [...document.querySelectorAll('main .hp-frame, main [data-verdict], main [data-exploited]')].filter((e) => getComputedStyle(e).visibility === 'hidden' || getComputedStyle(e).opacity === '0').length })`);
  check("with motion on, nothing on the page waits to appear", on.motion && on.verdict > 20 && on.hidden === 0, JSON.stringify(on));
  await client.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  await navigate(client, `${base}/`, HOME_READY);
  await evaluate(client, `document.querySelector('[data-radar]')?.scrollIntoView({ block: "center" })`);
  for (let i = 0; i < 40 && !(await evaluate(client, `Boolean(document.querySelector('[data-radar] canvas.is-live'))`)); i++) await sleep(200);
  const off = await evaluate(client, `({ motion: document.documentElement.classList.contains("motion"), radar: Boolean(document.querySelector('[data-radar] canvas.is-live')), gl: Boolean(document.createElement('canvas').getContext('webgl2')), rows: document.querySelectorAll('[data-news] [data-row="news"]').length })`);
  check("reduced motion: the page is complete and the radar holds one frame", !off.motion && off.rows > 0 && (off.radar || !off.gl), JSON.stringify(off));
  await client.send("Emulation.setEmulatedMedia", { features: [] });

  // phones
  await client.send("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 2, mobile: true });
  await navigate(client, `${base}/?final`, HOME_READY);
  await sleep(500);
  const w = await evaluate(client, `({ scroll: document.documentElement.scrollWidth, inner: window.innerWidth, tabs: [...document.querySelectorAll('[data-news-tab]')].every((b) => { const r = b.getBoundingClientRect(); return r.left >= 0 && r.right <= window.innerWidth; }), clash: (() => { const t = document.querySelector('#stack .hp-frame-title').getBoundingClientRect(), c = document.querySelector('#stack .hp-frame-ctl').getBoundingClientRect(); return t.right > c.left; })() })`);
  check("no sideways scroll on / at 375px, and the section lines hold their titles", w.scroll <= w.inner && w.tabs && !w.clash, JSON.stringify(w));

  // the live layer, let through: the live marker, or the built numbers when the Worker has no pulse yet
  await blockHosts(client, []);
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await navigate(client, `${base}/?final`, HOME_READY);
  await sleep(3500);
  const live = await evaluate(client, `({ marker: document.querySelector('[data-week] [data-line="published"]')?.textContent.includes("· live"), cves: Number(document.querySelector('[data-verdict]').dataset.cves), sweep: document.querySelector('[data-verdict]')?.closest('section')?.querySelector('[data-sweep-state]')?.dataset.sweepState ?? null })`);
  // a newer sweep from the real Worker carries its own counts; otherwise the live marker or the built numbers
  check("live layer: a newer sweep, the live marker or the built numbers", live.marker || live.sweep === "live" ? live.cves > 0 : live.cves === home.counters.cves_24h, JSON.stringify(live));
  await blockHosts(client, [WORKER]);
}

/**
 * The live layer (lib/live, components/live): the page swaps in a sweep
 * newer than its build, its label states that sweep's age in plain words,
 * a record with no page yet opens in a drawer and never links to the
 * missing page, and without the Worker the page keeps its snapshot and says
 * how old it is. The Worker is stubbed with a file made from the build's own
 * numbers plus one made-up record.
 */
async function checkLiveLayer(client, base, home, panel) {
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  const noPatch = `Number(document.querySelector('[data-verdict]').dataset.noPatch)`;
  const AGE = "(just now|\\d+ (min|h|d) ago)";

  // without the Worker: the built snapshot, and its real age in words
  await blockHosts(client, [WORKER]);
  await navigate(client, `${base}/?final`, `${HOME_READY} && document.querySelector('[data-sweep-state="built"]')`);
  const asBuilt = await evaluate(client, READ_LABELS);
  const builtSweep = asBuilt.page?.sweep;
  check("without the Worker the label states the built data's age", asBuilt.page?.state === "built" && new RegExp(`^data from ${AGE}$`).test(asBuilt.page.text) && Number.isFinite(Date.parse(builtSweep)), JSON.stringify(asBuilt.page));
  check("the header says the same", asBuilt.header?.state === "built" && asBuilt.header.sweep === builtSweep && new RegExp(`^data from ${AGE}$`).test(asBuilt.header.text), JSON.stringify(asBuilt.header));
  check("without the Worker the numbers are the build's", (await evaluate(client, noPatch)) === panel.verdict.noFullPatch);

  // a sweep three minutes old: the build's own model with one more record that has no page
  const head = sweepHead(builtSweep);
  const fresh = freshRecord(head.sweep);
  const board = await fetch(`${base}/live.json`).then((r) => r.json());
  const count = (k) => board.boards.find((b) => b.key === k)?.count ?? 0;
  const L = panel.ledger;
  const N = panel.news;
  const view = {
    now: head.sweep,
    today: head.sweep.slice(0, 10),
    lastUpdated: head.sweep,
    columns: { patch: { live: count("patch") }, breach: { live: count("breach") }, supply_chain: count("supply_chain"), research: count("research") },
    stats: { ...home, series: { cves_by_year: [], ai_cves_by_quarter: [], kev_by_month: [], breaches_by_month: [], kev_lag_by_year: [] }, epss_top: [] },
    panel: {
      verdict: { ...panel.verdict, noFullPatch: panel.verdict.noFullPatch + 1 },
      stack: panel.stack,
      // the made-up record leads the top stories, as the newest and most reported of the week
      news: {
        ...N,
        rows: [{ slug: FRESH_SLUG, title: fresh.title, lane: "patch", severity: 4, type: "not_ai", created: fresh.created_at, cvss: 9.8, cves: fresh.cve_ids, by: [...new Set(fresh.sources.map((x) => x.publisher))], sources: 99, stack: [] }, ...N.rows],
        top: [FRESH_SLUG, ...N.top],
        total: N.total + 1,
        exploited: N.exploited + 1,
        impact: N.impact + 1,
      },
      ledger: { due: L.due, later: L.later },
      week: panel.week,
      sieve: panel.sieve,
    },
    briefing: null,
  };
  const lists = Object.fromEntries(await Promise.all(["cves-week.json", "kev-week.json"].map(async (n) => [n, await fetch(`${base}/stats/${n}`).then((r) => r.text())])));
  let mode = "newer";
  const asked = [];
  await blockHosts(client, []);
  await stubHost(client, WORKER, (url) => {
    // the pulse and the globe fail as if blocked; only the live files answer
    if (!url.pathname.startsWith("/v1/live/")) return null;
    const name = url.pathname.slice("/v1/live/".length);
    asked.push(name + url.search);
    if (mode === "down") return { status: 503, body: { error: "the live files are unavailable" } };
    if (name === "home.json") {
      if (mode === "same") return { body: { ...head, sweep: builtSweep, view: { ...view, lastUpdated: builtSweep }, fresh: [] } };
      if (mode === "foreign") return { body: { ...head, v: 99, view, fresh: [fresh] } };
      return { body: { ...head, view, fresh: [fresh] } };
    }
    return lists[name] ? { body: lists[name] } : { status: 404, body: { error: "not found" } };
  });

  await navigate(client, `${base}/?final`, `${HOME_READY} && document.querySelector('[data-sweep-state="live"]')`);
  await sleep(400);
  const swapped = await evaluate(client, READ_LABELS);
  check("a newer sweep: the label says when it was checked", swapped.page?.state === "live" && swapped.page.sweep === head.sweep && /^checked \d+ min ago$/.test(swapped.page.text), JSON.stringify(swapped.page));
  check("a newer sweep: the header says the same", swapped.header?.state === "live" && swapped.header.sweep === head.sweep && swapped.header.text === swapped.page?.text, JSON.stringify(swapped.header));
  check("a newer sweep: the label is never fresher than its data", Date.parse(swapped.page?.sweep) === Date.parse(view.lastUpdated) && Date.parse(swapped.page?.sweep) <= Date.now(), `${swapped.page?.sweep} vs the view's ${view.lastUpdated}`);
  const shown = await evaluate(client, `({ noPatch: ${noPatch}, first: document.querySelector('[data-news] [data-row="news"]')?.dataset.slug ?? null, total: Number(document.querySelector('[data-news]')?.dataset.count) })`);
  check("a newer sweep: its numbers and rows are on the page", shown.noPatch === panel.verdict.noFullPatch + 1 && shown.first === FRESH_SLUG && shown.total === newsList(N, "top").length + 1, JSON.stringify(shown));
  const clicked = await call(client, CLICK_FRESH, FRESH_SLUG);
  check("a record with no page links its source, never the missing page", clicked.links >= 1 && clicked.toMissingPage === 0 && clicked.hrefs.length === 1 && clicked.hrefs[0] === FRESH_SOURCE && clicked.newTab, JSON.stringify({ links: clicked.links, hrefs: clicked.hrefs, toMissingPage: clicked.toMissingPage }));
  check("a click on it opens the record in a drawer and stays on the page", clicked.drawer?.slug === FRESH_SLUG && clicked.drawer.title === fresh.title && clicked.drawer.sources.includes(FRESH_SOURCE) && clicked.drawer.pageLinks === 0 && clicked.stayed && clicked.closed, JSON.stringify(clicked.drawer));
  if (home.counters.cves_7d !== null) {
    const r = await openAndRead(client, '[data-week] [data-line="published"] button');
    const wanted = `cves-week.json?s=${encodeURIComponent(head.sweep)}`;
    check("a newer sweep: a number opens the list of the same sweep", asked.includes(wanted) && r.count === home.counters.cves_7d && r.rows > 0 && r.closed, `asked ${asked.filter((a) => a.startsWith("cves-week")).join(", ") || "nothing"}, ${r.rows} rows`);
  }

  // the build is already the newest sweep: nothing is swapped, and "checked" is true of the build
  mode = "same";
  await navigate(client, `${base}/?final`, `${HOME_READY} && document.querySelector('[data-sweep-state="current"]')`);
  const same = await evaluate(client, READ_LABELS);
  check("no newer sweep: the build stands and its label says when it was checked", same.page?.state === "current" && same.page.sweep === builtSweep && new RegExp(`^checked ${AGE}$`).test(same.page.text) && (await evaluate(client, noPatch)) === panel.verdict.noFullPatch, JSON.stringify(same.page));

  // the Worker down, and a file of a shape the page does not know: the snapshot and its age, nothing swapped
  for (const [m, name] of [["down", "the Worker answers 503"], ["foreign", "a file of another version"]]) {
    mode = m;
    await navigate(client, `${base}/?final`, `${HOME_READY} && document.querySelector('[data-sweep-state="built"]')`);
    const kept = await evaluate(client, `({ labels: ${READ_LABELS}, noPatch: ${noPatch}, fresh: document.querySelectorAll('a[data-fresh-slug]').length })`);
    check(`${name}: the page keeps its snapshot and says its age`, kept.labels.page?.state === "built" && kept.labels.page.sweep === builtSweep && new RegExp(`^data from ${AGE}$`).test(kept.labels.page.text) && kept.noPatch === panel.verdict.noFullPatch && kept.fresh === 0, JSON.stringify(kept.labels.page));
  }
  await stubHost(client, WORKER, null);
  await blockHosts(client, [WORKER]);
}

async function checkTrends(client, base, home, panel) {
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await navigate(client, `${base}/trends?final`, TRENDS_READY);

  // the three instruments that moved from the home page: attack types, the attack surface, the AI flow
  const types = await evaluate(client, `[...document.querySelectorAll('[data-type]')].map((r) => ({ key: r.dataset.type, n: Number(r.dataset.n), ai: Number(r.dataset.ai), cells: r.querySelectorAll('.ascii-cells > i').length }))`);
  check("attack types", types.length === panel.types.length && types.every((t, i) => t.key === panel.types[i].key && t.n === panel.types[i].n && t.ai === panel.types[i].ai && t.cells >= 1 && t.cells <= 26), types.map((t) => `${t.key} ${t.n}/${t.ai}`).join(", "));
  const surface = await evaluate(client, `[...document.querySelectorAll('[data-tech]')].map((r) => ({ label: r.dataset.tech, n: Number(r.dataset.n), squares: r.querySelectorAll('.ascii-units > i').length, bright: r.querySelectorAll('.ascii-units > i:not(.old)').length }))`);
  check(
    "attack surface: one square per KEV entry, bright for the last 30 days",
    surface.length === panel.surface.length && surface.every((s, i) => s.label === panel.surface[i].label && s.squares === panel.surface[i].n && s.bright === panel.surface[i].recent),
    surface.map((s) => `${s.label} ${s.squares}/${s.bright}`).join(", "),
  );
  const flow = await evaluate(client, `(() => {
    const nodes = [...document.querySelectorAll('[data-node]')].map((n) => ({ cls: n.dataset.node, n: Number(n.dataset.n) }));
    const svg = document.querySelector('.flow-ribbons');
    const box = svg?.getBoundingClientRect();
    const paths = [...(svg?.querySelectorAll('path') ?? [])].map((p) => ({ cls: p.getAttribute('class'), ys: (p.getAttribute('d').match(/-?\\d+(?:\\.\\d+)?/g) || []).map(Number).filter((_, i) => i % 2 === 1) }));
    const vb = (svg?.getAttribute('viewBox') || '0 0 0 0').split(' ').map(Number);
    return { nodes, paths: paths.map((p) => p.cls), inside: paths.every((p) => p.ys.every((y) => y >= 0 && y <= vb[3])), h: Math.round(box?.height ?? 0) };
  })()`);
  const roles = { t: panel.ai.target.n, w: panel.ai.weapon.n, z: panel.ai.none };
  check("AI flow nodes", flow.nodes.length === 3 && flow.nodes.every((n) => n.n === roles[n.cls]), JSON.stringify(flow.nodes));
  for (const k of ["t", "w", "z"]) check(`AI flow ribbons ${k}`, flow.paths.filter((c) => c === k).length === Math.max(1, Math.ceil(roles[k] / 2)), `${flow.paths.filter((c) => c === k).length} paths for ${roles[k]} incidents`);
  check("AI flow ribbons stay in their box", flow.inside && flow.h > 100, `height ${flow.h}`);
  const weak = await evaluate(client, `(() => { const u = document.querySelectorAll('[data-weak] .ascii-units > i'); return { n: u.length, red: [...u].filter((i) => i.classList.contains('red')).length }; })()`);
  check("weak link: a square per CVE, the exploited ones red", weak.n === panel.ai.weak.cves && weak.red === panel.ai.weak.exploited, `${weak.n} squares, ${weak.red} red; panel.json ${panel.ai.weak.cves}/${panel.ai.weak.exploited}`);

  const counters = await evaluate(client, `Object.fromEntries([...document.querySelectorAll('[data-counter]')].map((e) => [e.dataset.counter, e.dataset.value === "" ? null : Number(e.dataset.value)]))`);
  for (const key of ["cves_24h", "cves_7d", "critical_7d", "kev_7d", "breached_accounts_month", "live"]) {
    check(`trends counter ${key}`, counters[key] === home.counters[key], `page ${counters[key]}, home.json ${home.counters[key]}`);
  }
  // every counter's drawer lists what it counts: as many rows, or the first LIST_CAP where the list is capped; a zero lists none
  const expectations = {
    cves_24h: [home.counters.cves_24h, Infinity],
    cves_7d: [home.counters.cves_7d, LIST_CAP],
    critical_7d: [home.counters.critical_7d, LIST_CAP],
    kev_7d: [home.counters.kev_7d, Infinity],
    breached_accounts_month: [home.counters.breaches_month, LIST_CAP],
  };
  for (const [key, [expected, cap]] of Object.entries(expectations)) {
    if (expected === null) continue;
    const r = await openAndRead(client, `button[data-counter="${key}"]`);
    const rows = Math.min(expected, cap);
    check(`trends counter ${key} opens its list`, r.count === expected && r.listed && !r.error && r.rows === rows && r.locked && r.closed, `count line "${r.head?.slice(0, 50)}", ${r.rows} rows, expected ${expected} and ${rows} rows${r.error ? `, error "${r.error}"` : ""}`);
  }
  const day = await openAndRead(client, `button[data-counter="cves_24h"]`);
  check("the 24-hour list is complete", day.rows === home.counters.cves_24h, `${day.rows} rows, counter ${home.counters.cves_24h}`);

  const kevLast = home.series.kev_by_month[home.series.kev_by_month.length - 1];
  const kev = await openAndRead(client, `[data-chart="kev-by-month"] rect[role="button"]`, -1);
  check(`KEV column ${kevLast.month} opens its additions`, kev.count === kevLast.total && kev.rows === Math.min(kevLast.total, LIST_CAP), `${kev.label} → "${kev.head?.slice(0, 40)}", ${kev.rows} rows`);
  const brPrev = home.series.breaches_by_month[home.series.breaches_by_month.length - 2];
  const br = await openAndRead(client, `[data-chart="breaches-by-month"] rect[role="button"]`, -2);
  check(`breach column ${brPrev.month} opens its breaches`, br.count === brPrev.accounts && br.rows === brPrev.breaches, `${br.label} → "${br.head?.slice(0, 40)}", ${br.rows} rows`);

  const charts = await evaluate(client, `[...document.querySelectorAll('#web [data-chart]')].map((c) => ({ name: c.dataset.chart, buttons: [...c.querySelectorAll('rect[role="button"]')].map((b) => b.getAttribute('aria-label')) }))`);
  for (const c of charts.filter((x) => x.buttons.length)) check(`chart ${c.name} labels`, c.buttons.every((l) => /^.+: \d+ \S/.test(l)), `${c.buttons.length} columns`);
  check("CVEs per year reaches back to 1999", charts.find((c) => c.name === "cves-by-year")?.buttons[0]?.startsWith("1999:") ?? false);
  check("the exploitation lag chart is on /trends", charts.some((c) => c.name === "kev-lag-by-year"), charts.map((c) => c.name).join(", "));

  const scope = await fetch(`${base}/stats/scope.json`).then((r) => (r.ok ? r.json() : { total: null, blips: [] }));
  await sleep(1500);
  const fig = await evaluate(client, `(() => {
    const cap = [...document.querySelectorAll("figcaption")].find((f) => f.textContent.startsWith("Radar scope of the"));
    return { total: Number((cap?.textContent.match(/of the (\\d+) incidents/) || [])[1]), fetched: performance.getEntriesByType("resource").some((e) => new URL(e.name).pathname === "/stats/scope.json") };
  })()`);
  check("radar scope fetches the blips its caption counts", fig.fetched && fig.total === scope.total && (scope.blips.length > 0 || scope.total === 0) && scope.blips.length <= scope.total, `caption ${fig.total}, scope.json ${scope.total} incidents and ${scope.blips.length} blips, fetched ${fig.fetched}`);
}

async function main() {
  const t0 = Date.now();
  const site = await openSite(args);
  const dir = path.resolve(args.dir ?? "out");
  const { client, close, exe } = await launch(args.browser);
  const errors = collectErrors(client);
  try {
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    const [home, panel] = await Promise.all(["/stats/home.json", "/stats/panel.json"].map((f) => fetch(`${site.base}${f}`).then((r) => r.json())));
    const stackText = await fetch(`${site.base}/stats/stack.json`).then((r) => r.text());
    const stackFile = { ...unpackStack(JSON.parse(stackText)), bytes: Buffer.byteLength(stackText) };
    await checkHome(client, site.base, dir, home, panel, stackFile);
    await checkLiveLayer(client, site.base, home, panel);
    await checkTrends(client, site.base, home, panel);
    const failed = checks.filter((c) => !c.ok);
    console.log(`\n${checks.length - failed.length}/${checks.length} home-page checks pass in ${((Date.now() - t0) / 1000).toFixed(1)} s · ${exe.split(/[\\/]/).pop()} · ${site.base}`);
    // a blocked Worker request is the check's own doing, not a page error
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
