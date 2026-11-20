#!/usr/bin/env node
/**
 * Checks the home page and the web half of /trends in a real browser against
 * the files they were built from.
 *
 * The home page (the day sheet, lib/panel): the hero's three numbers equal
 * /stats/panel.json and /stats/home.json; /stats/stack.json holds the
 * catalog (several hundred candidates, most urgent first, under its size
 * budget); My stack shows the default chips in that order with a coloured
 * word only where the rule put a flag (never for new critical CVEs), a chip
 * opens the list it counts and, apart from it and uncoloured, its new
 * criticals, a ?stack= link applies, stores and recomputes the picks
 * (an old key under its new name) and the ledger's stack tags, the chooser
 * lists the picks, the categories and what a search finds, and a stack of
 * forty fits a phone; the runway card leads with the nearest deadline
 * as a countdown and draws a dot per new record, a bar per record without a
 * patch and a marker per deadline day; the card's lead and the three lists
 * under it show this week's deadlines (with the time left), the records
 * without a full patch and the week's new records as panel.json has them,
 * tag the rows in the stack and the AI records, show only AI rows under "AI
 * only", and the drawers list every deadline ahead and every record without
 * a patch; the week's six cells equal the counters and open their lists;
 * nothing on the sheet pulses; the hero's
 * exploited-this-week numeral is the KEV counter, draws, lists the week's
 * newest entries and opens the week's list; motion is off under reduced
 * motion; the HTML stays under its budget; nothing scrolls sideways on a
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
const HOME_READY = `document.querySelector('[data-instrument="week"]') && document.querySelectorAll('[data-build][data-built]').length >= 5`;
/** The drawer lists' cap (lib/home.ts LIST_CAP). */
const LIST_CAP = 200;
const TRENDS_READY = `document.querySelectorAll('[data-counter]').length >= 6 && document.querySelector('[data-chart="kev-by-month"] rect') && document.querySelector('[data-instrument="ai"][data-built]')`;
/** The ledger's row caps (lib/panel/caps.ts): the runway's lead and three list rows, then three rows a list; six bars on the runway. */
const LEDGER_ROWS = { due: 4, patch: 3, fresh: 3 };
const RUNWAY_OPEN_BARS = 6;
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

/**
 * The records without a patch the page lists on their own: all but those whose CVEs are all on a deadline row
 * still ahead (lib/panel/deadlines.ts foldedOnDeadline). The page drops a deadline that has passed since the build.
 */
function openRows(ledger) {
  const ahead = new Set(ledger.due.filter((r) => dueEnd(r.due) > Date.now()).flatMap((r) => r.cves));
  return ledger.patch.filter((r) => !(r.cves.length > 0 && r.cves.every((c) => ahead.has(c))));
}

/** The ledger rows the page shows, in order, with where each links (lib/panel/ledger.ts, lib/panel/caps.ts). */
function ledgerRows(ledger) {
  return [
    ...ledger.due.filter((r) => dueEnd(r.due) > Date.now()).slice(0, LEDGER_ROWS.due).map((r) => ({ ...r, href: r.href })),
    ...openRows(ledger).slice(0, LEDGER_ROWS.patch).map((r) => ({ ...r, href: `/incidents/${r.slug}` })),
    ...ledger.fresh.slice(0, LEDGER_ROWS.fresh).map((r) => ({ ...r, href: `/incidents/${r.slug}` })),
  ];
}

/** What the page shows of the ledger: every row of every group, in order, with its marks and clock. */
const READ_LEDGER = `(() => [...document.querySelectorAll('[data-ledger] [data-row]')].map((el) => ({
  kind: el.dataset.row, ai: el.dataset.ai, hidden: el.hidden, href: el.querySelector('a')?.getAttribute('href') ?? null,
  clock: el.querySelector('[data-countdown]')?.textContent ?? null, stack: el.querySelector('[data-stack-mark]')?.dataset.stackMark ?? "",
  aiMark: el.querySelector('[data-ai-mark]')?.dataset.aiMark ?? null, ready: el.querySelector('[data-stack]')?.dataset.stack ?? null,
})))()`;

async function checkHome(client, base, dir, home, panel, stackFile) {
  await blockHosts(client, [WORKER]);
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await navigate(client, `${base}/?final`, HOME_READY);

  if (!args.url) {
    const html = await readFile(path.join(dir, "index.html"));
    check(`index.html under ${BUDGET_KB} KB`, html.length <= BUDGET_KB * 1024, `${Math.round(html.length / 1024)} KB`);
  }

  // the verdict
  const v = await evaluate(client, `(() => { const p = document.querySelector('[data-verdict]'); return p && { cves: p.dataset.cves === "" ? null : Number(p.dataset.cves), stack: Number(p.dataset.stackMatch), noPatch: Number(p.dataset.noPatch), text: p.textContent }; })()`);
  check("verdict shows", Boolean(v), v?.text.slice(0, 80));
  check("verdict CVEs are the 24 h counter", v?.cves === home.counters.cves_24h, `page ${v?.cves}, home.json ${home.counters.cves_24h}`);
  check("verdict no-patch count", v?.noPatch === panel.verdict.noFullPatch, `page ${v?.noPatch}, panel.json ${panel.verdict.noFullPatch}`);
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
    // the drawer says of a product's new criticals that none is known to be exploited: none may also be an exploited item, anywhere in the file
    const exploitedIds = new Set(stackFile.candidates.flatMap((c) => (c.items ?? []).flatMap((it) => it.cves)));
    const both = [...new Set(stackFile.candidates.flatMap((c) => (c.crits ?? []).map((x) => x.id)).filter((id) => exploitedIds.has(id)))];
    check("stack.json: no new critical CVE is also an exploited item", both.length === 0, both.length ? both.join(", ") : `${new Set(stackFile.candidates.flatMap((c) => (c.crits ?? []).map((x) => x.id))).size} new criticals listed, none among the ${exploitedIds.size} exploited ids`);
  }

  // My stack: the default tiles, most urgent first, a badge only where the rule put a flag, in the flag's tone
  const tiles = await evaluate(client, `[...document.querySelectorAll('[data-stack-tile]')].map((t) => ({ key: t.dataset.stackTile, n: Number(t.dataset.n), flag: t.dataset.flag, tier: Number(t.dataset.tier), crit: Number(t.dataset.crit), shown: t.querySelector('[data-num]')?.textContent, badge: t.querySelector('[data-stack-badge]')?.dataset.stackBadge ?? null }))`);
  check("stack shows the default tiles", tiles.map((t) => t.key).join(",") === panel.stack.default.join(","), tiles.map((t) => t.key).join(","));
  check("the default tiles are in the urgency order", panel.stack.tiles.map((t) => t.key).join(",") === [...panel.stack.tiles].sort(byUrgency).map((t) => t.key).join(",") && panel.stack.tiles.length <= 8, panel.stack.tiles.map((t) => `${t.key} ${t.tier}`).join(", "));
  const toneOf = (flag) => (!flag ? null : flag.startsWith("patch by ") || flag.startsWith("past due ") ? "due" : flag === "confirmed impact" ? "harm" : flag === "no patch yet" ? "open" : "partial");
  for (const t of panel.stack.tiles) {
    const p = tiles.find((x) => x.key === t.key);
    // new critical CVEs are the quiet signal: the tile carries their count, and never a badge for them
    check(`stack tile ${t.key}`, p && p.n === t.n && num(p.shown) === t.n && p.flag === (t.flag ?? "") && p.badge === toneOf(t.flag) && p.tier === t.tier && p.crit === t.crit, `page n ${p?.n} shown ${p?.shown} flag "${p?.flag}" badge ${p?.badge} tier ${p?.tier} crit ${p?.crit}, panel.json n ${t.n} flag "${t.flag ?? ""}" tier ${t.tier} crit ${t.crit}`);
  }
  const still = await evaluate(client, `({ dots: document.querySelectorAll(['#stack', '#runway', '#ledger', '#week'].flatMap((s) => [s + ' .ascii-pulse', s + ' .live-dot']).join(',')).length, ticking: [...document.documentElement.classList].filter((c) => c.startsWith('pulse-')), lights: document.querySelectorAll('#runway .rw-lights > i').length })`);
  check("nothing on the sheet pulses; the runway has its approach lights", still.dots === 0 && still.ticking.length === 0 && still.lights === 13, JSON.stringify(still));

  // a tile opens the list it counts, with as many rows as its number
  {
    const t = panel.stack.tiles[0];
    const r = await openAndRead(client, "[data-stack-tile]", 0);
    check("a stack tile opens its list", r.count === t.n && r.rows === t.n && r.closed, `count line "${r.head?.slice(0, 48)}", ${r.rows} rows, tile n ${t.n}`);
  }

  // the ledger: this week's deadlines, the records without a full patch, the week's new records, as panel.json has them
  const L = panel.ledger;
  const want = ledgerRows(L);
  const dueAlive = L.due.filter((r) => dueEnd(r.due) > Date.now());

  // the runway: the nearest deadline as a countdown, a dot per new record, a bar per record without a patch, a marker per deadline day
  const rw = await evaluate(client, `(() => { const c = document.querySelector('#runway'); if (!c) return null; const big = c.querySelector('[data-big-countdown]'); return { lead: c.querySelector('[data-lead]')?.dataset.name ?? null, big: big?.textContent ?? null, due: big?.dataset.bigCountdown ?? null, dots: [...c.querySelectorAll('[data-runway-dots]')].reduce((n, e) => n + e.children.length, 0), bars: c.querySelectorAll('[data-runway-bar]').length, marks: [...c.querySelectorAll('[data-runway-due]')].map((e) => Number(e.dataset.runwayDue)), w: Math.round(c.querySelector('[data-runway]')?.getBoundingClientRect().width ?? 0), outside: (() => { const box = c.querySelector('[data-runway]').getBoundingClientRect(); return [...c.querySelectorAll('[data-runway-due]')].filter((e) => { const r = e.getBoundingClientRect(); return r.left < box.left - 1 || r.right > box.right + 1; }).length; })(), scrolls: (() => { const s = c.querySelector('[data-runway]').parentElement; return s.scrollWidth > s.clientWidth + 1; })() }; })()`);
  check("runway shows, every deadline marker on its axis, no sideways scroll at this width", Boolean(rw) && rw.w >= 560 && rw.outside === 0 && !rw.scrolls, JSON.stringify(rw));
  if (dueAlive.length) {
    // days and hours from two days out, hours and minutes below that (lib/panel/dates.ts countdownParts)
    const mins = Math.floor((dueEnd(dueAlive[0].due) - Date.now()) / 60_000);
    const far = mins >= 2880;
    const got = (rw?.big?.match(/\d+/g) ?? []).map(Number);
    const gotMins = far ? got[0] * 1440 + got[1] * 60 : got[0] * 60 + got[1];
    // the page's clock and this one read a moment apart, and the far form drops the minutes
    check("runway leads with the nearest deadline and its countdown", rw?.lead === dueAlive[0].name && rw.due === dueAlive[0].due && got.length === 2 && gotMins <= mins + 2 && gotMins >= mins - (far ? 62 : 2), `page "${rw?.lead}" ${rw?.big}, panel.json "${dueAlive[0].name}" due ${dueAlive[0].due}, ${mins} min left`);
  }
  const perDot = Math.max(1, Math.ceil(Math.max(0, ...L.freshDays.map((d) => d.n)) / 27));
  check("runway draws a dot per new record", rw?.dots === L.freshDays.reduce((n, d) => n + Math.ceil(d.n / perDot), 0) && L.freshDays.reduce((n, d) => n + d.n, 0) === L.freshTotal, `${rw?.dots} dots, panel.json ${L.freshTotal} in ${L.freshDays.map((d) => d.n).join("+")}`);
  check("runway draws a bar per record without a patch", rw?.bars === Math.min(RUNWAY_OPEN_BARS, openRows(L).length), `${rw?.bars} bars`);
  check("runway marks each deadline day", rw?.marks.reduce((n, k) => n + k, 0) === dueAlive.length && rw.marks.length === new Set(dueAlive.map((r) => r.due)).size, `markers ${rw?.marks.join("+")}, ${dueAlive.length} deadlines`);
  const led = await evaluate(client, READ_LEDGER);
  check("ledger rows are panel.json's, in order", led.length === want.length && led.every((r, i) => r.kind === want[i].kind && r.href === want[i].href), `${led.length} rows: ${led.map((r) => `${r.kind} ${r.href}`).join(" | ")}`);
  const heads = await evaluate(client, `Object.fromEntries([...document.querySelectorAll('[data-ledger] [data-group]')].map((g) => [g.dataset.group, { count: g.querySelector('[data-head] [data-num]')?.textContent ?? '', note: g.querySelector('[data-head]')?.title ?? '' }]))`);
  check(
    "ledger columns carry the counts",
    Object.keys(heads).join(",") === "due,patch,new" && num(heads.due.count) === dueAlive.length && num(heads.patch.count) === L.noFullPatch && num(heads.new.count) === L.freshTotal && heads.new.note.includes(`${L.freshLoss} with confirmed impact`),
    Object.entries(heads).map(([k, h]) => `${k} ${h.count}`).join(", ") + `; panel.json ${dueAlive.length}, ${L.noFullPatch}, ${L.freshTotal} (${L.freshLoss} with confirmed impact)`,
  );
  // the first deadline is the runway's lead with its large countdown; the list's rows say the time left in words
  if (led.some((r) => r.kind === "due" && r.clock !== null)) {
    const clock = led.find((r) => r.kind === "due" && r.clock !== null).clock;
    check("ledger deadlines say the time left, in days or hours", /^(\d+ (days?|h|min) left|past due)$/.test(clock ?? ""), clock);
  }
  // a deadline counts as AI when an AI record without a full patch names one of its CVEs
  const isAi = (r) => r.type !== "not_ai";
  const aiCves = new Set(L.patch.filter(isAi).flatMap((r) => r.cves));
  const wantAi = (r) => (r.kind === "due" ? r.cves.some((c) => aiCves.has(c)) : isAi(r));
  const marks = led.map((r, i) => ({ page: r.stack, want: (want[i]?.stack ?? []).join(","), ai: r.aiMark, wantAi: Boolean(want[i] && wantAi(want[i])), dataAi: r.ai, kind: r.kind }));
  check("ledger tags the rows in the default stack", marks.every((m) => m.page === m.want), marks.filter((m) => m.page !== m.want).map((m) => `page "${m.page}" vs panel.json "${m.want}"`).join("; ") || `${marks.filter((m) => m.want).length} tagged`);
  check("ledger tags the AI records", marks.every((m) => (m.ai !== null) === m.wantAi && m.dataAi === (m.wantAi ? "1" : "0")), marks.map((m) => `${m.kind}:${m.ai ?? "-"}/${m.wantAi ? "ai" : "-"}`).join(" "));
  {
    const r = await openAndRead(client, '[data-ledger] [data-group="patch"] button');
    check("ledger: all without a full patch opens every record", r.count === L.noFullPatch && r.rows === L.patch.length && r.closed, `count line "${r.head?.slice(0, 48)}", ${r.rows} rows, panel.json ${L.patch.length}`);
  }
  if (L.later.length) {
    const r = await openAndRead(client, '[data-ledger] [data-group="due"] button');
    const all = L.due.length + L.later.length;
    check("ledger: later deadlines open every deadline ahead", r.count === all && r.rows === all && r.closed, `count line "${r.head?.slice(0, 48)}", ${r.rows} rows, panel.json ${all}`);
  }
  await evaluate(client, `document.querySelector('[data-filter="ai"]').click()`);
  await sleep(900);
  const aiOnly = await evaluate(client, `({ shown: [...document.querySelectorAll('[data-ledger] [data-row]')].filter((r) => !r.hidden).map((r) => r.dataset.row + r.dataset.ai), notes: document.querySelectorAll('[data-ledger] [data-note]').length, count: document.querySelector('[data-ledger] [data-group="new"] [data-head] [data-num]')?.textContent ?? '' })`);
  const aiRows = [
    ...dueAlive.filter(wantAi).slice(0, LEDGER_ROWS.due).map(() => "due1"),
    ...openRows(L).filter(isAi).slice(0, LEDGER_ROWS.patch).map(() => "patch1"),
    ...L.fresh.filter(isAi).slice(0, LEDGER_ROWS.fresh).map(() => "new1"),
  ];
  check("AI only shows the first AI rows of each list and counts them", aiOnly.shown.join(",") === aiRows.join(",") && num(aiOnly.count) === L.freshAi && aiOnly.notes === 3 - new Set(aiRows).size, `${JSON.stringify(aiOnly)}, expected ${aiRows.join(",") || "no rows"} and ${L.freshAi}`);
  await evaluate(client, `document.querySelector('[data-filter="all"]').click()`);
  await sleep(900);
  const back = await evaluate(client, `[...document.querySelectorAll('[data-ledger] [data-row]')].filter((r) => !r.hidden).length`);
  check("all brings every row back", back === want.length, `${back} rows`);

  // the week: six cells equal the counters, carry the site's levels, and their lists open
  const W = panel.week;
  const wk = await evaluate(client, `Object.fromEntries([...document.querySelectorAll('[data-week] [data-line]')].map((l) => [l.dataset.line, { value: l.querySelector('[data-num]')?.textContent ?? '', level: l.dataset.level || null, text: l.textContent.replace(/\\s+/g, ' ') }]))`);
  check("week: six cells", Object.keys(wk).join(",") === "published,critical,exploited,breaches,ai,patch-tuesday", Object.keys(wk).join(","));
  check("week published is the 7-day counter", num(wk.published?.value) === home.counters.cves_7d, `${wk.published?.value} vs ${home.counters.cves_7d}`);
  check("week critical is the 7-day counter", num(wk.critical?.value) === home.counters.critical_7d, `${wk.critical?.value} vs ${home.counters.critical_7d}`);
  check("week exploited is the 7-day KEV counter", num(wk.exploited?.value) === home.counters.kev_7d, `${wk.exploited?.value} vs ${home.counters.kev_7d}`);
  check("week breaches is the month's counter", num(wk.breaches?.value) === home.counters.breaches_month, `${wk.breaches?.value} vs ${home.counters.breaches_month}`);
  check("week AI is the roles' sum", num(wk.ai?.value) === W.ai.onAi + W.ai.usingAi && wk.ai?.text.includes(`of ${W.ai.total}`), `${wk.ai?.value} vs ${W.ai.onAi + W.ai.usingAi}`);
  check("week levels are panel.json's", wk.published?.level === String(W.published.level) && wk.exploited?.level === String(W.exploited.level), `published ${wk.published?.level}/${W.published.level}, exploited ${wk.exploited?.level}/${W.exploited.level}`);
  check("week patch tuesday is the next second Tuesday", wk["patch-tuesday"]?.text.includes(shortDate(W.patchTuesday)) && /today|tomorrow|in \d+ days/.test(wk["patch-tuesday"]?.text ?? ""), wk["patch-tuesday"]?.text.slice(0, 80));
  if (home.counters.cves_7d !== null) {
    const r = await openAndRead(client, '[data-week] [data-line="published"] button');
    check("week published opens its list", r.count === home.counters.cves_7d && r.rows > 0 && r.closed, `count line "${r.head?.slice(0, 40)}", ${r.rows} rows`);
  }
  if (home.counters.kev_7d) {
    const r = await openAndRead(client, '[data-week] [data-line="exploited"] button');
    check("week exploited opens its list", r.count === home.counters.kev_7d && r.rows === home.counters.kev_7d && r.closed, `count line "${r.head?.slice(0, 40)}", ${r.rows} rows`);
  }
  if (home.counters.breaches_month !== null) {
    const r = await openAndRead(client, '[data-week] [data-line="breaches"] button');
    check("week breaches opens the month's list", r.count === home.counters.breaches_month && r.listed && !r.error && r.rows === Math.min(home.counters.breaches_month, LIST_CAP) && r.closed, `count line "${r.head?.slice(0, 40)}", ${r.rows} rows${r.error ? `, error "${r.error}"` : ""}`);
  }

  // the footer
  const foot = await evaluate(client, `[...document.querySelectorAll('[data-panel-foot] a')].map((a) => a.getAttribute('href'))`);
  check("footer links lead to the live board and the briefing, never to the data files", foot.includes("/live") && foot.some((h) => h.startsWith("/briefing/")) && !foot.some((h) => /^\/(data|api|embed|stats|feed|llms|live\.json|changes)/.test(h)), `${foot.length} links: ${foot.join(" ")}`);

  // the hero's middle: this week's KEV additions as a dot-matrix numeral, the newest three under it
  const ex = await evaluate(client, `(() => { const e = document.querySelector('[data-exploited]'); return e && { value: e.dataset.value === "" ? null : Number(e.dataset.value), rows: [...e.querySelectorAll('[data-kev-row]')].map((r) => r.dataset.kevRow), w: e.getBoundingClientRect().width }; })()`);
  check("hero exploited is the 7-day KEV counter", ex?.value === home.counters.kev_7d && ex.w > 200, `page ${ex?.value} (${Math.round(ex?.w ?? 0)} px), home.json ${home.counters.kev_7d}`);
  const newest = panel.sieve.exploitedEntries.slice(0, 3).map((e) => e.cve);
  check("hero exploited lists the week's newest three", ex?.rows.join(",") === newest.join(","), `page ${ex?.rows.join(",")}, panel.json ${newest.join(",")}`);
  await sleep(1500);
  const inked = await evaluate(client, `(() => {
    const c = document.querySelector('[data-exploited] canvas');
    if (!c || !c.width) return 0;
    const px = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
    let n = 0;
    for (let i = 3; i < px.length; i += 4) if (px[i] > 200) n++;
    return n;
  })()`);
  check("hero exploited numeral draws", home.counters.kev_7d === null || inked > 400, `${inked} inked pixels`);
  if (home.counters.kev_7d) {
    const r = await openAndRead(client, "[data-exploited] button");
    check("hero exploited opens the week's list", r.count === home.counters.kev_7d && r.listed && r.rows === Math.min(home.counters.kev_7d, LIST_CAP) && r.closed, `count line "${r.head?.slice(0, 50)}", ${r.rows} rows, expected ${home.counters.kev_7d}`);
  }

  // a shared stack link applies, stores and recomputes: the verdict and the ledger's marks
  const rowKeys = new Set(want.flatMap((r) => [...r.cves, r.href]));
  const covering = stackFile.candidates.find((c) => !panel.stack.default.includes(c.key) && (c.items ?? []).some((it) => rowKeys.has(it.href) || it.cves.some((cve) => rowKeys.has(cve))));
  // the picks: one that covers a ledger row, one hit this week, a quiet one, one with new criticals only, and one under a key that has since changed
  const quietOne = stackFile.candidates.find((c) => c.tier === 5 && !c.kev7.length && !c.tail);
  const critOnly = stackFile.candidates.find((c) => c.tier === 4 && !panel.stack.default.includes(c.key));
  const [oldKey, newKey] = Object.entries(stackFile.aliases).find(([, now]) => !panel.stack.default.includes(now)) ?? [];
  const picks = [...new Set([...(covering ? [covering.key] : []), ...stackFile.candidates.filter((c) => c.kev7.length).slice(0, 1).map((c) => c.key), ...(quietOne ? [quietOne.key] : []), ...(critOnly ? [critOnly.key] : []), ...(newKey ? [newKey] : [])])];
  const asLinked = picks.map((k) => (k === newKey ? oldKey : k));
  const inOrder = picks.map((k) => stackFile.candidates.find((c) => c.key === k)).sort(byUrgency).map((c) => c.key);
  await navigate(client, `${base}/?final&stack=${asLinked.join(",")},not-a-product`, `${HOME_READY} && document.querySelector('[data-tiles][data-stack="ready"]')`);
  const shared = await evaluate(client, `({ tiles: [...document.querySelectorAll('[data-stack-tile]')].map((t) => t.dataset.stackTile), quiet: [...document.querySelectorAll('[data-stack-tile]')].map((t) => t.dataset.crit + '/' + (t.querySelector('[data-stack-badge]') ? 'badge' : 'plain')), stored: localStorage.getItem("gcd-radar:stack"), verdict: Number(document.querySelector('[data-verdict]').dataset.stackMatch), hidden: document.documentElement.classList.contains("stack-custom"), ledger: ${READ_LEDGER} })`);
  const expectMatch = stackMatches(stackFile, picks).length;
  check("?stack= applies the picks, most urgent first, an old key under its new name", shared.tiles.join(",") === inOrder.join(","), `${shared.tiles.join(",")} for ${asLinked.join(",")}${oldKey ? ` (${oldKey} is ${newKey} now)` : ""}`);
  check("?stack= stores the picks", shared.stored === picks.join(","), String(shared.stored));
  if (critOnly) {
    // the quiet signal: the tile carries the count without a coloured word, and under the tile's list are the CVEs themselves, apart from the exploited rows and uncoloured
    const at = inOrder.indexOf(critOnly.key);
    const drawer = await evaluate(client, `(async () => {
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      document.querySelector('[data-stack-tile="${critOnly.key}"]').click();
      for (let i = 0; i < 40 && !document.querySelector('[role="dialog"] [data-stack-crits]'); i++) await sleep(150);
      const d = document.querySelector('[role="dialog"]');
      const res = { crits: Number(d?.querySelector('[data-stack-crits]')?.dataset.stackCrits), listed: [...(d?.querySelectorAll('[data-stack-crit]') ?? [])].map((li) => li.dataset.stackCrit), rows: d?.querySelectorAll('ol > li').length ?? -1, red: d?.querySelectorAll('[data-stack-crits] [data-tag], [data-stack-crits] [data-cvss-band], [data-stack-crits] [class*="text-live"], [data-stack-crits] [class*="bg-live"]').length ?? -1 };
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
      await sleep(250);
      return res;
    })()`);
    check("new criticals are the quiet signal: no coloured word on the tile, their own uncoloured list in its drawer", shared.quiet[at] === `${critOnly.crit}/plain` && drawer.crits === critOnly.crit && drawer.listed.join(",") === critOnly.crits.map((c) => c.id).join(",") && drawer.rows === critOnly.n && drawer.red === 0, `${critOnly.key}: tile "${shared.quiet[at]}", drawer ${drawer.crits} with ${drawer.listed.length} listed, ${drawer.rows} exploited rows; stack.json ${critOnly.crit} with ${critOnly.crits.length} kept`);
  }
  check("a shared stack recomputes the verdict", shared.verdict === expectMatch && !shared.hidden, `verdict ${shared.verdict}, expected ${expectMatch}`);
  const hits = stackHits(stackFile, picks);
  const wantMarks = want.map((r) => rowStack(hits, { cves: r.cves, href: r.href }).join(","));
  check("a shared stack recomputes the ledger's marks", shared.ledger.length === want.length && shared.ledger.every((r, i) => r.stack === wantMarks[i] && r.ready === "ready"), `page ${shared.ledger.map((r) => r.stack || "-").join("|")}, expected ${wantMarks.map((m) => m || "-").join("|")}${covering ? ` (${covering.key} covers a row)` : " (no candidate covers a shown row)"}`);
  await navigate(client, `${base}/?final`, `${HOME_READY} && document.querySelector('[data-tiles][data-stack="ready"]')`);
  const kept = await evaluate(client, `[...document.querySelectorAll('[data-stack-tile]')].map((t) => t.dataset.stackTile).join(",")`);
  check("the stored stack comes back without the link", kept === inOrder.join(","), kept);

  // the chooser: the visitor's picks on top, every category with its count, search by name and by another name, a tick adds a tile, clearing goes back to the default
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
      res.ticked = [...document.querySelectorAll('[data-stack-tile]')].map((t) => t.dataset.stackTile);
      res.stored = localStorage.getItem("gcd-radar:stack");
      await type('');
      document.querySelector('[role="dialog"] [data-chooser-cat="${wanted?.cat}"]')?.click();
      await sleep(200);
      res.inCategory = document.querySelectorAll('[role="dialog"] [data-chooser-view="category"] ol > li').length;
      document.querySelector('[role="dialog"] [data-chooser-reset]')?.click();
      await sleep(300);
      res.cleared = [...document.querySelectorAll('[data-stack-tile]')].map((t) => t.dataset.stackTile);
      res.storedAfter = localStorage.getItem("gcd-radar:stack");
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
      await sleep(250);
      res.closed = !document.querySelector('[role="dialog"]');
      return res;
    })()`);
    const perCat = new Map();
    for (const c of stackFile.candidates) perCat.set(c.cat, (perCat.get(c.cat) ?? 0) + 1);
    check("chooser: the picks on top and the count line", chooser.count.startsWith(`${picks.length} of up to ${STACK_MAX} chosen`) && chooser.mine.join(",") === inOrder.join(",") && chooser.popular === 0, `"${chooser.count}", mine ${chooser.mine.join(",")}`);
    check("chooser: every category with its count", chooser.cats.length === perCat.size && chooser.cats.every(([k, n]) => perCat.get(k) === n) && chooser.cats.reduce((n, [, x]) => n + x, 0) === stackFile.candidates.length, chooser.cats.map(([k, n]) => `${k} ${n}`).join(", "));
    check("chooser: says how the lists are ordered, in text no smaller than 12 px", chooser.order.startsWith("Most urgent first") && chooser.small === 0, `${chooser.small} elements under 12 px; "${chooser.order.slice(0, 60)}"`);
    if (wanted) {
      check("chooser: search finds a product by its name and by another name it goes by", chooser.byName[0] === wanted.key && chooser.marked.toLowerCase() === wanted.label.toLowerCase() && chooser.byOther.includes(wanted.key) && chooser.none, `"${wanted.label}" → ${chooser.byName.slice(0, 3).join(",")}; "${wanted.aka[0]}" → ${chooser.byOther.slice(0, 3).join(",")}; nothing found shown ${chooser.none}`);
      const withIt = [...picks, wanted.key].map((k) => stackFile.candidates.find((c) => c.key === k)).sort(byUrgency).map((c) => c.key);
      check("chooser: a tick adds the product to the strip and to the stored picks", chooser.ticked.join(",") === withIt.join(",") && chooser.stored === [...picks, wanted.key].join(","), `${chooser.ticked.join(",")}; stored ${chooser.stored}`);
      check("chooser: a category opens its list", chooser.inCategory === perCat.get(wanted.cat), `${chooser.inCategory} rows, ${perCat.get(wanted.cat)} in ${wanted.cat}`);
    }
    check("chooser: clearing the choice brings the default back", chooser.cleared.join(",") === panel.stack.default.join(",") && chooser.storedAfter === null && chooser.closed, `${chooser.cleared.join(",")}; stored ${chooser.storedAfter}`);
  }

  // a stack as large as it gets: the link is capped at the limit and still fits the page on a phone
  {
    const many = stackFile.candidates.filter((c) => !c.tail).slice(0, STACK_MAX + 6).map((c) => c.key);
    const url = `${base}/?final&stack=${many.join(",")}`;
    await client.send("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 2, mobile: true });
    await navigate(client, url, `${HOME_READY} && document.querySelector('[data-tiles][data-stack="ready"]')`);
    const big = await evaluate(client, `({ tiles: document.querySelectorAll('[data-stack-tile]').length, scroll: document.documentElement.scrollWidth, inner: window.innerWidth })`);
    check(`a stack of ${STACK_MAX} is the most a link applies, and fits a phone`, big.tiles === STACK_MAX && big.scroll <= big.inner && url.length < 2000, `${big.tiles} tiles from ${many.length} keys, link ${url.length} characters, scrollWidth ${big.scroll} of ${big.inner}`);
    await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  }
  await evaluate(client, `localStorage.removeItem("gcd-radar:stack")`);

  // motion: on by default, each instrument building as it scrolls into view (a short viewport keeps the lower ones waiting), off under reduced motion
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 520, deviceScaleFactor: 1, mobile: false });
  await navigate(client, `${base}/`, `document.querySelector('[data-verdict][data-built]')`);
  const on = await evaluate(client, `({ motion: document.documentElement.classList.contains("motion"), waiting: document.querySelectorAll('[data-build]:not([data-built])').length })`);
  await evaluate(client, `window.scrollTo(0, document.body.scrollHeight)`);
  await sleep(600);
  const scrolled = await evaluate(client, `document.querySelectorAll('[data-build]:not([data-built])').length`);
  check("motion is on by default and builds on scroll", on.motion && on.waiting > 0 && scrolled === 0, `${JSON.stringify(on)}, after scrolling ${scrolled} waiting`);
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await client.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  await navigate(client, `${base}/`, HOME_READY);
  const off = await evaluate(client, `({ motion: document.documentElement.classList.contains("motion"), waiting: document.querySelectorAll('[data-build]:not([data-built])').length, building: document.querySelectorAll('.ascii-cells > i.b, .ascii-units > i.b').length, hidden: document.querySelectorAll('[data-num="wait"]').length })`);
  check("reduced motion: everything final at once", !off.motion && off.waiting === 0 && off.building === 0, JSON.stringify(off));
  await client.send("Emulation.setEmulatedMedia", { features: [] });

  // phones
  await client.send("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 2, mobile: true });
  await navigate(client, `${base}/?final`, HOME_READY);
  await sleep(500);
  const w = await evaluate(client, `({ scroll: document.documentElement.scrollWidth, inner: window.innerWidth })`);
  check("no sideways scroll on / at 375px", w.scroll <= w.inner, `scrollWidth ${w.scroll}, innerWidth ${w.inner}`);

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
  const view = {
    now: head.sweep,
    today: head.sweep.slice(0, 10),
    lastUpdated: head.sweep,
    columns: { patch: { live: count("patch") }, breach: { live: count("breach") }, supply_chain: count("supply_chain"), research: count("research") },
    stats: { ...home, series: { cves_by_year: [], ai_cves_by_quarter: [], kev_by_month: [], breaches_by_month: [], kev_lag_by_year: [] }, epss_top: [] },
    panel: {
      verdict: { ...panel.verdict, noFullPatch: panel.verdict.noFullPatch + 1 },
      stack: panel.stack,
      ledger: {
        ...L,
        fresh: [{ kind: "new", slug: FRESH_SLUG, title: fresh.title, lane: "patch", severity: 4, cvss: 9.8, type: "not_ai", created: fresh.created_at, product: "Check", cves: fresh.cve_ids, stack: [] }, ...L.fresh],
        freshTotal: L.freshTotal + 1,
        freshLoss: L.freshLoss + 1,
        freshDays: L.freshDays.map((d, i, all) => (i === all.length - 1 ? { ...d, n: d.n + 1, harm: d.harm + 1 } : d)),
      },
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
  const shown = await evaluate(client, `({ noPatch: ${noPatch}, first: document.querySelector('[data-ledger] [data-row="new"]')?.dataset.slug ?? null, total: document.querySelector('[data-ledger] [data-group="new"] [data-head] [data-num]')?.textContent ?? '' })`);
  check("a newer sweep: its numbers and rows are on the page", shown.noPatch === panel.verdict.noFullPatch + 1 && shown.first === FRESH_SLUG && num(shown.total) === L.freshTotal + 1, JSON.stringify(shown));
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
