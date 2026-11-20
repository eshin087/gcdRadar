#!/usr/bin/env node
/**
 * Checks a record's page and the quick-look drawer in a real browser against
 * the files they were built from.
 *
 * The record page, on a record whose CVE is on CISA's KEV list (picked from
 * /stats/stack.json, compared with /data/fix/<CVE>.json): the fix block
 * comes right after the title and summary and before the facts; it has the
 * PATCH, WORKAROUND and DEADLINE rows in that order, a cve.org link for the
 * CVE, at least one patch or advisory link, CISA's due date, and a numbered
 * source for every citation mark; every external link on the page opens in a
 * new tab with rel="noopener noreferrer"; the classification rows are folded
 * shut; no text is smaller than 12 px; nothing scrolls sideways on a phone.
 * A record with no CVE id shows no fix block.
 *
 * The quick look, from the home page: a My stack chip opens its list, a KEV
 * entry with no record of ours opens the quick look in place of the list
 * (one dialog at a time, the page does not navigate), the drawer shows the
 * fix block with the CVE's cve.org link, Esc returns to the list and a
 * second Esc closes it; the drawer fits a phone.
 *
 * Zero dependencies (scripts/lib/browser.mjs).
 *
 *   npm run build
 *   node scripts/check-incident.mjs                 # serves ./out on a free port
 *   node scripts/check-incident.mjs --url https://gcdradar.vercel.app
 *
 * Options: --dir <out dir>  --browser <chrome or edge>  --port <n>  --slug <record to check>  --verbose
 */
import { blockHosts, call, collectErrors, evaluate, launch, navigate, openSite, parseArgs, sleep } from "./lib/browser.mjs";

const args = parseArgs(process.argv.slice(2));
const verbose = Boolean(args.verbose);
const WORKER = "gcd-ai-radar-internet.eshin087.workers.dev";
const MIN_TEXT_PX = 12;

const checks = [];
function check(name, ok, detail) {
  checks.push({ name, ok, detail });
  if (verbose || !ok) console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? `: ${detail}` : ""}`);
}

const json = (base, path) => fetch(`${base}${path}`).then((r) => (r.ok ? r.json() : null));

/** What the record page shows, read in the page. */
const READ_PAGE = `(() => {
  const article = document.querySelector("article");
  const block = article?.querySelector("[data-fixblock]");
  const pos = (a, b) => Boolean(a && b && (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING));
  const ext = [...(article?.querySelectorAll('a[href^="http"]') ?? [])];
  let smallest = { px: 99, text: "" };
  for (const el of article?.querySelectorAll("*") ?? []) {
    const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 1);
    if (!own || !el.getClientRects().length) continue;
    const px = parseFloat(getComputedStyle(el).fontSize);
    if (px < smallest.px) smallest = { px, text: el.textContent.trim().slice(0, 40) };
  }
  return {
    hasBlock: Boolean(block),
    whatToDo: Boolean(article?.querySelector("[data-what-to-do]")),
    afterSummary: pos(article?.querySelector("h1"), block),
    beforeFacts: pos(block, article?.querySelector("[data-facts]")),
    rows: [...(block?.querySelectorAll("[data-fix-row]") ?? [])].map((r) => r.dataset.fixRow),
    checked: block?.dataset.fixChecked ?? null,
    cveRefs: [...(block?.querySelectorAll('a[data-fix-ref="cve"]') ?? [])].map((a) => a.href),
    refKeys: [...(block?.querySelectorAll("a[data-fix-ref]") ?? [])].map((a) => a.dataset.fixRef),
    fixLinks: [...(block?.querySelectorAll("a[data-fix-link]") ?? [])].map((a) => ({ kind: a.dataset.fixLink, href: a.href })),
    due: block?.querySelector("[data-fix-due]")?.dataset.fixDue ?? null,
    cited: [...new Set([...(block?.querySelectorAll("[data-fix-cite]") ?? [])].map((a) => Number(a.dataset.fixCite)))].sort((a, b) => a - b),
    citations: block?.querySelectorAll("[data-fix-citations] > li").length ?? 0,
    versions: block?.querySelectorAll("[data-fix-version]").length ?? 0,
    badLinks: ext.filter((a) => a.target !== "_blank" || !/\\bnoopener\\b/.test(a.rel) || !/\\bnoreferrer\\b/.test(a.rel)).map((a) => a.href).slice(0, 5),
    external: ext.length,
    classification: (() => { const d = article?.querySelector("details[data-classification]"); return d ? (d.open ? "open" : "closed") : "missing"; })(),
    heads: article?.querySelectorAll("[data-section-head]").length ?? 0,
    smallest,
    width: { scroll: document.documentElement.scrollWidth, inner: window.innerWidth },
  };
})()`;

async function pickKevRecord(base, stack) {
  if (typeof args.slug === "string") {
    const rec = await json(base, `/data/incidents/${args.slug}.json`);
    if (!rec?.cve_ids?.length) throw new Error(`--slug ${args.slug}: no such record, or it has no CVE id`);
    return { slug: args.slug, cve: rec.cve_ids[0], file: await json(base, `/data/fix/${rec.cve_ids[0]}.json`) };
  }
  const seen = new Set();
  for (const c of stack.candidates) {
    for (const it of c.items ?? []) {
      if (it.kind !== "kev" || it.external || !it.cves[0] || seen.has(it.cves[0])) continue;
      seen.add(it.cves[0]);
      const file = await json(base, `/data/fix/${it.cves[0]}.json`);
      // a record about exactly this CVE, already read by the fix stage: the page's block and the file agree one to one
      if (file?.record && file.fix.cves.length === 1 && file.fix.checked) return { slug: file.record.slug, cve: it.cves[0], file };
    }
  }
  return null;
}

async function recordPage(client, base, stack) {
  const pick = await pickKevRecord(base, stack);
  check("a KEV-listed record with fix details exists to check", Boolean(pick), pick ? `${pick.slug} (${pick.cve})` : "none in /stats/stack.json");
  if (!pick) return;
  const { slug, cve, file } = pick;
  const fix = file.fix;
  await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await navigate(client, `${base}/incidents/${slug}`, `document.querySelector("article h1")`);
  const p = await evaluate(client, READ_PAGE);
  check("the page shows the fix block", p.hasBlock);
  check("the fix block sits between the summary and the facts", p.afterSummary && p.beforeFacts, `after h1 ${p.afterSummary}, before facts ${p.beforeFacts}`);
  check("PATCH, WORKAROUND and DEADLINE, in that order", p.rows.slice(0, 3).join(",") === "patch,workaround,deadline", p.rows.join(","));
  check("the CVE links to its record on cve.org", p.cveRefs.includes(`https://www.cve.org/CVERecord?id=${cve}`), p.cveRefs.join(" "));
  check("the reference row also links NVD, CISA's entry and EPSS", ["nvd", "kev", "epss"].every((k) => p.refKeys.includes(k)), p.refKeys.join(","));
  const expected = [...fix.patch.links, ...fix.workaround.links];
  const direct = p.fixLinks.filter((l) => l.kind === "patch" || l.kind === "advisory");
  check("at least one patch or advisory link", direct.length >= 1, `${direct.length} on the page, ${expected.length} in the file`);
  check("every link in the file is on the page", expected.every((l) => p.fixLinks.some((x) => x.href === l.url)), `${p.fixLinks.length} of ${expected.length}`);
  check("the fixed versions equal the file's", p.versions === fix.patch.versions.length + fix.patch.recorded.length, `page ${p.versions}, file ${fix.patch.versions.length + fix.patch.recorded.length}`);
  check("CISA's due date equals the file's", p.due === (fix.deadline?.due ?? null), `page ${p.due}, file ${fix.deadline?.due}`);
  check("the block says when its sources were read", p.checked === fix.checked, `page ${p.checked}, file ${fix.checked}`);
  check("every citation mark has its numbered source", p.citations === fix.citations.length && p.cited.every((n) => n >= 1 && n <= p.citations), `marks ${p.cited.join(",")}, sources ${p.citations}, file ${fix.citations.length}`);
  check("every external link opens in a new tab with noopener noreferrer", p.badLinks.length === 0, `${p.external} links${p.badLinks.length ? `, wrong: ${p.badLinks.join(" ")}` : ""}`);
  check("the classification is folded shut", p.classification === "closed", p.classification);
  check("each section has its labelled head", p.heads >= 4, `${p.heads} heads`);
  check(`no text under ${MIN_TEXT_PX} px`, p.smallest.px >= MIN_TEXT_PX, `${p.smallest.px}px "${p.smallest.text}"`);

  await client.send("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 2, mobile: true });
  await navigate(client, `${base}/incidents/${slug}`, `document.querySelector("article h1")`);
  const m = await evaluate(client, READ_PAGE);
  check("the record page does not scroll sideways at 375px", m.width.scroll <= m.width.inner, `scrollWidth ${m.width.scroll}, innerWidth ${m.width.inner}`);
  check(`no text under ${MIN_TEXT_PX} px at 375px`, m.smallest.px >= MIN_TEXT_PX, `${m.smallest.px}px "${m.smallest.text}"`);

  // a record with no CVE id: no CVE record or CISA entry to quote, so no fix block
  const years = await json(base, "/data/years/index.json");
  const slim = (await json(base, `/data/slim/${years.years[0].year}.json`)) ?? [];
  const plain = slim.find((r) => (r.cve_ids ?? []).length === 0);
  if (plain) {
    await client.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
    await navigate(client, `${base}/incidents/${plain.slug}`, `document.querySelector("article h1")`);
    const q = await evaluate(client, READ_PAGE);
    check("a record with no CVE id shows no fix block", !q.hasBlock, plain.slug);
    check("its external links are safe too", q.badLinks.length === 0, q.badLinks.join(" "));
  } else check("a record with no CVE id exists to check", false);
}

const DIALOGS = `document.querySelectorAll('[role="dialog"]').length`;

async function waitFor(client, expression, tries = 80) {
  for (let i = 0; i < tries; i++) {
    if (await evaluate(client, `Boolean(${expression})`)) return true;
    await sleep(100);
  }
  return false;
}

async function quickLook(client, base, stack, { width, height, mobile }) {
  const at = `at ${width}px`;
  await client.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
  // a default chip whose list holds a KEV entry with no record of ours
  const cand = stack.default.map((k) => stack.candidates.find((c) => c.key === k)).find((c) => (c?.items ?? []).some((it) => it.kind === "kev" && it.external && it.cves[0]));
  check(`a default My stack chip lists a KEV entry without a record (${at})`, Boolean(cand), cand?.key ?? "none");
  if (!cand) return;
  const item = cand.items.find((it) => it.kind === "kev" && it.external && it.cves[0]);
  const cve = item.cves[0];
  await navigate(client, `${base}/?final`, `document.querySelector('[data-tiles][data-stack="ready"] [data-stack-tile]')`);
  const opened = await call(client, `(key) => { const t = document.querySelector('[data-stack-tile="' + key + '"]'); if (!t) return false; t.click(); return true; }`, cand.key);
  check(`the ${cand.key} chip is on the page (${at})`, opened);
  if (!opened) return;
  const listed = await waitFor(client, `document.querySelector('[role="dialog"] [data-quicklook-open]')`);
  check(`its list offers the quick look (${at})`, listed);
  if (!listed) return;
  await call(client, `(cve) => document.querySelector('[role="dialog"] [data-quicklook-open="' + cve + '"]').click()`, cve);
  const ready = await waitFor(client, `document.querySelector('[role="dialog"] [data-quicklook-state="ready"]')`);
  await sleep(450); // the drawer slides in over 0.3 s; measure it at rest
  const q = await evaluate(
    client,
    `(() => { const d = document.querySelector('[role="dialog"]'); const b = d?.querySelector("[data-fixblock]"); const panel = d?.querySelector("aside"); return {
      dialogs: ${DIALOGS}, target: d?.querySelector("[data-quicklook]")?.dataset.quicklook ?? null, state: d?.querySelector("[data-quicklook]")?.dataset.quicklookState ?? null,
      title: d?.querySelector("h2")?.textContent.trim() ?? "", block: Boolean(b), rows: [...(b?.querySelectorAll("[data-fix-row]") ?? [])].map((r) => r.dataset.fixRow),
      cveRef: b?.querySelector('a[data-fix-ref="cve"]')?.href ?? null, path: location.pathname, locked: document.documentElement.style.overflow === "hidden",
      fits: panel ? panel.getBoundingClientRect().right <= window.innerWidth + 1 && panel.scrollWidth <= panel.clientWidth + 1 : false,
      inner: (() => { const s = d?.querySelector("aside > div.overflow-y-auto"); return s ? s.scrollWidth <= s.clientWidth + 1 : false; })(),
    }; })()`,
  );
  check(`the quick look opens for ${cve} (${at})`, ready && q.target === cve && q.state === "ready", `state ${q.state}, target ${q.target}`);
  check(`one drawer at a time, on the same page (${at})`, q.dialogs === 1 && q.path === "/" && q.locked, `${q.dialogs} dialogs, path ${q.path}, page locked ${q.locked}`);
  check(`the drawer shows the fix block with its three rows (${at})`, q.block && q.rows.slice(0, 3).join(",") === "patch,workaround,deadline", q.rows.join(","));
  check(`the drawer links the CVE's record on cve.org (${at})`, q.cveRef === `https://www.cve.org/CVERecord?id=${cve}`, String(q.cveRef));
  check(`the drawer has a title (${at})`, q.title.length > 3, q.title);
  check(`the drawer fits the screen (${at})`, q.fits && q.inner, `panel fits ${q.fits}, body fits ${q.inner}`);
  // Esc closes the quick look and the list is back; a second Esc closes the list
  await evaluate(client, `window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }))`);
  const back = await waitFor(client, `document.querySelector('[role="dialog"] [data-stack-item]') && !document.querySelector("[data-quicklook]")`, 30);
  check(`Esc returns to the list (${at})`, back && (await evaluate(client, DIALOGS)) === 1);
  await evaluate(client, `window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }))`);
  const closed = await waitFor(client, `!document.querySelector('[role="dialog"]') && document.documentElement.style.overflow !== "hidden"`, 30);
  check(`a second Esc closes the list and frees the page (${at})`, closed);
}

async function run(client, base) {
  await client.send("Page.enable");
  await client.send("Runtime.enable");
  // the home page as built: its live layer would fetch the Worker
  await blockHosts(client, [WORKER]);
  const stack = await json(base, "/stats/stack.json");
  if (!stack) throw new Error("/stats/stack.json not found");
  await recordPage(client, base, stack);
  await quickLook(client, base, stack, { width: 1440, height: 900, mobile: false });
  await quickLook(client, base, stack, { width: 375, height: 812, mobile: true });
}

async function main() {
  const t0 = Date.now();
  const site = await openSite(args);
  const { client, close, exe } = await launch(args.browser);
  const errors = collectErrors(client);
  try {
    await run(client, site.base);
    const failed = checks.filter((c) => !c.ok);
    // the blocked Worker fetch is expected; anything else is a page error
    const real = [...new Set(errors)].filter((e) => !/ERR_BLOCKED_BY_CLIENT|Failed to fetch|Failed to load resource/.test(e));
    console.log(`\n${checks.length - failed.length}/${checks.length} record-page and quick-look checks pass in ${((Date.now() - t0) / 1000).toFixed(1)} s · ${exe.split(/[\\/]/).pop()} · ${site.base}`);
    if (real.length) console.log(`page errors (${real.length}):\n  ${real.slice(0, 10).join("\n  ")}`);
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
