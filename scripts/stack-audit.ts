/**
 * Audits the My stack catalog (lib/catalog) against the real files: what
 * every KEV entry lands on, which records and new critical CVEs each entry
 * claims, the file the site would build today, and the numbers a pull
 * request quotes. Nothing is written into the repository; pass a directory
 * to get the full lists as TSV files for reading by hand.
 *
 *   npx tsx scripts/stack-audit.ts            # the summary
 *   npx tsx scripts/stack-audit.ts <out dir>  # plus kev.tsv, tail.tsv, cross.tsv, criticals.tsv, records.tsv, order.tsv, stack.json
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { CATALOG, CATEGORIES, ancestorsOf, catalogKey } from "../lib/catalog";
import { affectedByCve } from "../lib/catalog/affected";
import { catalogMatchers, norm } from "../lib/catalog/match";
import { isDisclosedIncident } from "../lib/counting";
import { loadIncidents, loadStats } from "../lib/data";
import { addDays } from "../lib/lifecycle";
import { CRITICAL_MIN, STACK_DAYS, packStack, type StackCandidate } from "../lib/panel/picks";
import { buildStack, knownExploitedCves, tileOf } from "../lib/panel/stack";

const kb = (s: string) => `${(Buffer.byteLength(s) / 1024).toFixed(1)} KB`;

async function main() {
  const out = process.argv[2];
  const { incidents } = await loadIncidents();
  const stats = await loadStats();
  const kev = stats.kev?.entries ?? [];
  const recent = stats.cvesRecent?.cves ?? [];
  const nowIso = new Date().toISOString();
  const today = nowIso.slice(0, 10);
  const from = addDays(today, -STACK_DAYS);
  const matchers = catalogMatchers();

  // the catalog
  const perCat = new Map<string, number>();
  for (const e of CATALOG) perCat.set(e.cat, (perCat.get(e.cat) ?? 0) + 1);
  console.log(`catalog: ${CATALOG.length} curated entries (${CATALOG.filter((e) => e.level === "vendor").length} vendors, ${CATALOG.filter((e) => e.level === "product").length} products)`);
  console.log(
    CATEGORIES.filter((c) => perCat.has(c.key))
      .map((c) => `  ${c.label}: ${perCat.get(c.key)}`)
      .join("\n"),
  );

  // KEV
  const kevLines: string[] = [];
  const crossLines: string[] = [];
  const tail = new Map<string, { n: number; n90: number; products: Set<string> }>();
  let curated = 0;
  let curated90 = 0;
  let tail90 = 0;
  let in90 = 0;
  for (const e of kev) {
    const hit = matchers.filter((m) => m.columns(e.vendor, e.product, e.name));
    const recentRow = e.added > from && e.added <= today;
    if (recentRow) in90 += 1;
    if (hit.length) {
      curated += 1;
      if (recentRow) curated90 += 1;
    } else {
      if (recentRow) tail90 += 1;
      const t = tail.get(e.vendor.trim()) ?? { n: 0, n90: 0, products: new Set<string>() };
      t.n += 1;
      if (recentRow) t.n90 += 1;
      t.products.add(e.product);
      tail.set(e.vendor.trim(), t);
    }
    kevLines.push(`${e.added}\t${e.cve}\t${e.vendor}\t${e.product}\t${hit.map((m) => m.entry.key).join(", ") || "-"}`);
    // a hit by an entry that neither claims the vendor, nor sits under one that does, nor holds the product as its family: worth a look
    for (const m of hit) {
      const family = new Set([...m.entry.kevVendors, ...ancestorsOf(m.entry).flatMap((a) => a.kevVendors)].map(norm));
      const viaRule = m.entry.kev.some((r) => r.vendors?.map(norm).includes(norm(e.vendor)));
      if (!family.has(norm(e.vendor)) && !viaRule && !m.entry.family) crossLines.push(`${m.entry.key}\t${e.vendor}\t${e.product}\t${e.cve}`);
    }
  }
  console.log(`\nKEV: ${kev.length} entries; ${curated} on a curated entry, ${kev.length - curated} only on the long tail (${tail.size} vendors)`);
  console.log(`KEV in the last ${STACK_DAYS} days: ${in90}; ${curated90} on a curated entry, ${tail90} only on the long tail`);
  console.log(`cross-vendor term hits to read: ${crossLines.length}`);
  const clash = [...tail.keys()].filter((v) => CATALOG.some((e) => e.key === catalogKey(v)));
  if (clash.length) console.log(`!! long-tail vendors whose key a curated entry already has: ${clash.join(", ")}`);

  // records
  const exploited = incidents.filter((i) => i.severity >= 3 && !isDisclosedIncident(i) && i.first_reported > from && i.first_reported <= today);
  const recLines: string[] = [];
  let recHit = 0;
  for (const i of exploited) {
    const hit = matchers.filter((m) => m.record(i));
    if (hit.length) recHit += 1;
    recLines.push(`${hit.map((m) => m.entry.key).join(", ") || "-"}\t${i.title}\t${i.products.join("; ")}\t${i.tags.join(", ")}`);
  }
  console.log(`\nrecords: ${exploited.length} exploited in ${STACK_DAYS} days; ${recHit} on a curated entry`);

  // new criticals: the ones the site can show, so without those already known to be exploited
  const known = knownExploitedCves(incidents, kev);
  const scored = recent.filter((c) => c.score !== null && c.score >= CRITICAL_MIN);
  const crit = scored.filter((c) => !known.has(c.id.toUpperCase()));
  const critLines: string[] = [];
  let critHit = 0;
  const perEntry = new Map<string, number>();
  for (const c of crit) {
    const hit = matchers.filter((m) => m.describes(c.description));
    if (hit.length) critHit += 1;
    for (const m of hit) perEntry.set(m.entry.key, (perEntry.get(m.entry.key) ?? 0) + 1);
    critLines.push(`${hit.map((m) => m.entry.key).join(", ") || "-"}\t${c.id}\t${c.score}\t${c.description}`);
  }
  console.log(`\nnew criticals: ${scored.length} CVEs scored ${CRITICAL_MIN}+ in the file, ${scored.length - crit.length} of them already known to be exploited and left out; of the other ${crit.length}, ${critHit} matched to an entry by description, ${crit.filter((c) => !c.description).length} have no description`);
  console.log(
    `  most: ${[...perEntry]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([k, n]) => `${k} ${n}`)
      .join(", ")}`,
  );

  // the file the site would build today
  const t0 = Date.now();
  const file = buildStack(incidents, kev, today, nowIso, { criticals: recent, affected: affectedByCve((stats as unknown as Record<string, unknown>).fixes) });
  const ms = Date.now() - t0;
  const wire = JSON.stringify(packStack(file));
  const tiles = JSON.stringify(file.default.map((k) => tileOf(file.candidates.find((c) => c.key === k)!)));
  console.log(`\nstack file: ${file.candidates.length} candidates (${file.candidates.filter((c) => c.tail).length} long tail), ${Object.keys(file.aliases).length} old keys kept, built in ${ms} ms`);
  console.log(`  ${kb(wire)} as written, ${kb(JSON.stringify(file))} unpacked; the page's default tiles ${kb(tiles)}`);
  console.log(`  tiers: ${[1, 2, 3, 4, 5].map((t) => `${t}: ${file.candidates.filter((c) => c.tier === t).length}`).join(", ")}`);
  console.log(`  default: ${file.default.join(", ")}`);
  const line = (c: StackCandidate) => [c.tier, c.key, c.label, c.n, c.flag ?? "", c.cvss ?? "", c.due ?? "", c.late ?? "", c.crit || "", c.tail ? "tail" : c.level, c.why.join(" | ")].join("\t");

  if (out) {
    await fs.mkdir(out, { recursive: true });
    await Promise.all([
      fs.writeFile(path.join(out, "kev.tsv"), kevLines.join("\n")),
      fs.writeFile(path.join(out, "cross.tsv"), crossLines.sort().join("\n")),
      fs.writeFile(
        path.join(out, "tail.tsv"),
        [...tail]
          .sort((a, b) => b[1].n90 - a[1].n90 || b[1].n - a[1].n)
          .map(([v, t]) => `${v}\t${t.n}\t${t.n90}\t${[...t.products].join("; ")}`)
          .join("\n"),
      ),
      fs.writeFile(path.join(out, "criticals.tsv"), critLines.sort().join("\n")),
      fs.writeFile(path.join(out, "records.tsv"), recLines.sort().join("\n")),
      fs.writeFile(
        path.join(out, "order.tsv"),
        file.candidates
          .filter((c) => c.tier < 5 || c.n > 0)
          .map(line)
          .join("\n"),
      ),
      fs.writeFile(path.join(out, "stack.json"), wire),
    ]);
    console.log(`\nlists written to ${out}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
