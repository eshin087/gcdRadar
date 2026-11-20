import { describe, expect, it } from "vitest";
import { buildAiFlow, pickCase } from "@/lib/panel/ai-flow";
import { attackType, buildAttackTypes, weekIncidents } from "@/lib/panel/attack-types";
import { countdownParts, timeLeft } from "@/lib/panel/dates";
import { dueEnd, windowUsed } from "@/lib/panel/deadlines";
import { cveWindows, kevWeekHistory } from "@/lib/panel";
import { buildLedger, patchedCves } from "@/lib/panel/ledger";
import { bandOf, levelOf, quantile, ratioLevel } from "@/lib/panel/levels";
import { NEWS_EXPLOITED_KEPT, NEWS_KEPT, NEWS_NAMED, buildNews, newsList } from "@/lib/panel/news";
import { STACK_MAX, flagBadge, packStack, rowStack, stackHits, stackUrgency, unpackStack } from "@/lib/panel/picks";
import { STACK_DEFAULT_MAX, STACK_DEFAULT_MIN, buildStack, kevCatalogHref, knownExploitedCves, parsePicks, stackMatches, tileOf, type StackFile } from "@/lib/panel/stack";
import { buildSurface, techOf } from "@/lib/panel/technology";
import { kevName, recordCves, shortDate, slugKey } from "@/lib/panel/util";
import { patchTuesday, typicalBreachMonth, typicalCriticalWeek, typicalCveWeek } from "@/lib/panel/week";
import type { KevStatEntry } from "@/lib/stats-schema";
import { disclosedCve, incident } from "./fixtures";

const TODAY = "2026-10-29";
const NOW = "2026-10-29T23:30:00.000Z";

function kev(over: Partial<KevStatEntry>): KevStatEntry {
  return { cve: "CVE-2026-0001", added: "2026-10-27", due: "2026-11-17", vendor: "Vendor", product: "Product", name: "Flaw", ransomware: false, published: "2026-10-20", cvss: null, ...over };
}

describe("panel helpers", () => {
  it("names KEV entries without repeating the vendor", () => {
    expect(kevName("PHP Group", "PHP")).toBe("PHP");
    expect(kevName("Plex", "Plex Media Server")).toBe("Plex Media Server");
    expect(kevName("Linux", "Kernel")).toBe("Linux Kernel");
    expect(kevName("Microsoft", "")).toBe("Microsoft");
  });
  it("reads every CVE id a record names, once", () => {
    expect(recordCves({ cve_ids: ["CVE-2026-1"], tags: ["cve-2026-1", "CVE-2026-0002"], title: "Exploited CVE-2026-0003 flaw" }).sort()).toEqual(["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-1"]);
  });
  it("formats short dates and slugs", () => {
    expect(shortDate("2026-10-31")).toBe("31 Oct");
    expect(shortDate("2026-11-03")).toBe("3 Nov");
    expect(slugKey("Palo Alto Networks")).toBe("palo-alto-networks");
    expect(slugKey("Hugging Face libraries")).toBe("hugging-face-libraries");
  });
});

describe("levels", () => {
  it("judges a value against the quartiles of its history", () => {
    const history = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    const band = bandOf(history)!;
    expect(quantile(history, 0.25)).toBe(32.5);
    expect(levelOf(30, band)).toBe(0);
    expect(levelOf(50, band)).toBe(1);
    expect(levelOf(85, band)).toBe(2);
    expect(levelOf(200, band)).toBe(3);
  });
  it("says normal without enough history", () => {
    expect(bandOf([1, 2, 3])).toBeNull();
    expect(levelOf(999, null)).toBe(1);
  });
  it("compares a week with a typical week", () => {
    expect(ratioLevel(3232, 2063)).toBe(2);
    expect(ratioLevel(2000, 2063)).toBe(1);
    expect(ratioLevel(1000, 2063)).toBe(0);
    expect(ratioLevel(1000, null)).toBe(1);
  });
  it("counts CVEs in whole 24-hour windows back from the end", () => {
    const end = Date.parse(NOW);
    const at = (h: number) => new Date(end - h * 3_600_000).toISOString();
    const w = cveWindows([at(1), at(23.9), at(24.1), at(47), at(-1), at(24 * 20)], end, 3);
    expect(w).toEqual([0, 2, 2]);
  });
  it("sums KEV additions per 7-day window, today's week apart from the history", () => {
    const k = kevWeekHistory(["2026-10-29", "2026-10-23", "2026-10-22", "2026-10-15"], TODAY, 1);
    expect(k.now).toBe(2); // 23 Oct to 29 Oct
    expect(k.history[0]).toBe(1); // 16 Oct to 22 Oct
    expect(k.history.length).toBeGreaterThan(10);
  });
});

describe("attack types", () => {
  const base = { summary: "", tags: [], products: [], categories: ["general" as const], type: "not_ai" as const, lane: "breach" as const };
  it("files by the first rule that matches", () => {
    expect(attackType({ ...base, title: "Akira ransomware hits hospital chain" })).toBe("ransomware");
    expect(attackType({ ...base, title: "Malicious npm package steals tokens", lane: "supply_chain" })).toBe("supply");
    expect(attackType({ ...base, title: "China-nexus group exploits edge devices" })).toBe("espionage");
    expect(attackType({ ...base, title: "Deepfake CFO call costs firm $25M" })).toBe("fraud");
    expect(attackType({ ...base, title: "New infostealer spreads through ads" })).toBe("malware");
    expect(attackType({ ...base, title: "Agent tricked into leaking repo", type: "attack_on_ai", categories: ["agent_hijack"] as never })).toBe("ai");
    expect(attackType({ ...base, title: "Retailer confirms customer data stolen" })).toBe("breach");
    expect(attackType({ ...base, title: "Zero-day in VPN appliance exploited", lane: "patch" })).toBe("vuln");
    expect(attackType({ ...base, title: "Odd news", lane: "research" })).toBe("other");
  });
  it("counts the week's incidents, AI separately, disclosed CVEs left out, other last", () => {
    const week = weekIncidents(
      [
        incident({ first_reported: "2026-10-28", title: "Zero-day exploited in gateway", summary: "Attackers use the flaw against exposed appliances in the wild.", lane: "patch", type: "not_ai", categories: ["general"] }),
        incident({ first_reported: "2026-10-27", title: "Prompt injection exploit in assistant", summary: "A crafted page steers the assistant into running tools.", lane: "patch", type: "attack_on_ai", categories: ["prompt_injection"] }),
        incident({ first_reported: "2026-10-27", title: "Quiet item", lane: "research", type: "not_ai", categories: ["general"], tags: [], products: [], summary: "Nothing to match in this summary text at all." }),
        incident({ first_reported: "2026-10-22", title: "Outside the week, exploit", lane: "patch" }),
        disclosedCve({ first_reported: "2026-10-28" }),
      ],
      TODAY,
    );
    expect(week).toHaveLength(3);
    const rows = buildAttackTypes(week);
    expect(rows.map((r) => [r.key, r.n, r.ai])).toEqual([
      ["ai", 1, 1],
      ["vuln", 1, 0],
      ["other", 1, 0],
    ]);
  });
});

describe("attack surface", () => {
  it("sorts real KEV rows into technologies", () => {
    expect(techOf({ vendor: "Langflow", product: "Langflow", name: "Langflow Code Injection Vulnerability" })).toBe("AI stack");
    expect(techOf({ vendor: "Citrix", product: "NetScaler ADC", name: "Citrix NetScaler Memory Overflow" })).toBe("Network edge & VPN");
    expect(techOf({ vendor: "ConnectWise", product: "ScreenConnect", name: "ConnectWise ScreenConnect Path Traversal" })).toBe("Remote access & IT tools");
    expect(techOf({ vendor: "Linux", product: "Kernel", name: "Linux Kernel Missing Initialization" })).toBe("Operating systems");
    expect(techOf({ vendor: "Google", product: "Chromium V8", name: "Google Chromium V8 Type Confusion" })).toBe("Browsers");
    expect(techOf({ vendor: "PHP Group", product: "PHP", name: "PHP Remote Code Execution" })).toBe("Enterprise & web apps");
    expect(techOf({ vendor: "Microsoft", product: "SQL Server", name: "Microsoft SQL Server Remote Code Execution Vulnerability" })).toBe("Enterprise & web apps");
    expect(techOf({ vendor: "BeyondTrust", product: "Remote Support", name: "BeyondTrust Remote Support Authentication Bypass" })).toBe("Remote access & IT tools");
    expect(techOf({ vendor: "Siemens", product: "Software Center", name: "Siemens Software Center DLL Hijacking" })).toBe("OT & IoT");
    expect(techOf({ vendor: "Acme", product: "Widget", name: "Acme Widget Flaw" })).toBe("Other");
  });
  it("counts 90 days, bright for the last 30, Other last", () => {
    const rows = buildSurface(
      [
        kev({ cve: "CVE-1", vendor: "Cisco", product: "IOS XE", added: "2026-10-20" }),
        kev({ cve: "CVE-2", vendor: "Cisco", product: "ASA", added: "2026-09-01" }),
        kev({ cve: "CVE-3", vendor: "Acme", product: "Widget", added: "2026-10-20" }),
        kev({ cve: "CVE-4", vendor: "Linux", product: "Kernel", added: "2026-07-01" }),
      ],
      TODAY,
    );
    expect(rows).toEqual([
      { label: "Network edge & VPN", n: 2, recent: 1 },
      { label: "Other", n: 1, recent: 1 },
    ]);
  });
});

describe("the ledger", () => {
  const entries = [
    kev({ cve: "CVE-2026-0010", vendor: "PHP Group", product: "PHP", due: "2026-10-29", cvss: 9.2, added: "2026-10-26" }),
    kev({ cve: "CVE-2026-0011", vendor: "PHP Group", product: "PHP", due: "2026-10-29", cvss: 8.1, added: "2026-10-27", ransomware: true }),
    kev({ cve: "CVE-2026-0012", vendor: "Linux", product: "Kernel", due: "2026-10-31", cvss: 7.8 }),
    kev({ cve: "CVE-2026-0013", vendor: "Adobe", product: "Commerce", due: "2026-11-10" }),
    kev({ cve: "CVE-2026-0014", vendor: "Old", product: "Thing", due: "2026-10-01" }),
  ];
  const recs = [
    incident({ slug: "linux-kernel-record", lane: "patch", severity: 3, patch_status: "unpatched", cve_ids: ["CVE-2026-0012"], first_reported: "2026-10-28", created_at: "2026-10-28T06:00:00.000Z" }),
    incident({ slug: "netscaler", lane: "patch", severity: 3, patch_status: "unpatched", products: ["NetScaler ADC"], first_reported: "2026-10-27", created_at: "2026-10-27T06:00:00.000Z" }),
    incident({ slug: "partial", lane: "patch", severity: 3, patch_status: "partial", first_reported: "2026-10-28", created_at: "2026-10-28T07:00:00.000Z" }),
    incident({ slug: "closed", lane: "patch", severity: 3, patch_status: "unpatched", state: "closed", closed_at: "2026-10-20" }),
    incident({ slug: "loss", lane: "breach", severity: 4, type: "not_ai", categories: ["general"], first_reported: "2026-10-29", created_at: "2026-10-29T01:00:00.000Z" }),
    incident({ slug: "newest", lane: "supply_chain", severity: 3, first_reported: "2026-10-29", created_at: "2026-10-29T08:00:00.000Z" }),
    incident({ slug: "old-news", lane: "breach", severity: 4, first_reported: "2026-10-10", created_at: "2026-10-10T08:00:00.000Z" }),
    disclosedCve({ cve_ids: ["CVE-2026-0099"], state: "live", created_at: "2026-10-29T02:00:00.000Z" }),
  ];
  const stack: StackFile = {
    generated_at: NOW,
    default: ["linux"],
    aliases: {},
    candidates: [
      {
        key: "linux",
        label: "Linux",
        kind: "vendor",
        vendor: "Linux kernel",
        cat: "os",
        level: "product",
        n: 1,
        flag: "patch by 31 Oct",
        why: ["CISA deadline 2026-10-31"],
        due: "2026-10-31",
        late: null,
        patch: null,
        impact: false,
        flagScore: 7.8,
        cvss: 7.8,
        crit: 0,
        tier: 1,
        kev7: [],
        href: kevCatalogHref("Linux"),
        items: [{ kind: "kev", name: "Linux Kernel", cves: ["CVE-2026-0012"], date: "2026-10-27", due: "2026-10-31", cvss: 7.8, open: "due", href: "/incidents/linux-kernel-record", external: false }],
      },
    ],
  };
  const l = buildLedger(recs, entries, stack, TODAY, { entries: [{ cve: "CVE-2026-0010", patches: [{}], links: [] }, { cve: "CVE-2026-0012", patches: [], links: [{ kind: "advisory" }] }] } as unknown as Parameters<typeof buildLedger>[4]);

  it("groups this week's deadlines by vendor, product and day, nearest first, later ones apart", () => {
    expect(l.due.map((r) => r.name)).toEqual(["PHP", "Linux Kernel"]);
    expect(l.due[0]).toMatchObject({ cves: ["CVE-2026-0010", "CVE-2026-0011"], cvss: 9.2, ransomware: true, added: "2026-10-27", external: true, stack: [] });
    expect(l.due[1]).toMatchObject({ href: "/incidents/linux-kernel-record", external: false, stack: ["Linux"] });
    expect(l.later.map((r) => r.name)).toEqual(["Adobe Commerce"]);
  });
  it("says whether a patch is published for a deadline's first CVE", () => {
    // PHP's first CVE has a fixed version in the fix file; Linux's has an advisory only; Adobe's is not in the file
    expect(l.due.map((r) => r.fix)).toEqual([true, false]);
    expect(l.later[0]!.fix).toBe(false);
    expect([...patchedCves({ entries: [{ cve: "CVE-1", patches: [], links: [{ kind: "patch" }] }, { cve: "CVE-2", patches: [], links: [] }] } as unknown as Parameters<typeof patchedCves>[0])]).toEqual(["CVE-1"]);
    expect(patchedCves(null).size).toBe(0);
  });
  it("lists records without a full patch, unpatched first", () => {
    expect(l.patch.map((r) => r.slug)).toEqual(["linux-kernel-record", "netscaler", "partial"]);
    expect(l.patch[0]).toMatchObject({ stack: ["Linux"] });
    expect(l.patch[1]).toMatchObject({ name: "NetScaler ADC", patch: "unpatched", stack: [] });
    expect(l.noFullPatch).toBe(3);
    expect(l.exploitedLive).toBe(6);
  });
  it("marks rows by the picks' items, for the browser's own picks too", () => {
    const hits = stackHits(stack, ["linux"]);
    expect(rowStack(hits, { cves: ["CVE-2026-0012"] })).toEqual(["Linux"]);
    expect(rowStack(hits, { href: "/incidents/linux-kernel-record" })).toEqual(["Linux"]);
    expect(rowStack(hits, { cves: ["CVE-2026-0010"], href: "/incidents/other" })).toEqual([]);
    expect(rowStack(stackHits(stack, []), { cves: ["CVE-2026-0012"] })).toEqual([]);
  });
});

describe("the week", () => {
  it("finds the next Patch Tuesday, the second Tuesday of the month", () => {
    expect(patchTuesday("2026-11-09")).toBe("2026-11-10");
    expect(patchTuesday("2026-11-10")).toBe("2026-11-10");
    expect(patchTuesday("2026-11-11")).toBe("2026-12-08");
    expect(patchTuesday("2026-10-13")).toBe("2026-10-13");
    expect(patchTuesday("2026-12-31")).toBe("2027-01-12");
  });
  it("takes a typical week from the year's total over the days elapsed", () => {
    const source = { name: "NVD", url: "https://nvd.nist.gov/", license: "public domain" };
    expect(typicalCveWeek({ fetched_at: "2026-01-14T12:00:00.000Z", source, years: [{ year: 2026, total: 1400 }] })).toBe(700);
    expect(typicalCveWeek({ fetched_at: "2026-01-10T12:00:00.000Z", source, years: [{ year: 2026, total: 1000 }] })).toBeNull();
    expect(typicalCveWeek(null)).toBeNull();
  });
  it("averages the daily file's days before this week for a typical critical week", () => {
    const source = { name: "NVD", url: "https://nvd.nist.gov/", license: "public domain" };
    const days: Record<string, { cves: number; critical: number }> = {};
    for (let k = 0; k < 20; k++) days[`2026-10-${String(k + 1).padStart(2, "0")}`] = { cves: 500, critical: 40 + (k % 2) };
    days["2026-10-27"] = { cves: 900, critical: 300 };
    expect(typicalCriticalWeek({ fetched_at: NOW, source, days }, TODAY)).toBe(284);
    expect(typicalCriticalWeek({ fetched_at: NOW, source, days: { "2026-10-01": { cves: 1, critical: 1 } } }, TODAY)).toBeNull();
    expect(typicalCriticalWeek(null, TODAY)).toBeNull();
  });
  it("takes the median month of breaches over the months before", () => {
    const list = [{ added: "2026-10-01" }, { added: "2026-10-12" }, { added: "2026-10-30" }, { added: "2026-09-03" }, { added: "2026-11-03" }];
    expect(typicalBreachMonth(list, "2026-11", 3)).toBe(1);
    expect(typicalBreachMonth(list, "2026-11", 2)).toBe(2);
    expect(typicalBreachMonth([], "2026-11")).toBeNull();
  });
});

describe("how AI shows up", () => {
  it("splits the week by AI role and names techniques, targets and a case", () => {
    const week = [
      incident({ type: "attack_on_ai", categories: ["agent_hijack", "infra_vuln"], targets: ["framework_or_tooling"], severity: 3, source_count: 1 }),
      incident({ type: "attack_on_ai", categories: ["agent_hijack"], targets: ["framework_or_tooling", "n/a"], severity: 4, title: "The worst one" }),
      incident({ type: "attack_on_ai", categories: ["prompt_injection"], targets: ["open_weight_model"], severity: 3 }),
      incident({ type: "ai_enabled_attack", categories: ["ai_assisted_intrusion"], targets: ["individual_victims"] }),
      incident({ type: "not_ai", categories: ["general"], targets: ["n/a"] }),
    ];
    const all = [...week.map((i) => ({ ...i, first_reported: "2026-10-28" })), disclosedCve({ first_reported: "2026-10-28", type: "attack_on_ai", cve_ids: ["CVE-2026-0100"] })];
    const f = buildAiFlow(week, all, [kev({ vendor: "Langflow", product: "Langflow", added: "2026-03-01" }), kev({ vendor: "Langflow", product: "Langflow", added: "2025-12-01" })], TODAY);
    expect([f.total, f.target.n, f.weapon.n, f.none]).toEqual([5, 3, 1, 1]);
    expect(f.target.techniques.map((t) => `${t.n} ${t.label}`)).toEqual(["2 agent hijack", "1 prompt injection"]);
    expect(f.weapon.techniques[0]!.label).toBe("AI intrusion");
    expect(f.target.targets.map((t) => t.key)).toEqual(["framework_or_tooling", "open_weight_model"]);
    expect(f.target.case?.title).toBe("The worst one");
    expect(f.weak).toMatchObject({ cves: 1, exploited: 0, kevYear: 1, kevProducts: ["Langflow"] });
  });
  it("picks the case by severity, then sources, then the newest", () => {
    const a = incident({ severity: 3, first_reported: "2026-10-28", title: "a" });
    const b = incident({ severity: 3, first_reported: "2026-10-29", title: "b" });
    expect(pickCase([a, b])?.title).toBe("b");
    expect(pickCase([])).toBeNull();
  });
});

describe("my stack", () => {
  const entries = [
    kev({ cve: "CVE-2026-1001", vendor: "Microsoft", product: "Windows", added: "2026-10-01", due: "2026-10-20" }),
    kev({ cve: "CVE-2026-1002", vendor: "Microsoft", product: "SharePoint", added: "2026-09-10", due: "2026-10-01" }),
    kev({ cve: "CVE-2026-1003", vendor: "Linux", product: "Kernel", added: "2026-10-28", due: "2026-10-31", cvss: 7.8 }),
    // a deadline three days gone: past due, not forgotten
    kev({ cve: "CVE-2026-1004", vendor: "Cisco", product: "IOS XE", added: "2026-10-05", due: "2026-10-26", cvss: 9.1 }),
    // a deadline further out than three days
    kev({ cve: "CVE-2026-1005", vendor: "Langflow", product: "Langflow", added: "2026-10-10", due: "2026-11-12", cvss: 9.8 }),
    kev({ cve: "CVE-2026-1006", vendor: "Old", product: "Thing", added: "2026-01-01", due: "2026-01-22" }),
    // an older, scored entry beside an unscored record without a patch (below)
    kev({ cve: "CVE-2026-1007", vendor: "Veeam", product: "Backup & Replication", added: "2026-09-15", due: "2026-10-06", cvss: 9.9 }),
  ];
  const recs = [
    // the same CVE as a KEV entry: counted once
    incident({ title: "Windows flaw exploited", products: ["Windows"], cve_ids: ["CVE-2026-1001"], severity: 3, first_reported: "2026-10-02", state: "closed", closed_at: "2026-10-20", lane: "patch" }),
    // a new exploited record without a CVE: counted, and red while unpatched
    incident({ title: "Citrix gateway attacks", products: ["NetScaler ADC"], severity: 3, first_reported: "2026-10-27", lane: "patch", patch_status: "unpatched", type: "not_ai", categories: ["general"] }),
    incident({ title: "LiteLLM key theft", products: ["LiteLLM"], severity: 3, first_reported: "2026-10-20", type: "attack_on_ai", lane: "supply_chain" }),
    incident({ title: "LiteLLM proxy hijack", products: ["LiteLLM"], severity: 3, first_reported: "2026-10-21", type: "attack_on_ai", lane: "patch", patch_status: "patched" }),
    // a passing mention in the summary does not make a record Microsoft's
    incident({ title: "Retailer breach", summary: "The attackers used a Microsoft Teams lure to reach staff before the breach.", products: ["Retail POS"], severity: 4, lane: "breach", first_reported: "2026-10-28" }),
    // confirmed impact and nothing else
    incident({ title: "Zoom client flaw drained accounts", products: ["Zoom"], severity: 4, lane: "breach", first_reported: "2026-10-25", type: "not_ai", categories: ["general"] }),
    // exploited, no patch, and no CVSS score on it yet
    incident({ title: "Backup servers hit through an unpatched flaw", products: ["Veeam Backup & Replication"], severity: 3, lane: "patch", patch_status: "unpatched", first_reported: "2026-10-28", type: "not_ai", categories: ["general"] }),
  ];
  const criticals = [
    { id: "CVE-2026-2001", published: "2026-10-28T10:00:00.000Z", score: 9.8, severity: "CRITICAL" as const, version: "3.1" as const, description: "PostgreSQL before 18.2 allows an unauthenticated attacker to run code." },
    { id: "CVE-2026-2002", published: "2026-10-27T10:00:00.000Z", score: 9.1, severity: "CRITICAL" as const, version: "3.1" as const, description: "The Shop Sync plugin for WordPress is vulnerable to SQL injection through its PostgreSQL connector." },
    { id: "CVE-2026-2003", published: "2026-10-28T10:00:00.000Z", score: 8.9, severity: "HIGH" as const, version: "3.1" as const, description: "PostgreSQL before 18.2 leaks memory." },
    { id: "CVE-2026-2004", published: "2026-10-01T10:00:00.000Z", score: 10, severity: "CRITICAL" as const, version: "3.1" as const, description: "PostgreSQL before 17.9 allows code execution." },
    { id: "CVE-2026-2005", published: "2026-10-27T10:00:00.000Z", score: 9.9, severity: "CRITICAL" as const, version: "3.1" as const, description: "Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core)." },
  ];
  const file = buildStack(recs, entries, TODAY, NOW, { criticals });
  const tile = (key: string) => file.candidates.find((c) => c.key === key)!;

  it("lists the whole catalog, quiet products included, and the long tail of CISA's list", () => {
    expect(file.candidates.length).toBeGreaterThan(400);
    expect(tile("postgresql")).toMatchObject({ label: "PostgreSQL", cat: "database", n: 0, flag: null });
    expect(tile("old")).toMatchObject({ label: "Old", cat: "kev", tail: true, n: 0, tier: 5, also: ["Thing"] });
    expect(new Set(file.candidates.map((c) => c.key)).size).toBe(file.candidates.length);
  });
  it("counts KEV entries and exploited records once per CVE", () => {
    expect(tile("microsoft").n).toBe(2);
    expect(tile("citrix").n).toBe(1);
    expect(tile("litellm").n).toBe(2);
  });
  it("gives a vendor everything its products hold", () => {
    expect(tile("windows").n).toBe(1);
    expect(tile("sharepoint").n).toBe(1);
    expect(tile("netscaler")).toMatchObject({ n: 1, flag: "no patch yet" });
    expect(tile("citrix").items).toEqual(tile("netscaler").items);
    expect(tile("cisco-ios").n).toBe(1);
  });
  it("lists exactly what it counts, open items first, a KEV entry linking the record that names it", () => {
    for (const c of file.candidates) expect(c.items).toHaveLength(c.n);
    const ms = tile("microsoft").items!;
    expect(ms.map((x) => x.cves[0])).toEqual(["CVE-2026-1001", "CVE-2026-1002"]);
    expect(ms[0]).toMatchObject({ kind: "kev", name: "Microsoft Windows", date: "2026-10-01", due: "2026-10-20", open: null, external: false });
    expect(ms[0]!.href).toMatch(/^\/incidents\/fixture-incident-\d+$/);
    expect(ms[1]).toMatchObject({ kind: "kev", href: "https://nvd.nist.gov/vuln/detail/CVE-2026-1002", external: true });
    expect(tile("linux").items![0]).toMatchObject({ kind: "kev", open: "due", due: "2026-10-31" });
    expect(tile("citrix").items).toMatchObject([{ kind: "record", name: "Citrix gateway attacks", cves: [], open: "unpatched", external: false }]);
    expect(tile("litellm").items!.map((x) => x.name)).toEqual(["LiteLLM proxy hijack", "LiteLLM key theft"]);
    expect(tile("litellm").items!.every((x) => x.open === null)).toBe(true);
  });
  it("points a vendor at CISA's catalog and a family at its product page; the page's tiles carry no lists", () => {
    expect(tile("microsoft").href).toBe(kevCatalogHref("Microsoft"));
    expect(tile("microsoft").href).toBe("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=Microsoft");
    expect(tile("litellm").href).toBe("/products/litellm");
    const t = tileOf(tile("microsoft"));
    expect("items" in t || "crits" in t || "also" in t || "aka" in t).toBe(false);
    expect(t).toMatchObject({ key: "microsoft", n: 2, tier: 5, crit: 0 });
  });
  it("flags only what is exploited and open, a deadline within three days first", () => {
    expect(tile("microsoft")).toMatchObject({ flag: null, tier: 5 });
    expect(tile("linux")).toMatchObject({ flag: "patch by 31 Oct", why: ["CISA deadline 2026-10-31"], due: "2026-10-31", late: null, tier: 1, cvss: 7.8 });
    expect(tile("cisco")).toMatchObject({ flag: "past due 26 Oct", why: ["CISA deadline passed 2026-10-26"], due: null, late: "2026-10-26", tier: 1 });
    expect(tile("cisco").items![0]).toMatchObject({ open: "due", due: "2026-10-26" });
    expect(tile("langflow")).toMatchObject({ flag: "patch by 12 Nov", tier: 2, cvss: 9.8 });
    expect(tile("citrix")).toMatchObject({ flag: "no patch yet", patch: "unpatched", tier: 1 });
    expect(tile("zoom")).toMatchObject({ flag: "confirmed impact", impact: true, tier: 3 });
    expect(tile("litellm")).toMatchObject({ flag: null, tier: 5 });
  });
  it("carries the score of the item behind the flag, and says so when that item has none yet", () => {
    expect(tile("linux").flagScore).toBe(7.8);
    expect(tile("cisco").flagScore).toBe(9.1);
    expect(tile("langflow").flagScore).toBe(9.8);
    // records without a CVSS score: nothing to show, whatever else the product holds
    expect(tile("citrix")).toMatchObject({ flag: "no patch yet", flagScore: null, cvss: null });
    expect(tile("zoom")).toMatchObject({ flag: "confirmed impact", flagScore: null });
    // Veeam's unpatched record has no score, its older KEV entry has 9.9: none to show, 9.9 to be ordered by
    expect(tile("veeam")).toMatchObject({ flag: "no patch yet", n: 2, flagScore: null, cvss: 9.9, tier: 1 });
    // no flag, no flag score
    expect(tile("microsoft").flagScore).toBeNull();
    expect(tile("postgresql")).toMatchObject({ flagScore: null, cvss: 9.8 });
  });
  it("counts new critical CVEs apart from the flags: 9.0 and up, the last 14 days, the product as the subject", () => {
    expect(tile("postgresql")).toMatchObject({ crit: 1, flag: null, tier: 4, cvss: 9.8, n: 0 });
    expect(tile("postgresql").crits).toEqual([{ id: "CVE-2026-2001", score: 9.8, published: "2026-10-28", name: "PostgreSQL" }]);
    // a plugin for WordPress is not WordPress, and its connector is not PostgreSQL
    expect(tile("wordpress").crit).toBe(0);
  });
  it("names the product each critical CVE is about, on its vendor's list too, and gives a tile the highest few", () => {
    // WebLogic and Fusion Middleware both hold it; the first in the catalog names it
    expect(tile("oracle")).toMatchObject({ crit: 1, tier: 4, crits: [{ id: "CVE-2026-2005", score: 9.9, name: "WebLogic Server" }] });
    expect(tile("weblogic").crits).toEqual(tile("oracle").crits);
    expect(tileOf(tile("oracle")).crits).toEqual(tile("oracle").crits);
    const many = Array.from({ length: 12 }, (_, k) => ({ id: `CVE-2026-3${String(k).padStart(3, "0")}`, published: "2026-10-28T10:00:00.000Z", score: 9 + k / 20, severity: "CRITICAL" as const, version: "3.1" as const, description: "PostgreSQL before 18.2 allows code execution." }));
    const pg = buildStack([], [], TODAY, NOW, { criticals: many }).candidates.find((c) => c.key === "postgresql")!;
    expect(pg.crit).toBe(12);
    expect(pg.crits!.map((c) => c.score)).toEqual([9.55, 9.5, 9.45, 9.4, 9.35, 9.3, 9.25, 9.2]);
    expect(tileOf(pg).crits!.map((c) => c.score)).toEqual([9.55, 9.5, 9.45]);
  });
  it("leaves a CVE that is already known to be exploited out of the new criticals", () => {
    const pg = (id: string) => ({ id, published: "2026-10-28T10:00:00.000Z", score: 9.8, severity: "CRITICAL" as const, version: "3.1" as const, description: "PostgreSQL before 18.2 allows an unauthenticated attacker to run code." });
    const list = [pg("CVE-2026-4001"), pg("CVE-2026-4002"), pg("CVE-2026-4003"), pg("CVE-2026-4004")];
    // one on CISA's list, one named by an exploited record of ours, one only disclosed (severity 2), one nobody has seen used
    const onList = [kev({ cve: "CVE-2026-4001", vendor: "PostgreSQL", product: "PostgreSQL", added: "2026-10-29", due: "2026-11-19", cvss: 9.8 })];
    const ours = [
      incident({ title: "PostgreSQL servers taken over", products: ["PostgreSQL"], cve_ids: ["CVE-2026-4002"], severity: 3, first_reported: "2026-10-29", lane: "patch", patch_status: "patched", type: "not_ai", categories: ["general"] }),
      incident({ title: "PostgreSQL flaw disclosed", products: ["PostgreSQL"], cve_ids: ["CVE-2026-4003"], severity: 2, first_reported: "2026-10-29", lane: "patch", patch_status: "patched", type: "not_ai", categories: ["general"] }),
    ];
    expect([...knownExploitedCves(ours, onList)].sort()).toEqual(["CVE-2026-4001", "CVE-2026-4002"]);
    const built = buildStack(ours, onList, TODAY, NOW, { criticals: list }).candidates.find((c) => c.key === "postgresql")!;
    expect(built.crits?.map((c) => c.id)).toEqual(["CVE-2026-4003", "CVE-2026-4004"]);
    expect(built.crit).toBe(2);
    // the exploited two are among its items instead, so nothing is listed twice
    expect(built.items!.flatMap((x) => x.cves).sort()).toEqual(["CVE-2026-4001", "CVE-2026-4002"]);
    // and for every product of the shared fixture: no id on both lists
    for (const c of file.candidates) {
      const exploited = new Set((c.items ?? []).flatMap((x) => x.cves));
      expect((c.crits ?? []).filter((x) => exploited.has(x.id)), c.key).toEqual([]);
    }
  });
  it("takes the CVE Program's vendor and product names over the description when a file has them", () => {
    const named = buildStack(recs, entries, TODAY, NOW, { criticals, affected: new Map([["CVE-2026-2001", [{ vendor: "Redis", product: "Redis" }]], ["CVE-2026-2002", [{ vendor: "Old", product: "Thing" }]]]) });
    const of = (key: string) => named.candidates.find((c) => c.key === key)!;
    expect(of("postgresql").crit).toBe(0);
    expect(of("redis").crits?.map((c) => c.id)).toEqual(["CVE-2026-2001"]);
    expect(of("old")).toMatchObject({ crit: 1, tier: 4 });
  });
  it("orders every list by urgency: no full patch or a near deadline, later deadlines, impact, new criticals, quiet", () => {
    const order = file.candidates.map((c) => c.key);
    const at = (key: string) => order.indexOf(key);
    expect(file.candidates.map((c) => c.tier)).toEqual([...file.candidates.map((c) => c.tier)].sort((a, b) => a - b));
    // inside the first tier the higher CVSS leads: Veeam's 9.9 (from its other entry) over Cisco's 9.1 over Linux's 7.8, the unscored last
    expect(at("veeam")).toBeLessThan(at("cisco"));
    expect(at("cisco")).toBeLessThan(at("linux"));
    expect(at("linux")).toBeLessThan(at("citrix"));
    expect(at("linux")).toBeLessThan(at("langflow"));
    expect(at("langflow")).toBeLessThan(at("zoom"));
    expect(at("zoom")).toBeLessThan(at("postgresql"));
    expect(at("postgresql")).toBeLessThan(at("microsoft"));
    for (const c of file.candidates) expect(c.tier).toBe(stackUrgency(c, TODAY));
  });
  it("defaults to the most urgent of the best-known products, one per vendor family, filled up on a quiet day", () => {
    expect(file.default.slice(0, 5)).toEqual(["veeam", "cisco", "linux", "citrix", "langflow"]);
    expect(file.default).not.toContain("netscaler");
    expect(file.default).not.toContain("old");
    expect(file.default.length).toBeGreaterThanOrEqual(STACK_DEFAULT_MIN);
    expect(file.default.length).toBeLessThanOrEqual(STACK_DEFAULT_MAX);
    const quiet = buildStack([], [], TODAY, NOW);
    expect(quiet.default).toHaveLength(STACK_DEFAULT_MIN);
    expect(quiet.candidates.every((c) => c.tier === 5 && c.n === 0)).toBe(true);
  });
  it("matches the week's KEV additions to the picks, for the sieve", () => {
    expect(stackMatches(file, ["linux", "microsoft"]).map((m) => m.cve)).toEqual(["CVE-2026-1003"]);
    expect(stackMatches(file, ["microsoft"])).toEqual([]);
    expect(stackMatches(file, ["linux", "linux"])).toHaveLength(1);
  });
  it("reads picks from a URL: known keys only, no repeats, a changed key by its new name", () => {
    const known = new Set(file.candidates.map((c) => c.key));
    expect(parsePicks("Linux, microsoft,nope,linux", known)).toEqual(["linux", "microsoft"]);
    expect(parsePicks("berriai,litellm,php-group,vanderbilt-university", known, file.aliases)).toEqual(["litellm", "php", "redcap"]);
    expect(parsePicks("", known)).toEqual([]);
    expect(parsePicks(null, known)).toEqual([]);
    expect(parsePicks(Array.from(known).join(","), known)).toHaveLength(STACK_MAX);
  });
  it("turns every flag into a short badge with its tone", () => {
    expect(flagBadge("patch by 31 Oct")).toEqual({ word: "due 31 Oct", tone: "due" });
    expect(flagBadge("past due 26 Oct")).toEqual({ word: "past due 26 Oct", tone: "due" });
    expect(flagBadge("confirmed impact")).toEqual({ word: "impact", tone: "harm" });
    expect(flagBadge("no patch yet")).toEqual({ word: "no patch", tone: "open" });
    expect(flagBadge("partly patched")).toEqual({ word: "partial", tone: "partial" });
    for (const c of file.candidates) if (c.flag) expect(["due", "harm", "open", "partial"]).toContain(flagBadge(c.flag).tone);
  });
  it("travels compactly and comes back whole", () => {
    const wire = packStack(file);
    expect(unpackStack(JSON.parse(JSON.stringify(wire)))).toEqual(file);
    // a vendor and its product share their items in the table
    expect(wire.items.length).toBeLessThan(file.candidates.reduce((n, c) => n + c.n, 0));
    const quiet = wire.candidates.find((c) => c.label === "MariaDB")!;
    expect(Object.keys(quiet).sort()).toEqual(["c", "label"]);
  });
});

describe("the news lists", () => {
  const src = (publisher: string, n = 1) => Array.from({ length: n }, (_, k) => ({ url: `https://example.com/${publisher.toLowerCase().replace(/\W+/g, "-")}/${k}`, publisher, title: "Report", published_at: "2026-10-28" }));
  const rec = (slug: string, over: Parameters<typeof incident>[0], sources: ReturnType<typeof src>) => incident({ slug, state: "live", first_reported: "2026-10-28", created_at: "2026-10-28T10:00:00.000Z", ...over, sources, source_count: sources.length });
  const recs = [
    rec("big", { lane: "patch", severity: 2, type: "not_ai", categories: ["general"], created_at: "2026-10-27T10:00:00.000Z" }, [...src("Outlet A", 2), ...src("Outlet B"), ...src("Outlet C"), ...src("Outlet D"), ...src("Outlet E")]),
    rec("breach-new", { lane: "breach", severity: 4, type: "not_ai", categories: ["general"], created_at: "2026-10-29T09:00:00.000Z" }, [...src("Outlet A"), ...src("Outlet B")]),
    rec("breach-old", { lane: "breach", severity: 3, type: "not_ai", categories: ["general"], created_at: "2026-10-26T09:00:00.000Z" }, [...src("Outlet A"), ...src("Outlet B")]),
    rec("ai-one", { lane: "supply_chain", severity: 3, type: "attack_on_ai", created_at: "2026-10-28T09:00:00.000Z", cve_ids: ["CVE-2026-0012"] }, src("Outlet A")),
    rec("too-old", { lane: "breach", severity: 4, created_at: "2026-10-20T09:00:00.000Z" }, [...src("Outlet A"), ...src("Outlet B"), ...src("Outlet C")]),
    rec("closed", { lane: "breach", severity: 4, state: "closed", closed_at: "2026-10-29", created_at: "2026-10-29T08:00:00.000Z" }, src("Outlet A")),
    disclosedCve({ cve_ids: ["CVE-2026-0099"], state: "live", created_at: "2026-10-29T02:00:00.000Z" }),
  ];
  const stack = {
    default: ["linux"],
    candidates: [{ key: "linux", label: "Linux", items: [{ kind: "kev", name: "Linux Kernel", cves: ["CVE-2026-0012"], date: "2026-10-27", due: null, cvss: null, open: null, href: "https://nvd.nist.gov/vuln/detail/CVE-2026-0012", external: true }] }],
  } as unknown as Parameters<typeof buildNews>[1];
  const n = buildNews(recs, stack, NOW);

  it("takes the week's live records and leaves out old, closed and database-only ones", () => {
    expect(n.rows.map((r) => r.slug)).toEqual(["breach-new", "ai-one", "big", "breach-old"]);
    expect(n.total).toBe(4);
    expect(n.breaches).toBe(2);
    expect(n.ai).toBe(1);
  });
  it("counts a record's sources as distinct outlets and names the first of them", () => {
    const big = n.rows.find((r) => r.slug === "big")!;
    expect(big.sources).toBe(5);
    expect(big.by).toEqual(["Outlet A", "Outlet B", "Outlet C", "Outlet D"]);
    expect(big.by).toHaveLength(NEWS_NAMED);
  });
  it("ranks top stories by sources, then confirmed impact, then the newest", () => {
    expect(n.top).toEqual(["big", "breach-new", "breach-old", "ai-one"]);
    expect(newsList(n, "top").map((r) => r.slug)).toEqual(n.top);
  });
  it("lists breaches and AI records newest first, and the rows that belong to the stack", () => {
    expect(newsList(n, "breaches").map((r) => r.slug)).toEqual(["breach-new", "breach-old"]);
    expect(newsList(n, "ai").map((r) => r.slug)).toEqual(["ai-one"]);
    expect(newsList(n, "stack").map((r) => r.slug)).toEqual(["ai-one"]);
    expect(n.rows.find((r) => r.slug === "ai-one")!.stack).toEqual(["Linux"]);
    // a visitor's own picks: the browser hands in its own labels
    expect(newsList(n, "stack", (r) => (r.slug === "big" ? ["Mine"] : [])).map((r) => r.slug)).toEqual(["big"]);
  });
  it("places the week's exploited records on the radar: newer nearer twelve o'clock, red where impact is confirmed", () => {
    expect(n.exploited).toBe(3);
    expect(n.impact).toBe(1);
    expect(n.contacts).toHaveLength(3);
    const [newest, , oldest] = n.contacts;
    expect(newest![0]).toBeLessThan(oldest![0]);
    expect(newest![2]).toBe(1);
    expect(n.contacts.every(([turn, range]) => turn >= 0 && turn < 1 && range >= 0.2 && range <= 0.9)).toBe(true);
  });
  it("keeps a bounded pool however busy the week", () => {
    const busy = Array.from({ length: 80 }, (_, k) => rec(`r-${k}`, { lane: k % 2 ? "breach" : "patch", severity: 3, type: k % 3 ? "not_ai" : "attack_on_ai", categories: ["general"], created_at: `2026-10-29T${String(k % 23).padStart(2, "0")}:${String(k % 60).padStart(2, "0")}:00.000Z` }, src("Outlet A")));
    const many = buildNews(busy, { default: [], candidates: [] }, NOW);
    expect(many.total).toBe(80);
    expect(many.rows.length).toBeLessThanOrEqual(NEWS_EXPLOITED_KEPT + 3 * NEWS_KEPT);
    expect(many.top).toHaveLength(NEWS_KEPT);
  });
});

describe("deadlines", () => {
  const DAY = 86_400_000;
  it("passes a deadline at the end of its UTC day", () => {
    expect(dueEnd("2026-11-10")).toBe(Date.parse("2026-11-11T00:00:00Z"));
  });
  it("measures how much of CISA's window is used, from the listing day to the end of the due day", () => {
    const at = (iso: string) => Date.parse(iso);
    expect(windowUsed("2026-11-01", "2026-11-10", at("2026-11-01T00:00:00Z"))).toBe(0);
    expect(windowUsed("2026-11-01", "2026-11-10", at("2026-11-06T00:00:00Z"))).toBeCloseTo(0.5, 5);
    expect(windowUsed("2026-11-01", "2026-11-10", at("2026-11-11T00:00:00Z"))).toBe(1);
    // before the listing and after the deadline it stays inside 0 and 1
    expect(windowUsed("2026-11-01", "2026-11-10", at("2026-10-20T00:00:00Z"))).toBe(0);
    expect(windowUsed("2026-11-01", "2026-11-10", at("2026-12-01T00:00:00Z"))).toBe(1);
    expect(DAY).toBe(86_400_000);
  });
});

describe("time left", () => {
  it("reads in the coarsest unit that still says something, never a ticking clock", () => {
    const H = 3_600_000;
    expect(timeLeft(3 * 24 * H + 5 * H)).toBe("3 days");
    expect(timeLeft(47 * H)).toBe("1 day"); // floored: at least a day
    expect(timeLeft(24 * H)).toBe("1 day");
    expect(timeLeft(16 * H + 59 * 60_000 + 59_000)).toBe("16 h");
    expect(timeLeft(H)).toBe("1 h");
    expect(timeLeft(32 * 60_000)).toBe("32 min");
    expect(timeLeft(30_000)).toBe("1 min"); // the last minute rounds up, the countdown says "past due" at zero itself
  });
  it("splits the runway's countdown into two figures: hours and minutes, days and hours from two days out", () => {
    const H = 3_600_000;
    expect(countdownParts(21 * H + 32 * 60_000 + 46_000)).toEqual({ a: "21", au: "h", b: "32", bu: "m" });
    expect(countdownParts(47 * H + 59 * 60_000)).toEqual({ a: "47", au: "h", b: "59", bu: "m" });
    expect(countdownParts(48 * H)).toEqual({ a: "2", au: "d", b: "0", bu: "h" });
    expect(countdownParts(2 * 24 * H + 21 * H + 59 * 60_000)).toEqual({ a: "2", au: "d", b: "21", bu: "h" });
    expect(countdownParts(5 * 60_000)).toEqual({ a: "0", au: "h", b: "05", bu: "m" });
    expect(countdownParts(-1)).toEqual({ a: "0", au: "h", b: "00", bu: "m" });
  });
});
