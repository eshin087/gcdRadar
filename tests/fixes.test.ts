import { describe, expect, it } from "vitest";
import { buildBrief, fixMarkdown } from "@/lib/brief";
import { buildQuickLookFiles, fixViewForRecord } from "@/lib/fix-join";
import { bestFixLink, buildFixView, cveOrgUrl, epssUrl, fixFileUrl, hasFixDetail, kevEntryUrl, nvdUrl, saysNone } from "@/lib/fixes";
import type { FixEntry, FixLink, FixText, Fixes, KevStatEntry, KevStats } from "@/lib/stats-schema";
import { incident } from "./fixtures";

const TODAY = "2026-11-19";
const SRC = { name: "x", url: "https://example.org/", license: "CC0 1.0" };

const text = (cve: string, by: string, value: string, kind: FixText["kind"] = "vendor", cut = false): FixText => ({ text: value, cut, kind, source: { publisher: by, title: `${cve}, CVE record`, url: cveOrgUrl(cve) } });
const link = (url: string, kind: FixLink["kind"], source: FixLink["source"], title = ""): FixLink => ({ url, kind, title, source });

function entry(cve: string, over: Partial<FixEntry> = {}): FixEntry {
  return { cve, fetched_at: "2026-11-19T06:00:00.000Z", nvd_at: null, ghsa_at: null, found: true, cna: "acme", by: "Acme", by_vendor: true, title: "", patches: [], patches_more: 0, links: [], solutions: [], workarounds: [], kev: null, ...over };
}

const kev = (cve: string, added: string, due: string | null): KevStatEntry => ({ cve, added, due, vendor: "Acme", product: "Router", name: "Acme Router Command Injection Vulnerability", ransomware: false, published: null, cvss: 9.8 });

const full = entry("CVE-2026-0001", {
  patches: [
    { label: "Acme Router", version: "1.2", from: "1.0", url: null, source: "cve" },
    { label: "acme-router (npm)", version: "1.2.0", from: "< 1.2.0", url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", source: "ghsa" },
  ],
  patches_more: 3,
  links: [
    link("https://acme.example/patch-1", "patch", "nvd"),
    link("https://acme.example/sa-1", "advisory", "cve", "ACME-SA-1"),
    link("https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "advisory", "ghsa", "GHSA-aaaa-bbbb-cccc: RCE in acme-router"),
    link("https://acme.example/harden", "mitigation", "cve"),
  ],
  solutions: [text("CVE-2026-0001", "Acme", "Upgrade to Router 1.2 or later.")],
  workarounds: [text("CVE-2026-0001", "Acme", "Disable remote management until the update is applied.")],
  kev: { added: "2026-11-18", due: "2026-12-09", action: "Apply mitigations per vendor instructions.", description: "Acme Router contains a command injection flaw.", note: "", guidance: [{ label: "BOD 26-04", url: "https://www.cisa.gov/bod-26-04" }] },
});

describe("buildFixView: the join", () => {
  it("answers patch, workaround and deadline from the entry, and numbers each source once, in the order the view first uses it", () => {
    const v = buildFixView({ cves: ["CVE-2026-0001"], entries: [entry("CVE-2026-9999"), full], today: TODAY });
    expect(v.cves).toEqual(["CVE-2026-0001"]);
    expect(v.checked).toBe("2026-11-19T06:00:00.000Z");
    // 1: the CVE record (the first version row), 2: the GitHub advisory (the second), then the links in order, then CISA
    expect(v.citations.map((c) => [c.n, c.publisher, c.url])).toEqual([
      [1, "Acme", cveOrgUrl("CVE-2026-0001")],
      [2, "GitHub Advisory Database", "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],
      [3, "acme.example", "https://acme.example/patch-1"],
      [4, "acme.example", "https://acme.example/sa-1"],
      [5, "acme.example", "https://acme.example/harden"],
      [6, "CISA", kevEntryUrl("CVE-2026-0001")],
    ]);
    expect(v.patch.versions).toEqual([
      { label: "Acme Router", version: "1.2", from: "1.0", cite: 1 },
      { label: "acme-router (npm)", version: "1.2.0", from: "< 1.2.0", cite: 2 },
    ]);
    expect(v.patch.more).toBe(3);
    // the vendor's solution and workaround are the same source as the versions: the same number
    expect(v.patch.texts).toEqual([{ text: "Upgrade to Router 1.2 or later.", cut: false, by: "Acme", kind: "vendor", cite: 1 }]);
    expect(v.patch.links.map((l) => [l.label, l.host, l.cite])).toEqual([
      ["Patch", "acme.example", 3],
      ["Vendor advisory", "acme.example", 4],
      ["GitHub advisory", "github.com", 2],
    ]);
    expect(v.workaround).toMatchObject({ state: "text", texts: [{ text: "Disable remote management until the update is applied.", cite: 1 }], links: [{ label: "Mitigation", cite: 5 }], none: null });
    expect(v.deadline).toEqual({ cves: ["CVE-2026-0001"], cve: "CVE-2026-0001", due: "2026-12-09", added: "2026-11-18", action: "Apply mitigations per vendor instructions.", note: "", guidance: [{ label: "BOD 26-04", url: "https://www.cisa.gov/bod-26-04" }], cite: 6 });
    // every citation resolves to a publisher, a title and a link, and every number used is in the list
    for (const c of v.citations) expect(c.publisher && c.title && /^https:\/\//.test(c.url)).toBeTruthy();
    expect(v.citations.find((c) => c.n === 4)!.title).toBe("ACME-SA-1 (tagged in the CVE record)");
    expect(v.citations.find((c) => c.n === 3)!.title).toBe("Patch (tagged by NVD)");
    const used = [...v.patch.versions, ...v.patch.texts, ...v.patch.links, ...v.workaround.texts, ...v.workaround.links].map((x) => x.cite).concat(v.deadline!.cite);
    expect(new Set(used)).toEqual(new Set(v.citations.map((c) => c.n)));
    // the reference row: the same places for every CVE, CISA's entry only when listed
    expect(v.refs).toEqual([{ cve: "CVE-2026-0001", links: [{ key: "cve", label: "cve.org", url: cveOrgUrl("CVE-2026-0001") }, { key: "nvd", label: "NVD", url: nvdUrl("CVE-2026-0001") }, { key: "kev", label: "CISA KEV", url: kevEntryUrl("CVE-2026-0001") }, { key: "epss", label: "EPSS", url: epssUrl("CVE-2026-0001") }] }]);
    expect(bestFixLink(v)!.url).toBe("https://acme.example/patch-1");
    expect(v.summary).toBeNull();
  });

  it("merges a record's CVEs: versions and links once each, the nearest deadline still ahead, else the latest one passed", () => {
    const a = entry("CVE-2026-0001", { patches: [{ label: "Acme Router", version: "1.2", from: "", url: null, source: "cve" }], links: [link("https://acme.example/sa-1", "advisory", "cve")], kev: { added: "2026-10-01", due: "2026-10-22", action: "Old action.", description: "", note: "", guidance: [] } });
    const b = entry("CVE-2026-0002", { fetched_at: "2026-11-17T00:00:00.000Z", patches: [{ label: "Acme Router", version: "1.2", from: "", url: null, source: "cve" }], links: [link("https://acme.example/sa-1", "advisory", "kev")], kev: { added: "2026-11-18", due: "2026-12-09", action: "New action.", description: "", note: "", guidance: [] } });
    const v = buildFixView({ cves: ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"], entries: [a, b], kev: [kev("CVE-2026-0003", "2026-11-10", "2026-12-01")], today: TODAY });
    expect(v.patch.versions).toHaveLength(1);
    expect(v.patch.links).toHaveLength(1);
    // CVE-2026-0003 is on CISA's list but not read yet: its date counts, its action is not known
    expect(v.deadline).toMatchObject({ cves: ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"], cve: "CVE-2026-0003", due: "2026-12-01", added: "2026-11-10", action: "" });
    expect(v.citations.at(-1)).toMatchObject({ publisher: "CISA", url: kevEntryUrl("CVE-2026-0003") });
    // the brief says whose date it is
    expect(fixMarkdown(v, "https://example.test/x")).toContain("- CISA lists CVE-2026-0001, CVE-2026-0002, CVE-2026-0003 as exploited in the wild; US federal agencies must fix CVE-2026-0003 (listed 2026-11-10) by 2026-12-01.");
    // the oldest read among the entries is what the block's date says
    expect(v.checked).toBe("2026-11-17T00:00:00.000Z");
    const passed = buildFixView({ cves: ["CVE-2026-0001", "CVE-2026-0002"], entries: [a, b], today: "2026-12-20" });
    expect(passed.deadline).toMatchObject({ due: "2026-12-09", action: "New action." });
    expect(v.refs.map((r) => r.links.map((l) => l.key).join(","))).toEqual(["cve,nvd,kev,epss", "cve,nvd,kev,epss", "cve,nvd,kev,epss"]);
  });

  it("never invents a workaround: it quotes one, reports that the vendor lists none, or says none is listed, not read, or not published", () => {
    const state = (entries: FixEntry[], cves = ["CVE-2026-0001"]) => buildFixView({ cves, entries, today: TODAY }).workaround;
    expect(state([entry("CVE-2026-0001", { workarounds: [text("CVE-2026-0001", "F5", "None")] })])).toMatchObject({ state: "stated_none", texts: [], none: { by: "F5", cite: 1 } });
    expect(state([entry("CVE-2026-0001")])).toEqual({ state: "none_listed", texts: [], links: [], none: null });
    expect(state([entry("CVE-2026-0001", { found: false, cna: "", by: "" })])).toMatchObject({ state: "no_record" });
    expect(state([])).toMatchObject({ state: "unchecked" });
    // a vendor that says "none" and then describes a mitigation is quoted in full
    expect(state([entry("CVE-2026-0001", { workarounds: [text("CVE-2026-0001", "Palo Alto Networks", "No known workarounds exist for this issue.\nCustomers with Threat Prevention can enable Threat ID 510046.")] })]).state).toBe("text");
    for (const s of ["None", "none.", "N/A", "No workaround", "No workarounds are available.", "No known workarounds exist for this issue.", "There are no workarounds that address this vulnerability."]) expect(saysNone(s), s).toBe(true);
    for (const s of ["Disable the feature.", "No workaround is needed if the proxy is disabled; otherwise block port 80.", "An iRule is available upon request."]) expect(saysNone(s), s).toBe(false);
  });

  it("shows our own sentence only where no publisher's text is shown, labelled by its citation, and our fixed versions only where no source gave one", () => {
    const record = { action: "Update the router firmware.", fixed_in: ["Router 1.2"], source_count: 3, sourcesUrl: "#sources" };
    const bare = buildFixView({ cves: ["CVE-2026-0001"], entries: [entry("CVE-2026-0001")], record, today: TODAY });
    expect(bare.patch.recorded).toEqual([{ label: "", version: "Router 1.2", from: "", cite: 1 }]);
    expect(bare.summary).toEqual({ text: "Update the router firmware.", cite: 1 });
    expect(bare.citations).toEqual([{ n: 1, publisher: "gcdRadar", title: "This record, written by a language model from its 3 sources", url: "#sources" }]);
    const quoted = buildFixView({ cves: ["CVE-2026-0001"], entries: [full], record, today: TODAY });
    expect(quoted.summary).toBeNull();
    expect(quoted.patch.recorded).toEqual([]);
    expect(buildFixView({ cves: ["CVE-2026-0001"], entries: [], record: { ...record, action: "  ", fixed_in: [] }, today: TODAY })).toMatchObject({ summary: null, checked: null, deadline: null, citations: [] });
    expect(hasFixDetail(buildFixView({ cves: ["CVE-2026-0001"], entries: [], today: TODAY }))).toBe(false);
    expect(hasFixDetail(bare)).toBe(true);
  });

  it("names a third-party CNA in the record's citation", () => {
    const v = buildFixView({ cves: ["CVE-2026-0001"], entries: [entry("CVE-2026-0001", { cna: "mitre", by: "MITRE", by_vendor: false, patches: [{ label: "UnrealIRCd", version: "6.2.7.1", from: "", url: null, source: "cve" }] })], today: TODAY });
    expect(v.citations[0]).toEqual({ n: 1, publisher: "MITRE", title: "CVE record CVE-2026-0001, written by MITRE as the CNA", url: cveOrgUrl("CVE-2026-0001") });
  });
});

describe("the record's view, its brief and the drawer's files", () => {
  const fixes: Fixes = { fetched_at: "2026-11-19T06:00:00.000Z", sources: [SRC], kev_catalog_version: "2026.11.18", entries: [full, entry("CVE-2026-0005")] };
  const kevStats: KevStats = { fetched_at: "2026-11-19T06:00:00.000Z", source: SRC, catalog_version: "2026.11.18", entries: [kev("CVE-2026-0001", "2026-11-18", "2026-12-09"), kev("CVE-2026-0007", "2026-11-15", "2026-12-06"), kev("CVE-2025-0008", "2026-02-01", "2026-02-22")] };
  const stats = { fixes, kev: kevStats };
  const record = incident({ slug: "acme-router-rce", title: "Acme Router command injection exploited in the wild", cve_ids: ["CVE-2026-0001"], action: "Update to Router 1.2.", fixed_in: ["Router 1.2"], cvss: 9.8, state: "live" });
  const noCve = incident({ slug: "acme-breach", cve_ids: [], action: "Rotate credentials.", lane: "breach" });

  it("gives a record with a CVE id a view, and one without none", () => {
    expect(fixViewForRecord(noCve, stats, TODAY, "")).toBeNull();
    const v = fixViewForRecord(record, stats, TODAY, "https://example.test")!;
    expect(v.patch.versions[0]).toMatchObject({ label: "Acme Router", version: "1.2" });
    expect(v.deadline!.due).toBe("2026-12-09");
  });

  it("puts the patch link, the workaround and their numbered sources in the copied brief", () => {
    const site = "https://example.test";
    const brief = buildBrief(record, site, fixViewForRecord(record, stats, TODAY, site));
    expect(brief).toContain("## What to do\n\nUpdate to Router 1.2.\n\n(gcdRadar's summary, written by a language model from the sources below; not the vendor's words.)");
    expect(brief).toContain("## How to fix\n\nPatch\n- Acme Router: fixed in 1.2 (for 1.0) [1]");
    expect(brief).toContain("- 3 more fixed versions: https://example.test/incidents/acme-router-rce");
    expect(brief).toContain('- Acme\'s solution: "Upgrade to Router 1.2 or later." [1]');
    expect(brief).toContain("- Patch: https://acme.example/patch-1 [3]");
    expect(brief).toContain('Workaround\n- Acme\'s workaround: "Disable remote management until the update is applied." [1]\n- Mitigation: https://acme.example/harden [5]');
    expect(brief).toContain("Deadline\n- CISA lists CVE-2026-0001 as exploited in the wild (since 2026-11-18); US federal agencies must fix it by 2026-12-09. [6]");
    expect(brief).toContain(`References\n- CVE-2026-0001: cve.org ${cveOrgUrl("CVE-2026-0001")} · NVD ${nvdUrl("CVE-2026-0001")}`);
    expect(brief).toContain(`Sources for the fix\n[1] Acme · CVE record CVE-2026-0001 · ${cveOrgUrl("CVE-2026-0001")}`);
    expect(brief).not.toContain("undefined");
    expect(brief).not.toMatch(/<[a-z]/);
    // a record with no CVE id, or with nothing to say, keeps the brief it had
    expect(buildBrief(noCve, site, fixViewForRecord(noCve, stats, TODAY, site))).not.toContain("## How to fix");
    expect(buildBrief(record, site)).not.toContain("## How to fix");
    // multi-line vendor text stays one list item
    const md = fixMarkdown(buildFixView({ cves: ["CVE-2026-0001"], entries: [entry("CVE-2026-0001", { solutions: [text("CVE-2026-0001", "Acme", "Upgrade to 1.2.\nRestart the service.", "vendor", true)] })], today: TODAY }), "https://example.test/x");
    expect(md).toContain('- Acme\'s solution: "Upgrade to 1.2. / Restart the service." (cut; the source has the rest) [1]');
    expect(md).toContain("Workaround\n- No workaround published in the CVE record or by CISA yet.");
    expect(md).toContain("Deadline\n- Not on CISA's list of known exploited vulnerabilities, so no federal deadline.");
  });

  it("writes a quick-look file for every CVE the drawer can be asked about, with our record when there is one", () => {
    const files = buildQuickLookFiles([record, noCve, incident({ cve_ids: ["CVE-2026-0009"], state: "closed", closed_at: "2026-11-01" }), incident({ slug: "live-other", cve_ids: ["CVE-2026-0010"], state: "live" })], stats, TODAY, "2026-11-19T07:00:00.000Z", "https://example.test");
    // the fix file's two, the recent KEV entry not yet read, and the live record's CVE; not the old KEV entry, not the closed record's CVE
    expect(files.map((f) => f.cve)).toEqual(["CVE-2026-0001", "CVE-2026-0005", "CVE-2026-0007", "CVE-2026-0010"]);
    const [withRecord, entryOnly, kevOnly, liveOnly] = files;
    expect(withRecord).toMatchObject({ title: "Acme Router Command Injection Vulnerability", product: "Acme Router", cvss: 9.8, record: { slug: "acme-router-rce", title: "Acme Router command injection exploited in the wild" }, description: { by: "CISA", url: kevEntryUrl("CVE-2026-0001"), text: "Acme Router contains a command injection flaw." }, sources: [SRC] });
    expect(withRecord!.fix.patch.versions[0]!.version).toBe("1.2");
    expect(entryOnly).toMatchObject({ title: "CVE-2026-0005", product: "", record: null, description: null });
    // on CISA's list, not read by the fix stage yet: the deadline is there, the block says the rest was not looked up
    expect(kevOnly).toMatchObject({ record: null, fix: { checked: null, deadline: { due: "2026-12-06", action: "" }, workaround: { state: "unchecked" } } });
    expect(liveOnly!.record).toMatchObject({ slug: "live-other" });
    expect(fixFileUrl("CVE-2026-0001")).toBe("/data/fix/CVE-2026-0001.json");
  });
});
