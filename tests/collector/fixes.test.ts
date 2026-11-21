import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import settingsJson from "@/collector/config/settings.json";
import { SettingsSchema, type Settings } from "@/collector/lib/config";
import { HttpError, type HttpOptions } from "@/collector/lib/http";
import {
  attribution,
  buildEntry,
  cutText,
  cveRecordUrl,
  fixedVersions,
  fixesModule,
  ghsaParts,
  isHostOf,
  kevBlock,
  mergeLinks,
  needsGhsa,
  needsNvd,
  nvdLinks,
  parseCveRecord,
  parseKevNotes,
  planLookups,
  tidyText,
  urlKey,
  wantedCves,
  NO_RECORD,
  type CveRecord,
} from "@/collector/stats/fixes";
import { readAllStats, runStats } from "@/collector/stats/index";
import { resetNvdClock } from "@/collector/stats/nvd";
import type { StatsContext, StatsHttp } from "@/collector/stats/types";
import { FIX_LINK_MAX, FIX_TEXT_MAX, FixEntrySchema, STATS_FILES, type FixEntry, type FixLink, type Fixes, type KevStats } from "@/lib/stats-schema";

const base: Settings = SettingsSchema.parse(settingsJson);
const NOW = new Date("2026-11-19T12:00:00Z");
const BOD = "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk";

/** Shapes taken from real records in the CVE List (trimmed): Synology, the Linux kernel CNA, a MITRE-assigned record, JPCERT. */
const synology: CveRecord = {
  cveMetadata: { cveId: "CVE-2024-10441", state: "PUBLISHED", assignerShortName: "synology" },
  containers: {
    cna: {
      affected: [
        {
          vendor: "Synology",
          product: "DiskStation Manager (DSM)",
          versions: [
            { version: "7.2.2", status: "affected", lessThan: "7.2.2-72806-1", versionType: "semver" },
            { version: "7.2.1", status: "affected", lessThan: "7.2.1-69057-6", versionType: "semver" },
            { version: "0", status: "unknown", lessThan: "7.0", versionType: "semver" },
          ],
        },
        { vendor: "Synology", product: "BeeStation OS (BSM)", versions: [{ version: "1.1", status: "affected", lessThan: "1.1-65374", versionType: "semver" }] },
      ],
      references: [
        { url: "https://www.synology.com/en-global/security/advisory/Synology_SA_24_20", name: "Synology-SA-24:20 DSM (PWN2OWN 2024)", tags: ["vendor-advisory"] },
        { url: "https://example.org/writeup", tags: ["technical-description"] },
        { url: "https://example.org/gone", tags: ["patch", "broken-link"] },
      ],
    },
    adp: [{ providerMetadata: { shortName: "CISA-ADP" }, references: [{ url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-10441", tags: ["government-resource"] }] }],
  },
};

const linux: CveRecord = {
  cveMetadata: { cveId: "CVE-2026-53266", state: "PUBLISHED", assignerShortName: "Linux" },
  containers: {
    cna: {
      affected: [
        {
          vendor: "Linux",
          product: "Linux",
          versions: [
            { version: "63137bc5882a1882c553d389fdeeeace86ee1741", lessThan: "bf84ad7c7a9ede46e31afaa41a1ba06a159e8c87", status: "affected", versionType: "git" },
            { version: "5.4.73", lessThan: "5.5", status: "affected", versionType: "semver" },
          ],
        },
        {
          vendor: "Linux",
          product: "Linux",
          versions: [
            { version: "5.10", status: "affected" },
            { version: "0", lessThan: "5.10", status: "unaffected", versionType: "semver" },
            { version: "5.10.259", lessThanOrEqual: "5.10.*", status: "unaffected", versionType: "semver" },
            { version: "6.6.143", lessThanOrEqual: "6.6.*", status: "unaffected", versionType: "semver" },
            { version: "7.1", lessThanOrEqual: "*", status: "unaffected", versionType: "original_commit_for_fix" },
          ],
        },
      ],
      references: [{ url: "https://git.kernel.org/stable/c/bf84ad7c7a9e" }],
    },
  },
};

const unreal: CveRecord = {
  cveMetadata: { cveId: "CVE-2026-114713", state: "PUBLISHED", assignerShortName: "mitre" },
  containers: {
    cna: {
      affected: [{ vendor: "n/a", product: "UnrealIRCd", versions: [{ version: "6.2.0", status: "affected", lessThan: "6.2.7.1" }] }],
      solutions: [{ lang: "en", value: "Upgrade to UnrealIRCd 6.2.7.1 or later.   Alternatively, apply the hot-patch:\r\n\r\n\r\n  ./unrealircd hot-patch bundle-20261107" }],
      workarounds: [{ lang: "en", value: 'Add the following line to the configuration file: blacklist-module "labeled-response";' }, { lang: "fr", value: "Ajoutez la ligne." }],
    },
  },
};

describe("the CVE record", () => {
  it("finds a CVE's file in the CVE List by year and thousands", () => {
    expect(cveRecordUrl("CVE-2024-10441")).toBe("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/10xxx/CVE-2024-10441.json");
    expect(cveRecordUrl("CVE-2026-0322")).toContain("/2026/0xxx/CVE-2026-0322.json");
    expect(cveRecordUrl("CVE-2026-115560")).toContain("/2026/115xxx/CVE-2026-115560.json");
    expect(() => cveRecordUrl("GHSA-xxxx")).toThrow();
  });

  it("takes fixed versions from the exclusive bound of an affected range, the vendor's tagged links, and attributes the text to the vendor", () => {
    const p = parseCveRecord(synology, "CVE-2024-10441");
    expect(p).toMatchObject({ found: true, cna: "synology", by: "Synology", by_vendor: true });
    expect(p.patches.map((x) => `${x.label} | ${x.from} -> ${x.version}`)).toEqual([
      "Synology DiskStation Manager (DSM) | 7.2.2 -> 7.2.2-72806-1",
      "Synology DiskStation Manager (DSM) | 7.2.1 -> 7.2.1-69057-6",
      "Synology BeeStation OS (BSM) | 1.1 -> 1.1-65374",
    ]);
    // "unknown below 7.0" is not a fix; an untagged reference, a broken link and CISA's own page are not fix links
    expect(p.links).toEqual([{ url: "https://www.synology.com/en-global/security/advisory/Synology_SA_24_20", kind: "advisory", title: "Synology-SA-24:20 DSM (PWN2OWN 2024)", source: "cve" }]);
    expect(p.solutions).toEqual([]);
    // the vendors and products the record names, for matching a CVE to a product
    expect(p.affected).toEqual([{ vendor: "Synology", product: "DiskStation Manager (DSM)" }, { vendor: "Synology", product: "BeeStation OS (BSM)" }]);
    expect(p.workarounds).toEqual([]);
  });

  it("prefers the versions a CNA marks unaffected over bounded affected ranges, and never reads a commit hash as a version", () => {
    const p = parseCveRecord(linux, "CVE-2026-53266");
    // "5.4.73, less than 5.5" is where the flaw was introduced, not a fix
    expect(p.patches.map((x) => `${x.from} -> ${x.version}`)).toEqual(["5.10.* -> 5.10.259", "6.6.* -> 6.6.143", " -> 7.1"]);
    expect(p.links).toEqual([]);
    // the two blocks name one product: listed once
    expect(p.affected).toEqual([{ vendor: "Linux", product: "Linux" }]);
    expect(needsNvd(p)).toBe(true);
    expect(needsGhsa(p)).toBe(false);
  });

  it("uses a range's last change only when it ends unaffected, and leaves inclusive bounds and wildcards out", () => {
    const { patches } = fixedVersions([
      { vendor: "EG", product: "SiteGuard", versions: [{ version: "Ver2.20", status: "affected", lessThan: "Ver8.00 Update 5", changes: [{ at: "Ver3.10", status: "unaffected" }, { at: "Ver4.00 Update 5", status: "affected" }] }] },
      { vendor: "Acme", product: "Router", versions: [{ version: "1.0", status: "affected", lessThanOrEqual: "1.9" }, { version: "2.0", status: "affected", lessThan: "*" }, { version: "3.0", status: "affected", lessThan: "unspecified" }] },
      { vendor: "Acme", product: "Switch", versions: [{ version: "4.0", status: "affected", changes: [{ at: "4.2", status: "unaffected" }] }] },
    ]);
    expect(patches.map((x) => `${x.label} ${x.version}`)).toEqual(["EG SiteGuard Ver8.00 Update 5", "Acme Switch 4.2"]);
  });

  it("never takes a bound the record itself marks affected as a fix, and keeps per-branch fixes", () => {
    // consecutive ranges: 2.0 starts the second affected range, so only 3.0 is a fix
    expect(fixedVersions([{ vendor: "Acme", product: "Router", versions: [{ version: "1.0", status: "affected", lessThan: "2.0" }, { version: "2.0", status: "affected", lessThan: "3.0" }] }]).patches.map((p) => `${p.from}->${p.version}`)).toEqual(["2.0->3.0"]);
    // the same through a second block for the product, a single affected version, or a change back to affected
    expect(fixedVersions([{ vendor: "Acme", product: "Router", versions: [{ version: "1.0", status: "affected", lessThan: "2.0" }] }, { vendor: "Acme", product: "Router", versions: [{ version: "2.0", status: "affected" }] }]).patches).toEqual([]);
    expect(fixedVersions([{ vendor: "Acme", product: "Switch", versions: [{ version: "1.0", status: "affected", lessThan: "1.5" }, { version: "0.9", status: "affected", lessThan: "2.0", changes: [{ at: "1.5", status: "affected" }] }] }]).patches.map((p) => p.version)).toEqual(["2.0"]);
    // a bound marked affected for another product does not count against this one
    expect(fixedVersions([{ vendor: "Acme", product: "Router", versions: [{ version: "1.0", status: "affected", lessThan: "2.0" }] }, { vendor: "Acme", product: "Switch", versions: [{ version: "2.0", status: "affected" }] }]).patches.map((p) => `${p.label} ${p.version}`)).toEqual(["Acme Router 2.0"]);
    // real shapes that must stay: Apple writes one range per branch from 0 (iOS 16.7.8 sorts inside "0, less than 17.5" and is still the 16.x fix),
    // Synology's default status is affected while its description calls 7.2.2-72806-1 the fix
    const apple = fixedVersions([{ vendor: "Apple", product: "iOS and iPadOS", versions: [{ version: "0", status: "affected", lessThan: "16.7.8", versionType: "custom" }, { version: "0", status: "affected", lessThan: "17.5", versionType: "custom" }] }]);
    expect(apple.patches.map((p) => p.version)).toEqual(["16.7.8", "17.5"]);
    expect(parseCveRecord(synology, "CVE-2024-10441").patches.map((p) => p.version)).toEqual(["7.2.2-72806-1", "7.2.1-69057-6", "1.1-65374"]);
    // and Chrome, which writes "affected from X, less than X" for "below X" (CVE-2026-125350): X is the fix, not an affected version
    expect(fixedVersions([{ vendor: "Google", product: "Chrome", versions: [{ version: "157.0.8103.50", status: "affected", lessThan: "157.0.8103.50", versionType: "custom" }] }]).patches.map((p) => `${p.label} ${p.version}`)).toEqual(["Google Chrome 157.0.8103.50"]);
  });

  it("keeps a version the record lists as unaffected on its own, as not affected and never as a fix", () => {
    // Ivanti, CVE-2026-104935: its description says 22.7R2.14 "or prior" is not impacted, so one of the four is an older release, not a fix
    const ivanti = fixedVersions([{ vendor: "Ivanti", product: "Connect Secure", versions: ["25.1.3.0", "25.1.3.1", "22.8R2.5", "22.7R2.14"].map((version) => ({ version, status: "unaffected", versionType: "custom" })) }]);
    expect(ivanti.patches).toEqual(["25.1.3.0", "25.1.3.1", "22.8R2.5", "22.7R2.14"].map((version) => ({ label: "Ivanti Connect Secure", version, from: "", url: null, source: "cve", status: "unaffected" })));
    // a product whose fix the record states (a bounded affected range, or unaffected with an open range) shows that, once: the same version listed on its own adds nothing
    const perforce = fixedVersions([{ vendor: "Perforce", product: "Puppet Enterprise", versions: [{ version: "2023.8.0", status: "affected", lessThan: "2023.8.13" }, { version: "2023.8.13", status: "unaffected" }] }]);
    expect(perforce.patches).toEqual([{ label: "Perforce Puppet Enterprise", version: "2023.8.13", from: "2023.8.0", url: null, source: "cve" }]);
    const stated = fixedVersions([{ vendor: "Zammad", product: "Zammad", versions: [{ version: "7.2.2", status: "unaffected", lessThan: "*" }, { version: "6.0.0", status: "unaffected" }] }]);
    expect(stated.patches.map((p) => [p.version, p.status])).toEqual([["7.2.2", undefined]]);
    // "All" says the product is not affected at all; an unaffected range with a bound is an older range: neither is a version to install
    expect(fixedVersions([{ vendor: "Palo Alto Networks", product: "Cloud NGFW", versions: [{ version: "All", status: "unaffected", versionType: "custom" }] }]).patches).toEqual([]);
    expect(fixedVersions([{ vendor: "Linux", product: "Linux", versions: [{ version: "0", status: "unaffected", lessThan: "5.10" }, { version: "4.19", status: "unaffected", lessThanOrEqual: "5.9" }] }]).patches).toEqual([]);
    // Adobe writes several versions in one field; each is kept, and a product's free-text fix stays as written
    const adobe = fixedVersions([
      { vendor: "Adobe", product: "Magento Open Source", versions: [{ version: "2.4.9-2026-jul, 2.4.8-2026-jul, 2.4.7-2026-jul", status: "unaffected", versionType: "custom" }, { version: "0", status: "affected", lessThanOrEqual: "2.4.9, 2.4.8-p5" }] },
      { vendor: "Atlassian", product: "Crucible Data Center", versions: [{ version: "Patch version 4.9.15 and later", status: "unaffected" }, { version: "All other versions", status: "affected" }] },
    ]);
    expect(adobe.patches.map((p) => `${p.label}: ${p.status} ${p.version}`)).toEqual([
      "Adobe Magento Open Source: unaffected 2.4.9-2026-jul",
      "Adobe Magento Open Source: unaffected 2.4.8-2026-jul",
      "Adobe Magento Open Source: unaffected 2.4.7-2026-jul",
      "Atlassian Crucible Data Center: unaffected Patch version 4.9.15 and later",
    ]);
    // such a record has named safe versions, so GitHub is not asked for them
    expect(needsGhsa({ found: true, patches: ivanti.patches })).toBe(false);
  });

  it("keeps the CNA's solution and workaround as written, tidied, in English, and says a third-party CNA wrote them", () => {
    const p = parseCveRecord(unreal, "CVE-2026-114713");
    expect(p).toMatchObject({ by: "MITRE", by_vendor: false, affected: [{ vendor: "", product: "UnrealIRCd" }] });
    expect(p.patches).toEqual([{ label: "UnrealIRCd", version: "6.2.7.1", from: "6.2.0", url: null, source: "cve" }]);
    expect(p.solutions).toEqual([
      {
        text: "Upgrade to UnrealIRCd 6.2.7.1 or later. Alternatively, apply the hot-patch:\n./unrealircd hot-patch bundle-20261107",
        cut: false,
        kind: "cna",
        source: { publisher: "MITRE", title: "CVE-2026-114713, CVE record: solution", url: "https://www.cve.org/CVERecord?id=CVE-2026-114713" },
      },
    ]);
    expect(p.workarounds).toHaveLength(1);
    expect(p.workarounds[0]).toMatchObject({ kind: "cna", text: 'Add the following line to the configuration file: blacklist-module "labeled-response";' });
  });

  it("treats a rejected or malformed record as no record", () => {
    expect(parseCveRecord({ cveMetadata: { state: "REJECTED" }, containers: { cna: {} } }, "CVE-2026-0001")).toBe(NO_RECORD);
    expect(parseCveRecord({}, "CVE-2026-0001")).toBe(NO_RECORD);
  });

  it("attributes text to the vendor only when the CNA is the vendor", () => {
    expect(attribution("palo_alto", ["Palo Alto Networks"])).toEqual({ by: "Palo Alto Networks", by_vendor: true });
    expect(attribution("f5", ["F5"])).toEqual({ by: "F5", by_vendor: true });
    expect(attribution("Chrome", ["Google"])).toEqual({ by: "Google", by_vendor: true });
    expect(attribution("Google_Devices", ["Google"])).toEqual({ by: "Google", by_vendor: true });
    // GitHub's CNA is not a vendor called "git"; MITRE assigns for vendors that are not CNAs
    expect(attribution("GitHub_M", ["git"])).toEqual({ by: "GitHub", by_vendor: false });
    expect(attribution("mitre", ["n/a"])).toEqual({ by: "MITRE", by_vendor: false });
    expect(attribution("SomeCert", ["Acme"])).toEqual({ by: "SomeCert", by_vendor: false });
  });

  it("tidies whitespace without touching words, and cuts long text at a line or sentence", () => {
    expect(tidyText("  a  b \r\n\r\n\t c  ")).toBe("a b\nc");
    const long = `${"First sentence here. ".repeat(40)}`.trim();
    const cut = cutText(long);
    expect(cut.cut).toBe(true);
    expect(cut.text.length).toBeLessThanOrEqual(FIX_TEXT_MAX + 1);
    expect(cut.text.endsWith("here.…")).toBe(true);
    expect(cutText("short")).toEqual({ text: "short", cut: false });
  });
});

describe("CISA KEV, NVD and GitHub", () => {
  it("reads the notes: bare links are where CISA sends readers, labelled links are its guidance, NVD's page is dropped", () => {
    const notes = `This vulnerability could affect an open-source component. For more information, please see: ; https://lists.apache.org/thread/8slf0j9gz ; BOD 26-04: ${BOD} ; https://nvd.nist.gov/vuln/detail/CVE-2026-90436`;
    expect(parseKevNotes(notes)).toEqual({
      links: [{ url: "https://lists.apache.org/thread/8slf0j9gz", kind: "advisory", title: "", source: "kev" }],
      guidance: [{ label: "BOD 26-04", url: BOD }],
      note: "This vulnerability could affect an open-source component.",
    });
    expect(parseKevNotes("https://a.example/x; https://b.example/y?z=1;2")).toMatchObject({ links: [{ url: "https://a.example/x" }, { url: "https://b.example/y?z=1;2" }] });
    expect(parseKevNotes(undefined)).toEqual({ links: [], guidance: [], note: "" });
  });

  it("calls a link CISA's only when its hostname is cisa.gov or under it, whatever the note labels it", () => {
    // look-alikes: a name that ends in "cisa.gov", one that starts with it, and the same two for NVD
    const notes = [
      "https://notcisa.gov/a",
      "https://cisa.gov.example.org/b",
      "https://www.cisa.gov/c",
      "https://CISA.gov/d",
      "BOD 26-04: https://evilcisa.gov/e",
      `BOD 26-04: ${BOD}`,
      "Vendor fix: https://vendor.example/f",
      "https://nvd.nist.gov.example.org/g",
      "https://evilnvd.nist.gov/h",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
    ].join(" ; ");
    const link = (url: string, title = ""): FixLink => ({ url, kind: "advisory", title, source: "kev" });
    expect(parseKevNotes(notes)).toEqual({
      links: [link("https://notcisa.gov/a"), link("https://cisa.gov.example.org/b"), link("https://evilcisa.gov/e", "BOD 26-04"), link("https://vendor.example/f", "Vendor fix"), link("https://nvd.nist.gov.example.org/g"), link("https://evilnvd.nist.gov/h")],
      guidance: [{ label: "CISA", url: "https://www.cisa.gov/c" }, { label: "CISA", url: "https://cisa.gov/d" }, { label: "BOD 26-04", url: BOD }],
      note: "",
    });
    expect(isHostOf("https://cisa.gov/x", "cisa.gov")).toBe(true);
    expect(isHostOf("https://www.cisa.gov:443/x", "cisa.gov")).toBe(true);
    expect(isHostOf("https://cisa.gov./x", "cisa.gov")).toBe(true);
    for (const url of ["https://notcisa.gov/", "https://cisa.gov.example.org/", "https://example.org/cisa.gov", "https://example.org/?u=https://www.cisa.gov/", "https://user@example.org/#cisa.gov", "not a url"]) expect(isHostOf(url, "cisa.gov"), url).toBe(false);
  });

  it("keeps CISA's deadline, action and description as written", () => {
    const { kev, links } = kevBlock({ cveID: "CVE-2026-0007", vendorProject: "V", product: "P", vulnerabilityName: "N", dateAdded: "2026-11-18", shortDescription: "V P contains a flaw.", requiredAction: "Apply mitigations per vendor instructions.", dueDate: "2026-12-09", notes: "https://vendor.example/advisory ; https://nvd.nist.gov/vuln/detail/CVE-2026-0007" });
    expect(kev).toEqual({ added: "2026-11-18", due: "2026-12-09", action: "Apply mitigations per vendor instructions.", description: "V P contains a flaw.", note: "", guidance: [] });
    expect(links).toEqual([{ url: "https://vendor.example/advisory", kind: "advisory", title: "", source: "kev" }]);
    expect(kevBlock({ cveID: "CVE-2026-0008", vendorProject: "V", product: "P", vulnerabilityName: "N", dateAdded: "2026-11-18", shortDescription: "", dueDate: "soon" }).kev.due).toBeNull();
  });

  it("maps NVD's tags, a patch before an advisory", () => {
    expect(
      nvdLinks([
        { url: "https://vendor.example/a", tags: ["Vendor Advisory", "Patch"] },
        { url: "https://vendor.example/b", tags: ["Mitigation", "Vendor Advisory"] },
        { url: "https://x.example/c", tags: ["Exploit", "Third Party Advisory"] },
        { url: "https://x.example/d", tags: ["Vendor Advisory", "Broken Link"] },
        { url: "javascript:alert(1)", tags: ["Patch"] },
      ]),
    ).toEqual([
      { url: "https://vendor.example/a", kind: "patch", title: "", source: "nvd" },
      { url: "https://vendor.example/b", kind: "advisory", title: "", source: "nvd" },
    ]);
  });

  it("takes patched versions from a reviewed GitHub advisory only", () => {
    const adv = { ghsa_id: "GHSA-aaaa-bbbb-cccc", cve_id: "CVE-2026-0009", html_url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", summary: "RCE in example", description: null, severity: "high", type: "reviewed", published_at: "2026-11-01T00:00:00Z", vulnerabilities: [{ package: { ecosystem: "npm", name: "example" }, vulnerable_version_range: "< 2.3.1", first_patched_version: "2.3.1" }, { package: { ecosystem: "npm", name: "other" }, vulnerable_version_range: "*", first_patched_version: null }] };
    expect(ghsaParts(adv)).toEqual({
      patches: [{ label: "example (npm)", version: "2.3.1", from: "< 2.3.1", url: adv.html_url, source: "ghsa" }],
      links: [{ url: adv.html_url, kind: "advisory", title: "GHSA-aaaa-bbbb-cccc: RCE in example", source: "ghsa" }],
    });
    expect(ghsaParts({ ...adv, type: "unreviewed" })).toEqual({ patches: [], links: [] });
    expect(ghsaParts(null)).toEqual({ patches: [], links: [] });
    // shown as a GitHub advisory, so the page must be on github.com: a look-alike host is not taken
    expect(ghsaParts({ ...adv, html_url: "https://github.com.example.org/advisories/GHSA-aaaa-bbbb-cccc" })).toEqual({ patches: [], links: [] });
    expect(ghsaParts({ ...adv, html_url: "https://notgithub.com/advisories/GHSA-aaaa-bbbb-cccc" })).toEqual({ patches: [], links: [] });
  });

  it("merges links: each page once under its best mention, patch first, capped with a place for every kind", () => {
    const l = (url: string, kind: FixLink["kind"], source: FixLink["source"], title = ""): FixLink => ({ url, kind, title, source });
    const merged = mergeLinks([l("https://www.vendor.example/adv/", "advisory", "kev")], [l("http://vendor.example/adv", "advisory", "cve", "SA-1")], [l("https://vendor.example/patch", "patch", "nvd")]);
    expect(merged).toEqual([l("https://vendor.example/patch", "patch", "nvd"), l("http://vendor.example/adv", "advisory", "cve", "SA-1")]);
    expect(urlKey("https://www.vendor.example/adv/#top")).toBe(urlKey("http://vendor.example/adv"));
    const many = mergeLinks([...Array.from({ length: 12 }, (_, n) => l(`https://v.example/a${n}`, "advisory", "cve")), l("https://v.example/notes", "release_notes", "cve")]);
    expect(many).toHaveLength(FIX_LINK_MAX);
    expect(many.some((x) => x.kind === "release_notes")).toBe(true);
  });
});

/** A stored entry with nothing but its stamps: enough to plan lookups against. */
const entry = (cve: string, over: Partial<FixEntry> = {}): FixEntry => ({
  ...buildEntry({ cve, fetched_at: "2026-11-18T12:00:00.000Z", record: { ...NO_RECORD, found: true, cna: "acme", by: "Acme", by_vendor: true }, nvd: { at: null, links: [] }, ghsa: { at: null, patches: [], links: [] }, kev: null }),
  ...over,
});

describe("which CVEs, and which this run", () => {
  it("keeps the CVEs of live records, recent KEV entries and those with a deadline ahead", () => {
    const kev = [
      { cve: "CVE-2026-0001", added: "2026-11-18", due: "2026-12-09" },
      { cve: "CVE-2025-0002", added: "2026-08-21", due: "2026-09-11" }, // 90 days ago to the day: out
      { cve: "CVE-2025-0003", added: "2026-08-22", due: "2026-09-12" },
      { cve: "CVE-2024-0004", added: "2026-01-05", due: "2026-11-19" }, // old, but due today
      { cve: "CVE-2024-0005", added: "2026-01-05", due: null },
    ];
    expect(wantedCves(["CVE-2026-0009", "not-a-cve", "CVE-2026-0001"], kev, "2026-11-19", 90)).toEqual(["CVE-2024-0004", "CVE-2025-0003", "CVE-2026-0001", "CVE-2026-0009"]);
  });

  it("looks up new CVEs first (newest id first), then the entries read longest ago, within the budget", () => {
    const prev = new Map([
      ["CVE-2026-0001", entry("CVE-2026-0001", { fetched_at: "2026-11-10T00:00:00.000Z" })],
      ["CVE-2026-0002", entry("CVE-2026-0002", { fetched_at: "2026-11-12T00:00:00.000Z" })],
      ["CVE-2026-0003", entry("CVE-2026-0003", { fetched_at: "2026-11-18T00:00:00.000Z" })], // read yesterday: not due
    ]);
    const wanted = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0009", "CVE-2026-100000", "CVE-2025-99999"];
    expect(planLookups(wanted, prev, NOW, 10, 3)).toEqual(["CVE-2026-100000", "CVE-2026-0009", "CVE-2025-99999", "CVE-2026-0001", "CVE-2026-0002"]);
    expect(planLookups(wanted, prev, NOW, 2, 3)).toEqual(["CVE-2026-100000", "CVE-2026-0009"]);
    expect(planLookups(wanted, prev, NOW, 0, 3)).toEqual([]);
    // on a sweep that is not committed unless something changes, only the new CVEs: a re-read would move stamps nobody keeps
    expect(planLookups(wanted, prev, NOW, 10, 3, false)).toEqual(["CVE-2026-100000", "CVE-2026-0009", "CVE-2025-99999"]);
  });
});

/* ---------- the module, against a recorded-shape HTTP client ---------- */

/** The recorded requests that went to one host, by the parsed hostname (a substring of the URL would also match a look-alike). */
const sentTo = (calls: readonly string[], hostname: string) => calls.filter((u) => new URL(u).hostname === hostname);

function fakeHttp(answer: (url: string, opts?: HttpOptions) => unknown): StatsHttp & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async json<T>(url: string, opts?: HttpOptions) {
      calls.push(url);
      const out = answer(url, opts);
      if (out instanceof Error) throw out;
      return out as T;
    },
    async sleep() {
      /* no waiting in tests */
    },
  };
}

const kevStats = (version: string, entries: { cve: string; added: string; due: string | null }[]): KevStats => ({
  fetched_at: NOW.toISOString(),
  source: { name: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", license: "CC0 1.0" },
  catalog_version: version,
  entries: entries.map((e) => ({ ...e, vendor: "V", product: "P", name: "N", ransomware: false, published: null, cvss: null })),
});

const rawKev = (version: string, ids: string[]) => ({
  catalogVersion: version,
  vulnerabilities: ids.map((cveID) => ({ cveID, vendorProject: "V", product: "P", vulnerabilityName: "N", dateAdded: "2026-11-18", shortDescription: "A flaw.", requiredAction: "Apply mitigations per vendor instructions.", dueDate: "2026-12-09", notes: `https://vendor.example/${cveID} ; BOD 26-04: ${BOD}` })),
});

const published = (cve: string, cna: CveRecord["containers"] extends infer C ? (C extends { cna?: infer X } ? X : never) : never): CveRecord => ({ cveMetadata: { cveId: cve, state: "PUBLISHED", assignerShortName: "acme" }, containers: { cna } });

function world(opts: { catalog?: string; ghsaFails?: boolean; missing?: string[] } = {}) {
  return fakeHttp((url) => {
    if (url.startsWith("https://www.cisa.gov/")) return rawKev(opts.catalog ?? "2026.11.18", ["CVE-2026-0001", "CVE-2026-0002"]);
    if (url.startsWith("https://raw.githubusercontent.com/CVEProject/cvelistV5/")) {
      const cve = /CVE-\d+-\d+/.exec(url)![0];
      if (opts.missing?.includes(cve)) return new HttpError(`HTTP 404 for ${url}`, 404, url);
      // 0001: tagged advisory and a fixed version (asks nobody else); the others: neither (ask NVD and GitHub)
      if (cve === "CVE-2026-0001") return published(cve, { affected: [{ vendor: "Acme", product: "Router", versions: [{ version: "1.0", status: "affected", lessThan: "1.2" }] }], references: [{ url: "https://acme.example/sa-1", tags: ["vendor-advisory"] }], workarounds: [{ lang: "en", value: "Disable remote management." }] });
      return published(cve, { affected: [{ vendor: "Acme", product: "Switch", versions: [{ version: "2.0", status: "affected" }] }], references: [{ url: `https://acme.example/${cve}` }] });
    }
    if (url.startsWith("https://services.nvd.nist.gov/")) {
      const cve = /cveId=(CVE-\d+-\d+)/.exec(url)![1]!;
      return { totalResults: 1, resultsPerPage: 1, startIndex: 0, vulnerabilities: [{ cve: { id: cve, published: "2026-11-01T00:00:00.000", references: [{ url: `https://acme.example/${cve}`, tags: ["Vendor Advisory"] }] } }] };
    }
    if (url.startsWith("https://api.github.com/advisories")) return opts.ghsaFails ? new HttpError("HTTP 403", 403, url) : [];
    return new Error(`unexpected ${url}`);
  });
}

function ctx(http: StatsHttp, over: Partial<StatsContext> & { fix?: Partial<Settings["fix_lookup"]> } = {}): StatsContext {
  const { fix, ...rest } = over;
  const settings = { ...base, fix_lookup: { ...base.fix_lookup, ...fix } };
  return { settings, now: NOW, http, recordCveIds: [], liveCveIds: [], extraCveIds: [], produced: { kev: kevStats("2026.11.18", [{ cve: "CVE-2026-0001", added: "2026-11-18", due: "2026-12-09" }, { cve: "CVE-2026-0002", added: "2026-11-18", due: "2026-12-09" }]) }, log: () => undefined, ...rest };
}

describe("the fixes module", () => {
  beforeEach(() => resetNvdClock());

  it("builds an entry per wanted CVE from the record, CISA's catalog, and NVD and GitHub only where the record leaves a gap", async () => {
    const http = world();
    const out = (await fixesModule.fetch(ctx(http, { liveCveIds: ["CVE-2026-0003"] }), null))!;
    expect(out.kev_catalog_version).toBe("2026.11.18");
    expect(out.entries.map((e) => e.cve)).toEqual(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]);
    for (const e of out.entries) expect(FixEntrySchema.safeParse(e).success).toBe(true);
    const [a, b, c] = out.entries as [FixEntry, FixEntry, FixEntry];
    expect(a).toMatchObject({ found: true, by: "Acme", by_vendor: true, nvd_at: null, ghsa_at: null, patches: [{ label: "Acme Router", version: "1.2", from: "1.0", source: "cve" }] });
    expect(a.links.map((l) => `${l.kind}:${l.source}`)).toEqual(["advisory:cve", "advisory:kev"]);
    expect(a.workarounds[0]).toMatchObject({ text: "Disable remote management.", kind: "vendor", source: { publisher: "Acme", url: "https://www.cve.org/CVERecord?id=CVE-2026-0001" } });
    expect(a.kev).toMatchObject({ due: "2026-12-09", action: "Apply mitigations per vendor instructions.", guidance: [{ label: "BOD 26-04", url: BOD }] });
    // the record tags nothing and lists no fix: NVD's tag names the advisory, GitHub is asked for versions
    expect(b.nvd_at).toBe(NOW.toISOString());
    expect(b.ghsa_at).toBe(NOW.toISOString());
    expect(b.links.map((l) => `${l.kind}:${l.source}`)).toEqual(["advisory:nvd", "advisory:kev"]);
    // on a live record, not on KEV: no deadline
    expect(c.kev).toBeNull();
    expect(c.links).toEqual([{ url: "https://acme.example/CVE-2026-0003", kind: "advisory", title: "", source: "nvd" }]);
    // one catalog read, one file per CVE, NVD and GitHub for the two with gaps
    expect(http.calls.filter((u) => u.startsWith("https://www.cisa.gov/"))).toHaveLength(1);
    expect(sentTo(http.calls, "raw.githubusercontent.com")).toHaveLength(3);
    expect(sentTo(http.calls, "services.nvd.nist.gov")).toHaveLength(2);
    expect(sentTo(http.calls, "api.github.com")).toHaveLength(2);
  });

  it("spends at most the run's budgets, and gives an entry its missing NVD and GitHub answers on a later run without reading the record again", async () => {
    const first = (await fixesModule.fetch(ctx(world(), { liveCveIds: ["CVE-2026-0003", "CVE-2026-0004"], fix: { per_run: 3, nvd_per_run: 1, ghsa_per_run: 1 } }), null))!;
    // newest ids first: 0004, 0003, 0002 read; 0001 waits
    expect(first.entries.map((e) => e.cve)).toEqual(["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]);
    expect(first.entries.filter((e) => e.nvd_at !== null).map((e) => e.cve)).toEqual(["CVE-2026-0004"]);
    expect(first.entries.filter((e) => e.ghsa_at !== null).map((e) => e.cve)).toEqual(["CVE-2026-0004"]);

    const http = world();
    const later = new Date(NOW.getTime() + 1_800_000);
    const second = (await fixesModule.fetch({ ...ctx(http, { liveCveIds: ["CVE-2026-0003", "CVE-2026-0004"], fix: { per_run: 3, nvd_per_run: 5, ghsa_per_run: 5 } }), now: later }, first))!;
    expect(second.entries.map((e) => e.cve)).toEqual(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]);
    // only the waiting record is read; 0002 and 0003 get their NVD and GitHub answers, 0004 is left alone
    expect(sentTo(http.calls, "raw.githubusercontent.com").map((u) => /CVE-\d+-\d+/.exec(u)![0])).toEqual(["CVE-2026-0001"]);
    expect(sentTo(http.calls, "services.nvd.nist.gov").map((u) => /cveId=(CVE-\d+-\d+)/.exec(u)![1]).sort()).toEqual(["CVE-2026-0002", "CVE-2026-0003"]);
    const by = new Map(second.entries.map((e) => [e.cve, e]));
    expect(by.get("CVE-2026-0002")).toMatchObject({ fetched_at: NOW.toISOString(), nvd_at: later.toISOString(), ghsa_at: later.toISOString() });
    expect(by.get("CVE-2026-0002")!.links.some((l) => l.source === "nvd")).toBe(true);
    expect(by.get("CVE-2026-0004")).toEqual(first.entries.find((e) => e.cve === "CVE-2026-0004"));
  });

  it("records a CVE the program has not published, stops asking GitHub after a refusal, and survives a failed catalog read", async () => {
    const http = fakeHttp((url) => (url.startsWith("https://www.cisa.gov/") ? new Error("503") : world({ ghsaFails: true, missing: ["CVE-2026-0002"] }).json(url)));
    const out = (await fixesModule.fetch(ctx(http, { liveCveIds: ["CVE-2026-0003", "CVE-2026-0004"] }), null))!;
    const by = new Map(out.entries.map((e) => [e.cve, e]));
    expect(by.get("CVE-2026-0002")).toMatchObject({ found: false, cna: "", patches: [], links: [], nvd_at: null, ghsa_at: null, kev: null });
    // one refused GitHub call ends the lookups for the run; the entries stay marked as not asked
    expect(sentTo(http.calls, "api.github.com")).toHaveLength(1);
    expect(out.entries.every((e) => e.ghsa_at === null)).toBe(true);
    // no catalog: no KEV blocks yet, and the version stays unset so the next run reads it
    expect(out.kev_catalog_version).toBe("");
    expect(out.entries.every((e) => e.kev === null)).toBe(true);
  });

  it("reads the catalog again only for a new release or a missing block, refreshes every KEV block from it, and drops CVEs that left the set", async () => {
    const first = (await fixesModule.fetch(ctx(world()), null))!;
    const quiet = world();
    const same = (await fixesModule.fetch({ ...ctx(quiet), now: new Date(NOW.getTime() + 3_600_000) }, first))!;
    expect(quiet.calls).toEqual([]);
    expect(same.entries).toEqual(first.entries);

    const released = world({ catalog: "2026.11.20" });
    const next = (await fixesModule.fetch({ ...ctx(released), now: new Date(NOW.getTime() + 3_600_000), produced: { kev: kevStats("2026.11.20", [{ cve: "CVE-2026-0001", added: "2026-11-18", due: "2026-12-09" }]) } }, first))!;
    expect(released.calls).toEqual(["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"]);
    expect(next.kev_catalog_version).toBe("2026.11.20");
    // CVE-2026-0002 is no longer listed and on no live record: gone
    expect(next.entries.map((e) => e.cve)).toEqual(["CVE-2026-0001"]);
  });

  it("keeps the previous entry when a record would not fit the schema, instead of losing the whole file", async () => {
    const first = (await fixesModule.fetch(ctx(world(), { liveCveIds: ["CVE-2026-0003"] }), null))!;
    // four days later CVE-2026-0003's record comes back with a 300-character product name twice over the label's limit
    const odd = fakeHttp((url) => (url.includes("CVE-2026-0003.json") ? published("CVE-2026-0003", { affected: [{ vendor: "", product: "P", versions: [{ version: "1", status: "affected", lessThan: "2" }] }], references: [{ url: "https://acme.example/x", name: "n".repeat(300), tags: ["patch"] }] }) : world().json(url)));
    const logged: string[] = [];
    const next = (await fixesModule.fetch({ ...ctx(odd, { liveCveIds: ["CVE-2026-0003"] }), now: new Date(NOW.getTime() + 4 * 86_400_000), log: (m) => logged.push(m) }, first))!;
    // the title is cut to fit, so the entry is taken; nothing was logged as unfit
    expect(next.entries.find((e) => e.cve === "CVE-2026-0003")!.links[0]).toMatchObject({ kind: "patch", title: "n".repeat(200) });
    expect(logged.filter((m) => m.includes("does not fit"))).toEqual([]);
    for (const e of next.entries) expect(FixEntrySchema.safeParse(e).success).toBe(true);
  });

  it("on a sweep that is committed only if something changes, looks up new CVEs and re-reads nothing, so a quiet sweep stays quiet", async () => {
    // the first run leaves CVE-2026-0002 and CVE-2026-0003 without their NVD answer (budget 0)
    const first = (await fixesModule.fetch(ctx(world(), { liveCveIds: ["CVE-2026-0003"], fix: { nvd_per_run: 0 } }), null))!;
    const fourDays = new Date(NOW.getTime() + 4 * 86_400_000);
    // four days on every entry is due a re-read; with rechecks off nothing is asked and the file comes back as it was
    const quiet = world();
    const kept = (await fixesModule.fetch({ ...ctx(quiet, { liveCveIds: ["CVE-2026-0003"] }), now: fourDays, rechecks: false }, first))!;
    expect(quiet.calls).toEqual([]);
    expect(kept.entries).toEqual(first.entries);
    // a new CVE is still looked up, with its NVD answer: that is a real change, and the sweep is committed for it
    const fresh = world();
    const grown = (await fixesModule.fetch({ ...ctx(fresh, { liveCveIds: ["CVE-2026-0003", "CVE-2026-0004"] }), now: fourDays, rechecks: false }, first))!;
    expect(sentTo(fresh.calls, "raw.githubusercontent.com").map((u) => /CVE-\d+-\d+/.exec(u)![0])).toEqual(["CVE-2026-0004"]);
    expect(sentTo(fresh.calls, "services.nvd.nist.gov")).toHaveLength(1);
    expect(grown.entries.map((e) => e.cve)).toEqual(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]);
    expect(grown.entries.slice(0, 3)).toEqual(first.entries);
    // the same day on a sweep that is committed anyway: the re-reads and the missing answers are done
    const busy = world();
    const done = (await fixesModule.fetch({ ...ctx(busy, { liveCveIds: ["CVE-2026-0003"] }), now: fourDays }, first))!;
    expect(sentTo(busy.calls, "raw.githubusercontent.com")).toHaveLength(3);
    expect(done.entries.every((e) => e.fetched_at === fourDays.toISOString())).toBe(true);
    expect(done.entries.filter((e) => e.nvd_at !== null).map((e) => e.cve)).toEqual(["CVE-2026-0002", "CVE-2026-0003"]);
  });

  it("is off at a budget of zero", async () => {
    expect(await fixesModule.fetch(ctx(world(), { fix: { per_run: 0 } }), null)).toBeNull();
  });
});

describe("the fixes file in the stats run", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true }).catch(() => undefined);
  });

  it("is written one CVE per line, and a re-read that finds nothing new is bookkeeping, not a site change", async () => {
    resetNvdClock();
    const dir = await mkdtemp(path.join(tmpdir(), "radar-fixes-"));
    dirs.push(dir);
    // a kev.json for the module to read, written by the kev module's own run
    const http = fakeHttp((url) => {
      if (url.includes("hasKev")) return { totalResults: 0, resultsPerPage: 500, startIndex: 0, vulnerabilities: [] };
      return world().json(url);
    });
    const run = (now: Date) => runStats(base, { dataDir: dir, http, now, recordCveIds: [], liveCveIds: [], only: ["kev", "fixes"] });
    const first = await run(NOW);
    expect(first.failed).toEqual([]);
    expect(first.changed.sort()).toEqual(["stats/fixes.json", "stats/kev.json"]);
    expect(first.touched).toEqual([]);
    const raw = await readFile(path.join(dir, "stats", STATS_FILES.fixes), "utf8");
    expect(raw.split("\n").filter((l) => l.startsWith('  {"cve":'))).toHaveLength(2);
    const file = (await readAllStats(dir)).fixes as Fixes;
    expect(file.sources.map((s) => s.name)).toEqual(["CVE Program (CVE List)", "CISA Known Exploited Vulnerabilities catalog", "NVD", "GitHub Advisory Database"]);
    expect(file.sources[0]!.license).toContain("The MITRE Corporation");

    // an hour later nothing is due: nothing written
    const hour = await run(new Date(NOW.getTime() + 3_600_000));
    expect(hour.changed).toEqual([]);
    expect(hour.touched).toEqual([]);

    // four days later every entry is read again and says the same: the stamps move, the content does not
    const later = new Date(NOW.getTime() + 4 * 86_400_000);
    const again = await run(later);
    expect(again.changed).toEqual([]);
    expect(again.touched).toEqual(["stats/fixes.json"]);
    expect(((await readAllStats(dir)).fixes as Fixes).entries.every((e) => e.fetched_at === later.toISOString())).toBe(true);
  });
});
