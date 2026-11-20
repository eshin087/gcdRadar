import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { CATALOG, CATEGORIES, ancestorsOf, catalogEntry, catalogKey, descendants, rootOf } from "@/lib/catalog";
import { affectedByCve } from "@/lib/catalog/affected";
import { catalogMatchers, compile, recordFreeText, subjectOf, termPattern } from "@/lib/catalog/match";
import { STACK_MAX, byUrgency, findTyped, parsePicks, searchStack, sortByUrgency, stackUrgency, type StackCandidate } from "@/lib/panel/picks";
import { buildStack } from "@/lib/panel/stack";
import { PRODUCT_FAMILY_LABELS } from "@/lib/products";
import type { KevStatEntry, RecentCve } from "@/lib/stats-schema";

const matchers = catalogMatchers();
const matcher = (key: string) => matchers.find((m) => m.entry.key === key)!;
/** The keys of every curated entry that holds a KEV row. */
const onKev = (vendor: string, product: string, name = "") =>
  matchers
    .filter((m) => m.columns(vendor, product, name))
    .map((m) => m.entry.key)
    .sort();
const describedBy = (text: string) =>
  matchers
    .filter((m) => m.describes(text))
    .map((m) => m.entry.key)
    .sort();
const record = (title: string, products: string[] = [], tags: string[] = []) => ({ title, products, tags });
const onRecord = (title: string, products: string[] = [], tags: string[] = []) =>
  matchers
    .filter((m) => m.record(record(title, products, tags)))
    .map((m) => m.entry.key)
    .sort();

describe("the catalog", () => {
  it("is several hundred entries, every category in use", () => {
    expect(CATALOG.length).toBeGreaterThanOrEqual(400);
    const used = new Set(CATALOG.map((e) => e.cat));
    for (const c of CATEGORIES) if (c.key !== "kev") expect(used.has(c.key), c.key).toBe(true);
    expect(used.has("kev")).toBe(false);
  });
  it("has unique keys that are their own slugs, and no old key that is someone's key", () => {
    const keys = CATALOG.map((e) => e.key);
    expect(new Set(keys).size).toBe(keys.length);
    for (const k of keys) expect(catalogKey(k), k).toBe(k);
    const was = CATALOG.flatMap((e) => e.was);
    expect(new Set(was).size).toBe(was.length);
    for (const w of was) expect(keys.includes(w), w).toBe(false);
  });
  it("names every entry and its vendor, in a known category", () => {
    const cats = new Set<string>(CATEGORIES.map((c) => c.key));
    for (const e of CATALOG) {
      expect(e.name.trim(), e.key).not.toBe("");
      expect(e.vendor.trim(), e.key).not.toBe("");
      expect(cats.has(e.cat), e.key).toBe(true);
    }
  });
  it("hangs every product on a vendor entry that exists, without loops", () => {
    for (const e of CATALOG) {
      if (!e.parent) continue;
      const parent = catalogEntry(e.parent);
      expect(parent, `${e.key} -> ${e.parent}`).toBeDefined();
      expect(parent!.level, `${e.key} -> ${e.parent}`).toBe("vendor");
      expect(ancestorsOf(e).length).toBeLessThanOrEqual(2);
    }
    expect(descendants().get("broadcom")).toEqual(expect.arrayContaining(["vmware", "esxi", "vcenter"]));
    expect(rootOf(catalogEntry("esxi")!).key).toBe("broadcom");
  });
  it("compiles every term, and gives every entry something to match on", () => {
    for (const e of CATALOG) {
      expect(() => compile(e), e.key).not.toThrow();
      for (const r of e.kev) for (const src of [r.product, r.name]) if (src) expect(() => new RegExp(src), e.key).not.toThrow();
      expect(e.terms.length + e.kevVendors.length + e.kev.length + (e.family ? 1 : 0), e.key).toBeGreaterThan(0);
      for (const t of [...e.terms, ...(e.text ?? []), ...(e.cve ?? [])]) {
        expect(t, e.key).toBe(t.toLowerCase());
        // the matcher closes every term with a word boundary, so one that ends in a single digit or letter class could never be followed by a second
        expect(/(?:\\d|\])(?:\)|\||$)/.test(t), `${e.key}: ${t}`).toBe(false);
      }
    }
    expect(() => termPattern(["("])).toThrow();
  });
  it("lists every AI product family of lib/products.ts under its old key", () => {
    for (const label of PRODUCT_FAMILY_LABELS) {
      const e = CATALOG.find((x) => x.family === label);
      expect(e, label).toBeDefined();
      expect(e!.key, label).toBe(catalogKey(label));
      expect(e!.cat).toBe("ai");
    }
  });
  it("covers the areas a stack is made of", () => {
    for (const key of [
      ...["windows", "windows-server", "macos", "ios", "android", "linux", "ubuntu", "rhel", "chrome", "edge", "firefox", "safari"],
      ...["exchange-server", "sharepoint", "outlook", "office", "teams", "azure", "entra-id", "microsoft-365", "google-workspace", "zimbra", "slack", "zoom"],
      ...["cisco", "fortinet", "palo-alto-networks", "ivanti", "sonicwall", "netscaler", "f5", "juniper", "check-point", "zyxel", "mikrotik", "ubiquiti", "sophos", "watchguard"],
      ...["aws", "google-cloud", "vcenter", "esxi", "kubernetes", "docker", "okta", "active-directory", "cyberark", "keycloak"],
      ...["postgresql", "mysql", "mongodb", "redis", "sql-server", "oracle-database", "apache-http-server", "nginx", "tomcat", "node-js", "php", "spring", "openssl", "log4j"],
      ...["wordpress", "drupal", "magento", "github", "gitlab", "jenkins", "teamcity", "npm", "pypi"],
      ...["screenconnect", "teamviewer", "kaseya", "solarwinds", "manageengine", "veeam", "synology", "qnap", "netapp", "crowdstrike", "sentinelone"],
      ...["sap", "oracle", "salesforce", "servicenow", "chatgpt", "claude", "litellm", "langflow", "ollama"],
    ]) {
      expect(catalogEntry(key), key).toBeDefined();
    }
  });
  it("never lets an entry claim another vendor's product by name", () => {
    // every entry's own name, filed under its own vendor as CISA would file it, may only land inside its own family
    const allowed = new Map<string, string[]>([
      // GitHub belongs to Microsoft, and its Copilot is filed under both names
      ["github-copilot", ["copilot"]],
      // the vendor's name is part of these products' names
      ["libwebp", ["google"]],
      ["go", ["google"]],
      ["angular", ["google"]],
      ["tensorflow", ["google"]],
      ["react", ["meta"]],
      ["guacamole", ["apache"]],
      ["crowd", ["atlassian"]],
      ["asterisk", ["sangoma"]],
      ["streamlit", ["snowflake"]],
      ["gradio", ["hugging-face-libraries"]],
      ["spring", ["vmware"]],
      ["rabbitmq", ["vmware"]],
      ["horizon", ["vmware"]],
      ["cpanel", ["wordpress"]],
      ["rancher", ["suse"]],
      ["lxd", ["ubuntu"]],
      ["elastic", ["elastic"]],
    ]);
    const strays: string[] = [];
    for (const e of CATALOG) {
      const root = rootOf(e).key;
      for (const m of matchers) {
        if (m.entry === e || rootOf(m.entry).key === root) continue;
        if (!m.columns(e.vendor, e.name)) continue;
        if (allowed.get(e.key)?.includes(m.entry.key) || allowed.get(e.key)?.includes(rootOf(m.entry).key)) continue;
        strays.push(`${m.entry.key} claims ${e.vendor} | ${e.name} (${e.key})`);
      }
    }
    expect(strays).toEqual([]);
  });
});

describe("matching CISA's columns", () => {
  it("reads the vendor column first: a vendor holds every row under its name", () => {
    expect(onKev("Microsoft", "Silverlight")).toEqual(["microsoft"]);
    expect(onKev("Cisco", "BroadWorks")).toEqual(["cisco"]);
    expect(onKev("Apache", "Roller")).toEqual(["apache"]);
  });
  it("reads the product column next, in CISA's own wording", () => {
    expect(onKev("Microsoft", "Win32k")).toEqual(["microsoft", "windows", "windows-server"]);
    expect(onKev("Microsoft", "Exchange Server")).toEqual(["exchange-server", "microsoft"]);
    expect(onKev("Microsoft", "Office Outlook")).toEqual(["microsoft", "office", "outlook"]);
    expect(onKev("Cisco", "IOS and IOS XE Software")).toEqual(["cisco", "cisco-ios"]);
    expect(onKev("Citrix", "Application Delivery Controller (ADC) and Gateway")).toEqual(["citrix", "netscaler"]);
    expect(onKev("Ivanti", "Endpoint Manager Mobile (EPMM)")).toEqual(["ivanti", "ivanti-epmm"]);
    expect(onKev("Ivanti", "Endpoint Manager (EPM)")).toEqual(["ivanti", "ivanti-epm"]);
    expect(onKev("Fortinet", "FortiOS and FortiProxy")).toEqual(["fortinet", "fortios", "fortiproxy"]);
    expect(onKev("Apache", "Log4j2")).toEqual(["apache", "log4j"]);
    expect(onKev("Apple", "Multiple Products", "Apple Multiple Products WebKit Memory Corruption Vulnerability")).toEqual(["apple", "ios", "macos", "safari"]);
  });
  it("follows a vendor through its other names", () => {
    expect(onKev("Android", "Framework")).toEqual(["android", "google"]);
    expect(onKev("Broadcom", "VMware vCenter Server")).toEqual(["broadcom", "vcenter", "vmware"]);
    expect(onKev("VMware Tanzu", "Spring Cloud")).toEqual(["spring", "vmware"]);
    expect(onKev("Synacor", "Zimbra Collaboration Suite (ZCS)")).toEqual(["zimbra"]);
    expect(onKev("BerriAI", "LiteLLM")).toEqual(["litellm"]);
    expect(onKev("IBM", "Langflow")).toEqual(["ibm", "langflow"]);
    expect(onKev("PHP Group", "PHP")).toEqual(["php"]);
    expect(onKev("Vanderbilt University", "Research Electronic Data Capture (REDCap)")).toEqual(["redcap"]);
    expect(onKev("Pulse Secure", "Pulse Connect Secure")).toEqual(["ivanti", "ivanti-connect-secure"]);
  });
  it("keeps short and common names to their own vendor", () => {
    // Edge is Microsoft's browser, not VMware's SD-WAN Edge; Exchange is not the Internet Key Exchange
    expect(onKev("VMware", "SD-WAN Edge")).toEqual(["vmware"]);
    expect(onKev("Microsoft", "Internet Key Exchange (IKE) Service Extensions")).toEqual(["microsoft", "windows", "windows-server"]);
    expect(onKev("Microsoft", "Edge")).toEqual(["edge", "microsoft"]);
    // "entra" sits inside "N-central"; the old alias pattern put N-able's product under Microsoft
    expect(onKev("N-able", "N-central")).toEqual(["n-able"]);
    expect(onKev("Microsoft", "Teams")).toEqual(["microsoft", "teams"]);
    // "for" names a platform: a driver for Windows is Intel's, a library for Node.js is not Node.js
    expect(onKev("Intel", "Ethernet Diagnostics Driver for Windows")).toEqual(["intel"]);
    expect(onKev("Npm package", "System Information Library for Node.JS")).toEqual(["npm"]);
    expect(onKev("Git", "Git")).toEqual(["git"]);
    expect(onKev("GitLab", "Community and Enterprise Editions")).toEqual(["gitlab"]);
    expect(onKev("Gitea", "Gitea")).toEqual(["gitea"]);
    expect(onKev("Oracle", "Java SE")).toEqual(["java", "oracle"]);
    expect(onKev("Apple", "iOS")).toEqual(["apple", "ios"]);
    expect(onKev("Cisco", "IOS XR")).toEqual(["cisco", "cisco-ios"]);
  });
  it("leaves an unknown vendor to the long tail", () => {
    expect(onKev("Ahsay", "AhsayCBS")).toEqual([]);
    expect(onKev("Daemon", "Daemon Tools Lite")).toEqual([]);
  });
});

describe("matching the real KEV file", () => {
  const file = JSON.parse(readFileSync(path.join(process.cwd(), "data/stats/kev.json"), "utf8")) as { entries: KevStatEntry[] };
  const byCve = new Map(file.entries.map((e) => [e.cve, e]));

  it("puts most of CISA's catalog on a curated entry", () => {
    const held = file.entries.filter((e) => matchers.some((m) => m.columns(e.vendor, e.product, e.name))).length;
    expect(held / file.entries.length).toBeGreaterThan(0.9);
  });
  it("holds a hand-checked sample of real entries where a reader would look for them", () => {
    // read by hand against the catalog on 2026-11-20; a row CISA has since changed is skipped
    const sample: [string, string[]][] = [
      ["CVE-2021-44228", ["apache", "log4j"]],
      ["CVE-2023-34362", ["moveit", "progress"]],
      ["CVE-2023-4966", ["citrix", "netscaler"]],
      ["CVE-2024-3400", ["palo-alto-networks", "pan-os"]],
      ["CVE-2024-1709", ["connectwise", "screenconnect"]],
      ["CVE-2023-22515", ["atlassian", "confluence"]],
      ["CVE-2024-21887", ["ivanti", "ivanti-connect-secure"]],
      ["CVE-2023-27997", ["fortinet", "fortios", "fortiproxy"]],
      ["CVE-2021-26855", ["exchange-server", "microsoft"]],
      ["CVE-2023-20198", ["cisco", "cisco-ios"]],
      ["CVE-2024-23897", ["jenkins"]],
      ["CVE-2023-42793", ["jetbrains", "teamcity"]],
      ["CVE-2022-22965", ["spring", "vmware"]],
      ["CVE-2021-21972", ["vcenter", "vmware"]],
      ["CVE-2022-1388", ["big-ip", "f5"]],
      ["CVE-2023-46805", ["ivanti", "ivanti-connect-secure"]],
      ["CVE-2020-1472", ["active-directory", "microsoft", "windows", "windows-server"]],
      ["CVE-2024-4577", ["php"]],
      ["CVE-2023-3519", ["citrix", "netscaler"]],
      ["CVE-2022-41040", ["exchange-server", "microsoft"]],
      ["CVE-2024-10441", ["synology", "synology-dsm"]],
      ["CVE-2026-40217", ["litellm"]],
      ["CVE-2026-90436", ["apache", "apache-axis"]],
    ];
    let checked = 0;
    for (const [cve, keys] of sample) {
      const e = byCve.get(cve);
      if (!e) continue;
      checked += 1;
      expect(onKev(e.vendor, e.product, e.name), `${cve} ${e.vendor} | ${e.product}`).toEqual(keys);
    }
    expect(checked).toBeGreaterThan(sample.length / 2);
  });
  it("builds a candidate for every vendor on the list, each under one key", () => {
    const stack = buildStack([], file.entries, "2026-11-20", "2026-11-20T06:00:00.000Z");
    const keys = stack.candidates.map((c) => c.key);
    expect(new Set(keys).size).toBe(keys.length);
    const known = new Set(keys);
    for (const vendor of new Set(file.entries.map((e) => e.vendor.trim()))) {
      const k = catalogKey(vendor);
      expect(known.has(k) || stack.aliases[k] !== undefined, `${vendor} (${k})`).toBe(true);
    }
    for (const [old, now] of Object.entries(stack.aliases)) {
      expect(known.has(old), old).toBe(false);
      expect(known.has(now), `${old} -> ${now}`).toBe(true);
    }
  });
  it("never lists a CVE on CISA's list as a new critical, whatever NVD's file holds that day", () => {
    const recent = JSON.parse(readFileSync(path.join(process.cwd(), "data/stats/cves-recent.json"), "utf8")) as { cves: RecentCve[] };
    // "now" is the newest CVE in the file, so its last 14 days are in the window on any day the test runs
    const now = recent.cves.reduce((top, c) => (c.published > top ? c.published : top), "");
    const stack = buildStack([], file.entries, now.slice(0, 10), now, { criticals: recent.cves });
    const listed = stack.candidates.flatMap((c) => c.crits ?? []);
    expect(listed.length).toBeGreaterThan(0);
    expect([...new Set(listed.filter((c) => byCve.has(c.id)).map((c) => c.id))]).toEqual([]);
  });
  it("keeps the keys picks were saved under before the catalog", () => {
    // /stats/stack.json as production served it on 2026-11-20: 88 candidates
    const before = "microsoft google linux cisco litellm apple citrix apache connectwise plex claude jfrog palo-alto-networks adobe chatgpt check-point claude-code-sdks fortinet ivanti mikrotik oracle sonicwall synology wordpress ahsay arista atlassian barracuda-networks berriai diskstation-manager f5 fireworks-ai gitlab hugging-face-libraries langflow n-able openai-models papercut php-group red-hat siemens vanderbilt-university zammad-gmbh zyxel acronis ajax-net-professional apache-axis beyondtrust broadcom claude-code-extension collabora cursor eg-secure-solutions gitea gpt-5-6 gpustack ibm isc kestra kludex llama-cpp onlyoffice openai-operator openbsd opencode opencode-console openwave-messaging-limited owncloud perforce proftpd railway sangoma sglang signalwire strapi unrealircd vllm warp-agentic-development-environment wso2".split(" ");
    // not products anyone runs: dropped on purpose
    const dropped = ["ai-agents", "ai-assistants", "agent-framework", "chainalysis-internal-tools", "cloud-resources", "court-ai-document-processing-system", "large-language-models", "near-ai", "northflank"];
    const stack = buildStack([], file.entries, "2026-11-20", "2026-11-20T06:00:00.000Z");
    const known = new Set(stack.candidates.map((c) => c.key));
    for (const key of before) expect(parsePicks(key, known, stack.aliases), key).toHaveLength(1);
    expect(parsePicks(before.join(","), known, stack.aliases).length).toBe(STACK_MAX);
    expect(parsePicks("berriai,php-group,zammad-gmbh,vanderbilt-university,diskstation-manager,gpt-5-6,kludex,isc", known, stack.aliases)).toEqual(["litellm", "php", "zammad", "redcap", "synology-dsm", "openai", "fastapi", "bind"]);
    expect(parsePicks(dropped.join(","), known, stack.aliases)).toEqual([]);
  });
});

describe("matching records", () => {
  it("reads the product names, then the title and tags", () => {
    expect(onRecord("Critical RCE Vulnerabilities in Citrix NetScaler ADC and Gateway", ["NetScaler ADC", "NetScaler Gateway"])).toEqual(["citrix", "netscaler"]);
    expect(onRecord("Microsoft Teams IT Support Scams Deploy Malware and Ransomware", ["Microsoft Teams"])).toEqual(["microsoft", "teams"]);
    expect(onRecord("Help desk impersonation leads to ransomware", [], ["windows", "ransomware"])).toEqual(["windows"]);
    expect(onRecord("LiteLLM Compromised in Supply Chain Attack", ["LiteLLM"])).toEqual(["litellm"]);
  });
  it("keeps common words out: a team is not Teams, an oracle is not Oracle, an outlook is not Outlook", () => {
    expect(onRecord("Red teams breach a retailer through its help desk", ["Retail POS"])).toEqual([]);
    expect(onRecord("Price oracle manipulation drains a lending protocol", ["Lending protocol"])).toEqual([]);
    expect(onRecord("The outlook for ransomware payments in 2027")).toEqual([]);
    expect(onRecord("Attackers go after rust-belt utilities with a new exchange scam")).toEqual([]);
    expect(onRecord("Git repositories leaked by a misconfigured server")).toEqual([]);
    expect(onRecord("Railway operator hit by ransomware", ["Railway signalling"])).toEqual([]);
    expect(onRecord("Railway Breach Leads to Stolen AI Keys", ["Railway"])).toEqual(["railway"]);
  });
  it("files a product that belongs to an AI family under that family alone", () => {
    expect(onRecord("MCP Atlassian command injection", ["MCP Atlassian"], ["mcp-atlassian"])).toEqual(["mcp-servers-tools"]);
    expect(onRecord("pgEdge Postgres MCP Server flaw", ["pgEdge Postgres MCP Server"])).toEqual(["mcp-servers-tools"]);
    expect(onRecord("Claude Code extension poisoned with a backdoor", ["Claude Code"])).toEqual(["claude-code-sdks"]);
    expect(recordFreeText(record("MCP Atlassian command injection", ["MCP Atlassian"], ["mcp-atlassian"]))).not.toContain("atlassian");
  });
  it("takes a family's own label as that family, with nothing in the title to go by", () => {
    // productFamily answers a label with the label, as it answers a name it does not know: the label is still the family
    expect(onRecord("API keys stolen through a poisoned release", ["LiteLLM"])).toEqual(["litellm"]);
    expect(onRecord("Model server left open to the internet", ["Ollama"])).toEqual(["ollama"]);
    for (const label of PRODUCT_FAMILY_LABELS) {
      const own = CATALOG.filter((e) => e.family === label).map((e) => e.key).sort();
      expect(own.length, label).toBeGreaterThan(0);
      expect(onRecord("API keys stolen through a poisoned release", [label]), label).toEqual(own);
    }
    // a name no family knows is still read as a name
    expect(onRecord("API keys stolen through a poisoned release", ["NetScaler ADC"])).toEqual(["citrix", "netscaler"]);
  });
  it("does not take the one who reports the news for the one that was hit", () => {
    expect(onRecord("Google disrupts a 1.3 million-device botnet", ["XCPE malware"])).toEqual([]);
    expect(onRecord("Google Chrome exploited use-after-free in XML", ["Google Chrome"])).toEqual(["chrome", "google"]);
    // a security vendor in the tags is the source, not the victim
    expect(onRecord("Hackers hijack exposed AI models for unauthorized computing", [], ["symantec", "honeypot"])).toEqual([]);
    expect(onRecord("Symantec Endpoint Protection flaw exploited", ["Symantec Endpoint Protection"])).toEqual(["symantec"]);
  });
});

describe("matching CVE descriptions", () => {
  it("finds the subject of the sentence", () => {
    expect(subjectOf("grav before 1.7.53.7 contains an authentication bypass")).toEqual({ span: [0, 3], head: 0 });
    expect(subjectOf("react is a javascript library for building user interfaces.")).toEqual({ span: [0, 4], head: 0 });
    expect(subjectOf("the shop sync plugin for wordpress is vulnerable to sql injection")).toEqual({ span: [4, 4], head: 0 });
    expect(subjectOf("double free in windows dns allows an unauthorized attacker to execute code").span).toBeNull();
  });
  it("matches the vendors' own sentence forms", () => {
    expect(describedBy("Double free in Windows DNS allows an unauthorized attacker to execute code over a network.")).toEqual(["windows", "windows-server"]);
    expect(describedBy("Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).")).toEqual(["fusion-middleware", "oracle", "weblogic"]);
    expect(describedBy("Use after free in WebView in Google Chrome on Android prior to 158.0.8127.36 allowed a remote attacker to execute arbitrary code")).toEqual(["chrome", "google"]);
    expect(describedBy("A improper authorization vulnerability in Fortinet FortiManager 8.0.0, FortiManager 7.6.0 through 7.6.7 may allow an attacker")).toEqual(["fortimanager", "fortinet"]);
    expect(describedBy("Memory overflow in SMPP traffic can lead to unpredictable or erroneous behavior or Denial of Service in Citrix NetScaler ADC")).toEqual(["citrix", "netscaler"]);
    expect(describedBy("In JetBrains TeamCity before 2026.1.3, 2025.11.7 remote code execution was possible via argument injection in Perforce settings")).toEqual(["jetbrains", "teamcity"]);
    expect(describedBy("Craft CMS from 5.0.0 before 5.11.2 contains an authorization bypass vulnerability")).toEqual(["craft-cms"]);
    expect(describedBy("In SendInfo of UssiController.cpp, there is a possible way to corrupt memory due to a use after free.")).toEqual(["android"]);
    expect(describedBy("SAP NetWeaver Application Server ABAP does not sufficiently validate certain network input.")).toEqual(["sap", "sap-netweaver"]);
  });
  it("does not count a platform, an add-on's host or part of another name", () => {
    // every one of these matched an entry before the subject rule, on the NVD file of 2026-11-19
    for (const text of [
      "The Cloud Storage Manager for Fluent Forms – Google Drive, Dropbox, OneDrive, S3 Uploads plugin for WordPress is vulnerable to Arbitrary File Write",
      "The Ahime Image Printer WordPress plugin through 1.0.0 does not validate the name of uploaded files",
      "The Registration Form for WooCommerce plugin for WordPress is vulnerable to privilege escalation",
      "Portabase is a database backup and restore tool for PostgreSQL, MySQL, MsSQL, MariaDB, Firebird SQL, SQLite, MongoDB, Redis",
      "cf-manager is an all-in-one dashboard for managing multiple Cloudflare accounts and services.",
      "rabbitmq-c is a C-language AMQP client library for RabbitMQ.",
      "AdminNeo before 5.9.1 contains an authentication bypass vulnerability in the ClickHouse driver that allows remote attackers to log in",
      "pnpm exe before 10.34.8 embeds an outdated Node.js runtime that still trusts compromised intermediate CA certificates",
      "blueprintUE Self-Hosted Edition before 4.3.7 contains an insecure default configuration in its Docker Compose examples",
      "OpsTree BuildPiper before 2.7.0 contains a privilege escalation vulnerability that allows project users to gain Kubernetes cluster access",
      "HTTP::Session versions before 0.43 for Perl allow memcached command injection via unfiltered session ids",
      "INDOTALENT WHMS (Asp.Net-Core-Inventory-Order-Management-System) before 10.20261109 contains an authentication bypass vulnerability",
      "Incorrect Privilege Assignment vulnerability in miniOrange OAuth Single Sign On miniorange-login-with-eve-online-google-facebook allows Privilege Escalation",
      "Jumis (formerly Tildes Jumis) creates and uses a Microsoft SQL Server login named ##Tilde_JumisAdmin##",
      "MyMangaDB is a self-hosted manga collection manager with automatic metadata, MyAnimeList import, Docker support, and collection statistics.",
      "Improper Input Validation in a third-party VPN client for Windows may allow an unauthenticated user to escalate privileges",
      "Dancer versions before 1.3400 for Perl pass unvalidated session ids from the session cookie to the session engine.",
    ]) {
      expect(describedBy(text), text).toEqual([]);
    }
    expect(describedBy("Zohocorp ManageEngine M365 Manager Plus versions below 4818 is affected by an authenticated technician vulnerability")).toEqual(["manageengine", "zoho"]);
    expect(describedBy("Improper Input Validation in Zoom Workplace for Windows may allow an unauthenticated user to conduct an escalation of privilege")).toEqual(["zoom"]);
    expect(describedBy("Server-side request forgery (ssrf) in Azure Managed Grafana allows an unauthorized attacker to elevate privileges over a network.")).toEqual(["azure"]);
  });
  it("never reads a description for the package registries, whose names are in thousands of them", () => {
    expect(matcher("npm").describes("npm before 11.2.0 allows a malicious package to run code")).toBe(false);
    expect(matcher("pypi").describes("PyPI package foo before 1.2 allows code execution")).toBe(false);
  });
});

describe("the CVE Program's names, when a file has them", () => {
  it("reads the shapes such a file is likely to take", () => {
    const pairs = [{ vendor: "Fortinet", product: "FortiWeb" }];
    expect(affectedByCve({ "CVE-2026-0001": { affected: pairs } }).get("CVE-2026-0001")).toEqual(pairs);
    expect(affectedByCve({ cves: { "cve-2026-0002": { vendor: "Fortinet", product: "FortiWeb" } } }).get("CVE-2026-0002")).toEqual(pairs);
    expect(affectedByCve({ fixes: [{ cve: "CVE-2026-0003", vendors: ["Fortinet"], products: ["FortiWeb", "FortiProxy"] }] }).get("CVE-2026-0003")).toEqual([...pairs, { vendor: "Fortinet", product: "FortiProxy" }]);
    expect(affectedByCve([{ id: "CVE-2026-0004", product: "FortiWeb" }]).get("CVE-2026-0004")).toEqual([{ vendor: "", product: "FortiWeb" }]);
    // the shape the fix-first work's data/stats/fixes.json has (its hand-over note, 2026-11-20)
    const fixes = { fetched_at: "2026-11-20T06:00:00.000Z", sources: [], kev_catalog_version: "2026.11.18", entries: [{ cve: "CVE-2024-10441", found: true, affected: [{ vendor: "Synology", product: "DiskStation Manager (DSM)" }, { vendor: "Synology", product: "BeeStation OS (BSM)" }], patches: [] }] };
    expect(affectedByCve(fixes).get("CVE-2024-10441")).toEqual(fixes.entries[0]!.affected);
  });
  it("is empty for a file without them, or no file", () => {
    expect(affectedByCve(undefined).size).toBe(0);
    expect(affectedByCve({ generated_at: "2026-11-20", cves: { "CVE-2026-0005": { fix: "upgrade to 2.0" } } }).size).toBe(0);
    expect(affectedByCve("nonsense").size).toBe(0);
  });
  it("matches those names the way a KEV row is matched, other vendors' spellings included", () => {
    expect(onKev("Oracle Corporation", "WebLogic Server")).toEqual(["oracle", "weblogic"]);
    expect(onKev("Apache Software Foundation", "Apache Tomcat")).toEqual(["apache", "tomcat"]);
    expect(onKev("The PHP Group", "PHP")).toEqual(["php"]);
    // the CVE Program's records spell names their own way
    expect(onKev("jfrog", "artifactory")).toEqual(["jfrog"]);
    expect(onKev("Microsoft", "Windows 11 Version 24H2")).toEqual(["microsoft", "windows", "windows-server"]);
    expect(onKev("Linux", "Linux")).toEqual(["linux"]);
    // a record that names no vendor: the vendor's own naming scheme still says whose it is, a product's short name alone does not
    expect(onKev("", "FortiWeb")).toEqual(["fortinet"]);
    expect(onKev("", "Edge")).toEqual([]);
  });
});

describe("the urgency order", () => {
  const c = (over: Partial<StackCandidate>): StackCandidate => ({ key: "k", label: "K", kind: "vendor", vendor: "K", cat: "os", level: "product", n: 0, flag: null, why: [], due: null, late: null, patch: null, impact: false, flagScore: null, cvss: null, crit: 0, tier: 5, kev7: [], href: "", ...over });
  const TODAY = "2026-11-20";

  it("puts a product in one of five tiers", () => {
    expect(stackUrgency(c({ patch: "unpatched" }), TODAY)).toBe(1);
    expect(stackUrgency(c({ patch: "partial" }), TODAY)).toBe(1);
    expect(stackUrgency(c({ due: "2026-11-20" }), TODAY)).toBe(1);
    expect(stackUrgency(c({ due: "2026-11-23" }), TODAY)).toBe(1);
    expect(stackUrgency(c({ late: "2026-11-15" }), TODAY)).toBe(1);
    expect(stackUrgency(c({ due: "2026-11-24" }), TODAY)).toBe(2);
    expect(stackUrgency(c({ due: "2026-11-24", impact: true, crit: 4 }), TODAY)).toBe(2);
    expect(stackUrgency(c({ impact: true, crit: 4 }), TODAY)).toBe(3);
    expect(stackUrgency(c({ crit: 4 }), TODAY)).toBe(4);
    expect(stackUrgency(c({}), TODAY)).toBe(5);
    // the same deadline is three days off tomorrow
    expect(stackUrgency(c({ due: "2026-11-24" }), "2026-11-21")).toBe(1);
  });
  it("orders a tier by CVSS, then the nearest deadline, the most items, the name", () => {
    const list = [
      c({ label: "Quiet B" }),
      c({ label: "Quiet A" }),
      c({ label: "Busy quiet", n: 4 }),
      c({ label: "Criticals", tier: 4, crit: 2, cvss: 9.8 }),
      c({ label: "Impact", tier: 3, impact: true }),
      c({ label: "Later, far", tier: 2, due: "2026-12-05", cvss: 9.9 }),
      c({ label: "Later, near", tier: 2, due: "2026-11-27", cvss: 7.1 }),
      c({ label: "No patch, 8.1", tier: 1, patch: "unpatched", cvss: 8.1 }),
      c({ label: "Due soon, 9.8", tier: 1, due: "2026-11-21", cvss: 9.8 }),
      c({ label: "Past due, 9.8", tier: 1, late: "2026-11-18", cvss: 9.8 }),
      c({ label: "No score", tier: 1, patch: "partial" }),
    ];
    expect(sortByUrgency(list).map((x) => x.label)).toEqual(["Past due, 9.8", "Due soon, 9.8", "No patch, 8.1", "No score", "Later, near", "Later, far", "Impact", "Criticals", "Busy quiet", "Quiet A", "Quiet B"]);
    expect(byUrgency(list[0]!, list[0]!)).toBe(0);
  });
});

describe("the chooser's search", () => {
  const c = (key: string, label: string, over: Partial<StackCandidate> = {}): StackCandidate => ({ key, label, kind: "vendor", vendor: label, cat: "os", level: "product", n: 0, flag: null, why: [], due: null, late: null, patch: null, impact: false, flagScore: null, cvss: null, crit: 0, tier: 5, kev7: [], href: "", ...over });
  const list = [
    c("microsoft", "Microsoft", { level: "vendor", also: ["Silverlight", "Skype for Business"], aka: ["msft"] }),
    c("windows", "Windows", { vendor: "Microsoft", tier: 1, patch: "unpatched" }),
    c("teams", "Microsoft Teams", { vendor: "Microsoft" }),
    c("microsoft-365", "Microsoft 365", { vendor: "Microsoft", aka: ["office 365", "o365"] }),
    c("postgresql", "PostgreSQL", { aka: ["postgres"] }),
    c("sql-server", "SQL Server", { vendor: "Microsoft" }),
    c("mysql", "MySQL", { vendor: "Oracle" }),
  ];
  const keys = (q: string) => searchStack(list, q).hits.map((h) => h.c.key);

  it("puts names before vendors, and the urgent first inside a rank", () => {
    expect(keys("micro")).toEqual(["microsoft", "microsoft-365", "teams", "windows", "sql-server"]);
    expect(keys("sql")).toEqual(["sql-server", "mysql", "postgresql"]);
    expect(keys("Microsoft  Teams")).toEqual(["teams"]);
  });
  it("answers to other names and to the products a vendor covers, saying which", () => {
    expect(searchStack(list, "o365").hits).toMatchObject([{ c: { key: "microsoft-365" }, rank: 5, via: "o365" }]);
    expect(searchStack(list, "silverlight").hits).toMatchObject([{ c: { key: "microsoft" }, rank: 6, via: "Silverlight" }]);
    expect(keys("postgres")).toEqual(["postgresql"]);
    expect(keys("nothing like it")).toEqual([]);
    expect(searchStack(list, "  ")).toEqual({ hits: [], total: 0 });
  });
  it("caps what it returns and says how many there were", () => {
    const found = searchStack(list, "s", 2);
    expect(found.total).toBe(7);
    // the one name that starts with it, then the most urgent of those that hold it
    expect(found.hits.map((h) => h.c.key)).toEqual(["sql-server", "windows"]);
  });
  it("finds where the typed part starts, a word's start first", () => {
    expect(findTyped("microsoft teams", "tea")).toBe(10);
    expect(findTyped("postgresql", "sql")).toBe(7);
    expect(findTyped("sql server sqlite", "sql")).toBe(0);
    expect(findTyped("windows", "x")).toBe(-1);
  });
});
