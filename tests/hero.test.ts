import { describe, expect, it } from "vitest";
import { BLOCK_GLYPHS } from "@/components/hero/BlockNumeral";
import { productName, shortProduct } from "@/components/hero/ExploitedWeek";

describe("the hero's exploited rows", () => {
  it("names a KEV product the way people say it", () => {
    expect(productName({ vendor: "PHP Group", product: "PHP" })).toBe("PHP");
    expect(productName({ vendor: "GitLab", product: "GitLab" })).toBe("GitLab");
    expect(productName({ vendor: "Ivanti", product: "Connect Secure" })).toBe("Ivanti Connect Secure");
    expect(productName({ vendor: "Cisco", product: "Secure Firewall ASA" })).toBe("Cisco Secure Firewall ASA");
    expect(productName({ vendor: "", product: "Exim" })).toBe("Exim");
    expect(productName({ vendor: "Zimbra", product: "" })).toBe("Zimbra");
  });

  it("shortens a name to the one CISA gives in brackets, for a line of several", () => {
    expect(shortProduct({ vendor: "Synology", product: "DiskStation Manager (DSM)" })).toBe("Synology DSM");
    expect(shortProduct({ vendor: "Vanderbilt University", product: "Research Electronic Data Capture (REDCap)" })).toBe("REDCap");
    expect(shortProduct({ vendor: "BerriAI", product: "LiteLLM" })).toBe("BerriAI LiteLLM");
    expect(shortProduct({ vendor: "Citrix", product: "NetScaler ADC and Gateway" })).toBe("Citrix NetScaler ADC and Gateway");
    expect(shortProduct({ vendor: "GitLab", product: "Community and Enterprise Editions (GitLab CE/EE)" })).toBe("GitLab CE/EE");
  });

  it("draws every digit of the block numeral on a 5 by 7 grid", () => {
    expect(Object.keys(BLOCK_GLYPHS).sort().join("")).toBe("0123456789");
    for (const rows of Object.values(BLOCK_GLYPHS)) {
      expect(rows).toHaveLength(7);
      expect(rows.every((r) => /^[01]{5}$/.test(r))).toBe(true);
    }
    // no two digits share a shape
    expect(new Set(Object.values(BLOCK_GLYPHS).map((r) => r.join(""))).size).toBe(10);
  });
});
