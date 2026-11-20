import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { BUDGET_GAP_MINUTES, commitsSweep, HEARTBEAT_MINUTES, overPushBudget, PUSH_BUDGET, quietSweep, type QuietInput } from "@/collector/cadence";
import { loadConfig, type Schedule } from "@/collector/lib/config";
import { checkLiveFiles, LIVE_BRANCH_FILES, liveIdentity, publishLive } from "@/collector/live";
import { DUE_HOURS, isDue } from "@/collector/pipeline/run";
import { kevModule, KEV_URL } from "@/collector/stats/kev";
import type { StatsContext } from "@/collector/stats/types";
import type { RunRecord } from "@/lib/schema";

/** How often a sweep reaches main (collector/cadence.ts), where its live files go (collector/live.ts), and what four sweeps an hour ask of the sources. */

const schedules = new Map<string, Schedule>([
  ["thn", "every_run"],
  ["kev", "every_run"],
  ["nvd", "two_hourly"],
  ["hibp", "six_hourly"],
]);

function run(over: Partial<Pick<RunRecord, "errors" | "sources">> & { pending?: number; calls?: number } = {}): QuietInput["record"] {
  return {
    errors: over.errors ?? [],
    counts: { fetched: 12, prefiltered: 0, merged: 0, classified: 0, published: 0, review: 0, rejected: 0, pending: over.pending ?? 0, updated: 0, closed: 0, reopened: 0 },
    llm: { calls: over.calls ?? 0, prompt_tokens: 0, completion_tokens: 0, by_model: {} },
    sources: over.sources ?? [
      { id: "thn", ok: true, items: 12, duration_ms: 200 },
      { id: "kev", ok: true, items: 0, duration_ms: 80 },
    ],
  };
}

const quiet = (over: Partial<QuietInput> = {}): QuietInput => ({ changedFiles: ["runs.json", "collector-state.json"], sideChanged: false, record: run(), lookedUp: 0, schedules, ...over });

describe("a quiet sweep", () => {
  it("is one that changed only the run ledger and the sources' clock", () => {
    expect(quietSweep(quiet())).toBe(true);
    expect(quietSweep(quiet({ changedFiles: ["runs.json"] }))).toBe(true);
    expect(quietSweep(quiet({ changedFiles: [] }))).toBe(true);
  });

  it("is not one that changed a record, a list or a statistics file", () => {
    for (const file of ["incidents/2026.json", "seen.json", "rejected.json", "pending.json", "review-queue.json"]) expect(quietSweep(quiet({ changedFiles: ["runs.json", "collector-state.json", file] }))).toBe(false);
    expect(quietSweep(quiet({ sideChanged: true }))).toBe(false);
  });

  it("is not one with an error, a waiting candidate, a model call or an advisory lookup", () => {
    expect(quietSweep(quiet({ record: run({ errors: ["gtig: This operation was aborted"] }) }))).toBe(false);
    // every provider out of quota: nothing classified, nothing changed, and the stall alarm needs this run on record
    expect(quietSweep(quiet({ record: run({ pending: 3 }) }))).toBe(false);
    expect(quietSweep(quiet({ record: run({ calls: 1 }) }))).toBe(false);
    expect(quietSweep(quiet({ lookedUp: 2 }))).toBe(false);
  });

  it("is not one that read a source with a schedule of its own, whose clock must be kept", () => {
    const withNvd = [...run().sources, { id: "nvd", ok: true, items: 9, duration_ms: 270_000 }];
    expect(quietSweep(quiet({ record: run({ sources: withNvd }) }))).toBe(false);
    expect(quietSweep(quiet({ record: run({ sources: [{ id: "thn", ok: false, items: 0, duration_ms: 20 }] }) }))).toBe(false);
    expect(quietSweep(quiet({ record: run({ sources: [{ id: "unknown", ok: true, items: 0, duration_ms: 20 }] }) }))).toBe(false);
  });

  it("is committed once an hour, and always when it found something", () => {
    expect(commitsSweep(true, 14)).toBe(false);
    expect(commitsSweep(true, HEARTBEAT_MINUTES - 1)).toBe(false);
    expect(commitsSweep(true, HEARTBEAT_MINUTES)).toBe(true);
    expect(commitsSweep(true, null)).toBe(true);
    expect(commitsSweep(false, 2)).toBe(true);
  });
});

describe("the push budget", () => {
  it("skips a sweep only when main has taken its day's commits and the last data commit is recent", () => {
    expect(overPushBudget(PUSH_BUDGET - 1, 5)).toBe(false);
    expect(overPushBudget(PUSH_BUDGET, 14)).toBe(true);
    expect(overPushBudget(PUSH_BUDGET + 20, BUDGET_GAP_MINUTES - 1)).toBe(true);
    expect(overPushBudget(PUSH_BUDGET + 20, BUDGET_GAP_MINUTES)).toBe(false);
    expect(overPushBudget(null, 5)).toBe(false);
    expect(overPushBudget(PUSH_BUDGET, null)).toBe(false);
  });

  it("leaves room under Vercel's hundred deployments a day", () => {
    expect(PUSH_BUDGET).toBeLessThanOrEqual(80);
    // under the fuse at most two sweeps an hour reach main
    expect(BUDGET_GAP_MINUTES).toBeGreaterThan(15);
    expect(BUDGET_GAP_MINUTES).toBeLessThan(30);
  });
});

describe("what four sweeps an hour ask of the sources", () => {
  const sources = loadConfig().sources;
  const byId = new Map(sources.map((s) => [s.id, s]));

  it("reads CISA's catalog on every sweep and NVD's keyword searches every two hours", () => {
    expect(byId.get("kev")?.schedule).toBe("every_run");
    expect(byId.get("nvd")?.schedule).toBe("two_hourly");
    expect(byId.get("gdelt")?.schedule).toBe("own_workflow");
  });

  it("finds a two-hourly source due after two hours, not after one", () => {
    const now = new Date("2026-11-20T12:00:00Z");
    expect(DUE_HOURS.two_hourly).toBeLessThan(2);
    expect(isDue({ schedule: "two_hourly" }, "2026-11-20T11:00:00Z", now)).toBe(false);
    expect(isDue({ schedule: "two_hourly" }, "2026-11-20T10:05:00Z", now)).toBe(true);
    expect(isDue({ schedule: "two_hourly" }, undefined, now)).toBe(true);
  });
});

describe("the KEV statistics on every sweep", () => {
  const settings = loadConfig().settings;
  const previous = { fetched_at: "2026-11-20T05:00:00.000Z", source: { name: "CISA", url: "https://www.cisa.gov/", license: "CC0 1.0" }, catalog_version: "2026.11.18", feed_modified: "Wed, 18 Nov 2026 19:17:40 GMT", entries: [{ cve: "CVE-2026-0001", added: "2026-11-18", due: "2026-12-09", vendor: "V", product: "P", name: "N", ransomware: false, published: "2026-11-01", cvss: 9.1 }] };
  const catalog = { catalogVersion: "2026.11.20", vulnerabilities: [{ cveID: "CVE-2026-0001", vendorProject: "V", product: "P", vulnerabilityName: "N", dateAdded: "2026-11-18", shortDescription: "", dueDate: "2026-12-09" }] };

  function ctx(answer: { notModified: boolean; body?: string; lastModified?: string }, seen: Record<string, unknown>[]): StatsContext {
    return {
      settings,
      now: new Date("2026-11-20T05:15:00Z"),
      recordCveIds: [],
      extraCveIds: [],
      produced: {},
      log: () => undefined,
      http: {
        json: async () => {
          throw new Error("the conditional path must not fall back to a plain download");
        },
        sleep: async () => undefined,
        fetch: async (url, opts) => {
          seen.push({ url, lastModified: opts?.lastModified });
          return { url, status: answer.notModified ? 304 : 200, ok: true, body: answer.body ?? "", headers: new Headers(answer.lastModified ? { "last-modified": answer.lastModified } : {}), truncated: false, notModified: answer.notModified, contentType: "application/json" };
        },
      },
    };
  }

  it("is due on every run", () => {
    expect(kevModule.maxAgeHours).toBe(0);
  });

  it("asks with the date of the catalog it last read, and writes nothing when CISA answers 304", async () => {
    const seen: Record<string, unknown>[] = [];
    expect(await kevModule.fetch(ctx({ notModified: true }, seen), previous)).toBeNull();
    expect(seen).toEqual([{ url: KEV_URL, lastModified: previous.feed_modified }]);
  });

  it("keeps the new catalog's date for the next sweep", async () => {
    const seen: Record<string, unknown>[] = [];
    const next = await kevModule.fetch(ctx({ notModified: false, body: JSON.stringify(catalog), lastModified: "Fri, 20 Nov 2026 05:10:00 GMT" }, seen), previous);
    expect(next).toMatchObject({ catalog_version: "2026.11.20", feed_modified: "Fri, 20 Nov 2026 05:10:00 GMT" });
    // the entry's NVD date and score carry over: no new listing, so no join
    expect(next?.entries[0]).toMatchObject({ cve: "CVE-2026-0001", published: "2026-11-01", cvss: 9.1 });
  });
});

describe("publishing the live files", () => {
  let repo: string;
  const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
  const files = { "home.json": '{"v":1}\n', "board.json": '{"v":1,"board":true}\n', "cves-week.json": '{"cves":[]}\n' };

  beforeAll(() => {
    repo = mkdtempSync(path.join(tmpdir(), "radar-live-test-"));
    git("init", "-q", "-b", "main");
    git("config", "user.name", "Test");
    git("config", "user.email", "test@example.test");
    writeFileSync(path.join(repo, "kept.txt"), "work in progress\n");
    git("add", "kept.txt");
    git("commit", "-q", "-m", "first");
    writeFileSync(path.join(repo, "kept.txt"), "work in progress, edited\n");
  });
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  it("makes one commit with no parent that holds the files and the switch that keeps Vercel off the branch", async () => {
    const res = await publishLive(files, "2026-11-20T05:36:00.000Z", { cwd: repo, push: false });
    expect(res).toMatchObject({ published: false, files: 3 });
    expect(res.sha).toMatch(/^[0-9a-f]{40}$/);
    expect(git("rev-list", "--count", res.sha!)).toBe("1");
    expect(git("log", "-1", "--format=%s", res.sha!)).toBe("live: sweep 2026-11-20T05:36:00.000Z");
    expect(git("ls-tree", "--name-only", res.sha!).split("\n").sort()).toEqual(["README.md", "board.json", "cves-week.json", "home.json", "vercel.json"]);
    expect(git("show", `${res.sha}:home.json`)).toBe('{"v":1}');
    expect(JSON.parse(git("show", `${res.sha}:vercel.json`))).toMatchObject({ git: { deploymentEnabled: false } });
    expect(JSON.parse(LIVE_BRANCH_FILES["vercel.json"]!).git.deploymentEnabled).toBe(false);
  });

  it("leaves the checkout, its index and its branch as they were", async () => {
    const before = { head: git("rev-parse", "HEAD"), branch: git("rev-parse", "--abbrev-ref", "HEAD"), status: git("status", "--porcelain") };
    await publishLive(files, "2026-11-20T05:51:00.000Z", { cwd: repo, push: false });
    expect({ head: git("rev-parse", "HEAD"), branch: git("rev-parse", "--abbrev-ref", "HEAD"), status: git("status", "--porcelain") }).toEqual(before);
    expect(readFileSync(path.join(repo, "kept.txt"), "utf8")).toBe("work in progress, edited\n");
    expect(existsSync(path.join(repo, "home.json"))).toBe(false);
  });

  it("pushes to the live branch only, replacing what was there", async () => {
    const remote = mkdtempSync(path.join(tmpdir(), "radar-live-remote-"));
    try {
      execFileSync("git", ["init", "-q", "--bare", "-b", "main", remote]);
      git("remote", "add", "bulletin", remote);
      git("push", "-q", "bulletin", "HEAD:refs/heads/main");
      const first = await publishLive(files, "2026-11-20T05:36:00.000Z", { cwd: repo, remote: "bulletin" });
      const second = await publishLive({ ...files, "home.json": '{"v":1,"n":2}\n' }, "2026-11-20T05:51:00.000Z", { cwd: repo, remote: "bulletin" });
      expect(first.published && second.published).toBe(true);
      const refs = execFileSync("git", ["for-each-ref", "--format=%(refname) %(objectname)"], { cwd: remote, encoding: "utf8" }).trim().split("\n").sort();
      expect(refs).toEqual([`refs/heads/live ${second.sha}`, `refs/heads/main ${git("rev-parse", "HEAD")}`]);
      expect(execFileSync("git", ["rev-list", "--count", "refs/heads/live"], { cwd: remote, encoding: "utf8" }).trim()).toBe("1");
    } finally {
      rmSync(remote, { recursive: true, force: true });
    }
  });

  it("refuses a file the Worker would not serve, and reports instead of throwing", async () => {
    expect(() => checkLiveFiles({ "runs.json": "[]" })).toThrow(/not a live file/);
    expect(() => checkLiveFiles({ "../home.json": "{}" })).toThrow();
    const res = await publishLive({ "secrets.json": "{}" }, "2026-11-20T05:36:00.000Z", { cwd: repo, push: false });
    expect(res.published).toBe(false);
    expect(res.error).toMatch(/not a live file/);
    const failed = await publishLive(files, "2026-11-20T05:36:00.000Z", { cwd: repo, remote: "no-such-remote" });
    expect(failed.published).toBe(false);
    expect(failed.error).toBeTruthy();
  });

  it("commits as the collector's identity on Actions", () => {
    expect(liveIdentity({ COLLECTOR_GIT_NAME: "Owner", COLLECTOR_GIT_EMAIL: "owner@example.test" })).toMatchObject({ GIT_AUTHOR_NAME: "Owner", GIT_COMMITTER_EMAIL: "owner@example.test" });
    expect(liveIdentity({ GITHUB_ACTIONS: "true" }).GIT_AUTHOR_NAME).toBe("github-actions[bot]");
    expect(liveIdentity({})).toEqual({});
  });
});
