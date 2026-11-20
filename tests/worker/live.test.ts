import { beforeEach, describe, expect, it } from "vitest";
import { apiUrl, FRESH_S, KEEP_S, live, LIVE_BRANCH, LIVE_REPO, looksLikeJsonObject, rawUrl, resetLiveMemory, type LiveCache, type LiveFetch } from "../../worker/src/live";
import { REPO } from "../../worker/src/dispatch";
import { LIVE_BRANCH as SITE_LIVE_BRANCH } from "../../lib/live/shape";

/** The Worker's /v1/live/<name>: where the bytes come from, how long a copy is kept, and what a visitor gets when GitHub fails. */

const T0 = Date.parse("2026-11-20T05:40:00Z");
const at = (seconds: number) => new Date(T0 + seconds * 1000);
const BODY = '{"v":1,"sweep":"2026-11-20T05:36:00.000Z","view":{}}\n';
const NEWER = '{"v":1,"sweep":"2026-11-20T05:51:00.000Z","view":{}}\n';

interface Call {
  url: string;
  headers: Record<string, string>;
}

/** A fake GitHub: `answer(url, headers)` returns a Response, or throws for a network failure. */
function github(answer: (url: string, headers: Record<string, string>) => Response): { fetch: LiveFetch; calls: Call[] } {
  const calls: Call[] = [];
  return {
    calls,
    fetch: async (url, init) => {
      calls.push({ url, headers: init.headers });
      return answer(url, init.headers);
    },
  };
}

const ok = (body: string, etag = '"e1"') => new Response(body, { status: 200, headers: { ETag: etag } });
const get = (name: string, opts: Parameters<typeof live>[2]) => live(new Request(`https://worker.example/v1/live/${name}?s=whatever`), name, opts);

beforeEach(() => resetLiveMemory());

describe("where the bytes come from", () => {
  it("reads the collector's repository and the branch the collector publishes to", () => {
    expect(LIVE_REPO).toBe(REPO);
    expect(LIVE_BRANCH).toBe(SITE_LIVE_BRANCH);
    expect(apiUrl("home.json")).toBe("https://api.github.com/repos/eshin087/gcdRadar/contents/home.json?ref=live");
    expect(rawUrl("home.json")).toBe("https://raw.githubusercontent.com/eshin087/gcdRadar/live/home.json");
  });

  it("asks GitHub's API with the token and hands the bytes on untouched", async () => {
    const gh = github(() => ok(BODY));
    const res = await get("home.json", { token: "t0ken", fetch: gh.fetch, now: at(0) });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(BODY);
    expect(gh.calls).toHaveLength(1);
    expect(gh.calls[0]!.url).toBe(apiUrl("home.json"));
    expect(gh.calls[0]!.headers).toMatchObject({ Authorization: "Bearer t0ken", Accept: "application/vnd.github.raw+json" });
    expect(res.headers.get("X-Live-Source")).toBe("api");
    expect(res.headers.get("Cache-Control")).toBe(`public, max-age=${FRESH_S}`);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Content-Type")).toContain("application/json");
  });

  it("never sends the token anywhere but GitHub's API", async () => {
    const gh = github((url) => (url.startsWith("https://api.github.com/") ? new Response("no", { status: 403 }) : ok(BODY)));
    const res = await get("home.json", { token: "t0ken", fetch: gh.fetch, now: at(0) });
    expect(res.headers.get("X-Live-Source")).toBe("raw");
    expect(gh.calls.map((c) => c.url)).toEqual([apiUrl("home.json"), rawUrl("home.json")]);
    expect(gh.calls[1]!.headers.Authorization).toBeUndefined();
  });

  it("uses the raw host when the Worker has no token", async () => {
    const gh = github(() => ok(BODY));
    const res = await get("board.json", { fetch: gh.fetch, now: at(0) });
    expect(gh.calls.map((c) => c.url)).toEqual([rawUrl("board.json")]);
    expect(await res.text()).toBe(BODY);
  });

  it("serves only the names of the live files", async () => {
    const gh = github(() => ok(BODY));
    for (const name of ["runs.json", "vercel.json", "../../data/seen.json", "home.json/extra", "", "home"]) {
      const res = await get(name, { token: "t", fetch: gh.fetch, now: at(0) });
      expect(res.status).toBe(404);
    }
    expect(gh.calls).toHaveLength(0);
    expect((await get("breaches-2026-11.json", { fetch: gh.fetch, now: at(0) })).status).toBe(200);
  });
});

describe("how long a copy is kept", () => {
  it("answers from memory for a minute without asking GitHub", async () => {
    const gh = github(() => ok(BODY));
    await get("home.json", { token: "t", fetch: gh.fetch, now: at(0) });
    const again = await get("home.json", { token: "t", fetch: gh.fetch, now: at(FRESH_S - 1) });
    expect(gh.calls).toHaveLength(1);
    expect(again.headers.get("X-Live-Source")).toBe("memory");
    expect(again.headers.get("Age")).toBe(String(FRESH_S - 1));
    expect(await again.text()).toBe(BODY);
  });

  it("then asks again with the copy's ETag, and a 304 keeps the copy", async () => {
    let n = 0;
    const gh = github((_url, headers) => (++n === 1 ? ok(BODY, '"e1"') : headers["If-None-Match"] === '"e1"' ? new Response(null, { status: 304 }) : ok("{}")));
    await get("home.json", { token: "t", fetch: gh.fetch, now: at(0) });
    const res = await get("home.json", { token: "t", fetch: gh.fetch, now: at(FRESH_S + 5) });
    expect(gh.calls[1]!.headers["If-None-Match"]).toBe('"e1"');
    expect(await res.text()).toBe(BODY);
    expect(res.headers.get("Age")).toBe("0");
    // confirmed a moment ago: memory answers the next minute
    await get("home.json", { token: "t", fetch: gh.fetch, now: at(FRESH_S + 30) });
    expect(gh.calls).toHaveLength(2);
  });

  it("serves a new sweep's file as soon as GitHub has it", async () => {
    let body = BODY;
    const gh = github(() => ok(body, `"${body.length}-${body.slice(20, 40)}"`));
    await get("home.json", { token: "t", fetch: gh.fetch, now: at(0) });
    body = NEWER;
    const res = await get("home.json", { token: "t", fetch: gh.fetch, now: at(FRESH_S + 1) });
    expect(await res.text()).toBe(NEWER);
  });

  it("keeps each file's copy apart", async () => {
    const gh = github((url) => ok(url.includes("board") ? '{"board":1}' : BODY));
    await get("home.json", { fetch: gh.fetch, now: at(0) });
    const board = await get("board.json", { fetch: gh.fetch, now: at(1) });
    expect(await board.text()).toBe('{"board":1}');
    expect(gh.calls).toHaveLength(2);
  });

  it("shares a fresh copy through the cache, and never a stale one", async () => {
    const store = new Map<string, Response>();
    const cache: LiveCache = { match: async (key) => store.get(key)?.clone(), put: async (key, res) => void store.set(key, res) };
    const waits: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => void waits.push(p) };
    const gh = github(() => ok(BODY));
    await get("home.json", { token: "t", fetch: gh.fetch, cache, ctx, now: at(0) });
    await Promise.all(waits);
    expect([...store.keys()]).toEqual(["https://worker.example/v1/live/home.json"]);
    // another isolate: no memory, the cache has it
    resetLiveMemory();
    const shared = await get("home.json", { token: "t", fetch: gh.fetch, cache, ctx, now: at(20) });
    expect(shared.headers.get("X-Live-Source")).toBe("cache");
    expect(await shared.text()).toBe(BODY);
    expect(gh.calls).toHaveLength(1);
    // a minute on, the cached copy is too old to pass for fresh
    resetLiveMemory();
    await get("home.json", { token: "t", fetch: gh.fetch, cache, ctx, now: at(FRESH_S + 1) });
    expect(gh.calls).toHaveLength(2);
  });
});

describe("when GitHub fails", () => {
  it("serves the last copy, marked stale and offered for less time", async () => {
    let up = true;
    const gh = github(() => {
      if (!up) throw new Error("connect timeout");
      return ok(BODY);
    });
    await get("home.json", { token: "t", fetch: gh.fetch, now: at(0) });
    up = false;
    const res = await get("home.json", { token: "t", fetch: gh.fetch, now: at(600) });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(BODY);
    expect(res.headers.get("X-Live-Source")).toBe("stale");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=30");
    expect(res.headers.get("Age")).toBe("600");
  });

  it("answers 503 with nothing to serve, or once the copy is too old", async () => {
    const down = github(() => new Response("upstream", { status: 502 }));
    const cold = await get("home.json", { token: "t", fetch: down.fetch, now: at(0) });
    expect(cold.status).toBe(503);
    expect(cold.headers.get("Cache-Control")).toBe("no-store");
    expect(cold.headers.get("Access-Control-Allow-Origin")).toBe("*");

    let up = true;
    const gh = github(() => (up ? ok(BODY) : new Response("", { status: 500 })));
    await get("board.json", { fetch: gh.fetch, now: at(0) });
    up = false;
    expect((await get("board.json", { fetch: gh.fetch, now: at(KEEP_S - 1) })).status).toBe(200);
    expect((await get("board.json", { fetch: gh.fetch, now: at(KEEP_S + 1) })).status).toBe(503);
  });

  it("does not pass on a body that is not a JSON object", async () => {
    const gh = github((url) => (url.startsWith("https://api.") ? ok("<html>rate limited</html>") : ok("404: Not Found")));
    expect((await get("home.json", { token: "t", fetch: gh.fetch, now: at(0) })).status).toBe(503);
    expect(looksLikeJsonObject(new TextEncoder().encode('{"a":1}').buffer as ArrayBuffer)).toBe(true);
    expect(looksLikeJsonObject(new TextEncoder().encode("[1]").buffer as ArrayBuffer)).toBe(false);
    expect(looksLikeJsonObject(new ArrayBuffer(0))).toBe(false);
  });

  it("answers HEAD with the headers and no body", async () => {
    const gh = github(() => ok(BODY));
    const res = await live(new Request("https://worker.example/v1/live/home.json", { method: "HEAD" }), "home.json", { fetch: gh.fetch, now: at(0) });
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Live-Source")).toBe("raw");
    expect(await res.text()).toBe("");
  });
});
