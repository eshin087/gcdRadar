/**
 * GET /v1/live/<name>: the newest sweep's files, for the pages to redraw
 * from between site rebuilds (lib/live/shape.ts on the site's side). The
 * collector replaces them on the repository's `live` branch after every
 * sweep (collector/live.ts); this route hands them on as they are.
 *
 * Nothing is parsed: a file is up to a few hundred kilobytes and the Free
 * plan allows about ten milliseconds of CPU, so the bytes go from GitHub to
 * the visitor untouched (the page checks what it gets). Nothing is written
 * to KV either, whose thousand free writes a day the other two routes
 * already use: a copy is kept in the isolate's memory for a minute and in
 * the Cache API beside it.
 *
 * Where the bytes come from, in order:
 *  1. GitHub's REST contents API, when the Worker has its GitHub token
 *     (GITHUB_DISPATCH_TOKEN, which can read any public repository). It
 *     serves a new commit at once, and a request that answers 304 against
 *     the copy's ETag does not count against the token's rate limit.
 *  2. raw.githubusercontent.com, with no token: the same file up to five
 *     minutes later (its CDN caches for 300 s).
 *  3. The last copy this isolate saw, for up to six hours, when GitHub
 *     answers neither way.
 * With none of the three the route answers 503 and the page keeps what it
 * was built with. A late copy is safe to serve: every file carries the time
 * of its own sweep, and the page's label states that time, not the time of
 * the request.
 *
 * Nothing here names a Worker global (Env, ExecutionContext, caches): the
 * root test suite and typecheck run this file under Node, so the token,
 * fetch, the cache and the context come in as the small structural types
 * below.
 */

export const LIVE_REPO = "eshin087/gcdRadar";
export const LIVE_BRANCH = "live";
/** The names the route serves: the two views, the stack candidates, and the lists the home page's numbers open (lib/live/shape.ts LIVE_FILE_PATTERN). */
export const LIVE_NAME = /^(?:home|board|stack|cves-day|cves-week|kev-week|breaches-\d{4}-\d{2})\.json$/;
/** Seconds a copy is served without asking GitHub again; also the HTTP max-age. */
export const FRESH_S = 60;
/** Seconds the last good copy may stand in when GitHub cannot be reached. */
export const KEEP_S = 6 * 3600;
const UPSTREAM_TIMEOUT_MS = 8000;
const USER_AGENT = "gcdradar-internet/0.1 (+https://gcdradar.vercel.app)";

export type LiveVia = "api" | "raw";
/** How a response was produced: fetched just now, from a warm copy, or a stale copy served because GitHub failed. */
export type LiveSource = LiveVia | "memory" | "cache" | "stale";

interface Copy {
  body: ArrayBuffer;
  etag: string | null;
  via: LiveVia;
  /** Epoch milliseconds GitHub last confirmed or sent this copy. */
  at: number;
}

export type LiveFetch = (url: string, init: { headers: Record<string, string>; signal: AbortSignal }) => Promise<Response>;

/** The slice of the Cache API this route uses. */
export interface LiveCache {
  match(key: string): Promise<Response | undefined>;
  put(key: string, response: Response): Promise<void>;
}

/** The slice of ExecutionContext this route uses. */
export interface LiveContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface LiveOptions {
  /** The GitHub token, when the Worker has one. */
  token?: string;
  fetch?: LiveFetch;
  cache?: LiveCache;
  ctx?: LiveContext;
  now?: Date;
}

/** Shared for the isolate's lifetime: one copy per file name, and the fetch in flight for it. Never request-scoped data. */
const memory = new Map<string, Copy>();
const inflight = new Map<string, Promise<Copy | null>>();

/** Forgets the isolate's copies (tests). */
export function resetLiveMemory(): void {
  memory.clear();
  inflight.clear();
}

export function apiUrl(name: string): string {
  return `https://api.github.com/repos/${LIVE_REPO}/contents/${name}?ref=${LIVE_BRANCH}`;
}

export function rawUrl(name: string): string {
  return `https://raw.githubusercontent.com/${LIVE_REPO}/${LIVE_BRANCH}/${name}`;
}

const CORS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Accept, Content-Type",
  "Access-Control-Max-Age": "86400",
  "Access-Control-Expose-Headers": "X-Live-Source, Age",
};

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff", ...CORS, ...extra },
  });
}

/** A JSON object, by its first byte: all this route checks of a file it never parses. */
export function looksLikeJsonObject(body: ArrayBuffer): boolean {
  return body.byteLength > 1 && new Uint8Array(body, 0, 1)[0] === 0x7b;
}

/** One upstream, asked with the copy's ETag when the copy came from the same place: the new copy, the old one confirmed (304), or null. */
async function ask(doFetch: LiveFetch, url: string, headers: Record<string, string>, via: LiveVia, had: Copy | undefined, nowMs: number): Promise<Copy | null> {
  const all: Record<string, string> = { "User-Agent": USER_AGENT, ...headers };
  if (had && had.via === via && had.etag) all["If-None-Match"] = had.etag;
  const res = await doFetch(url, { headers: all, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
  if (res.status === 304 && had) return { ...had, at: nowMs };
  if (!res.ok) {
    console.warn(JSON.stringify({ event: "live_upstream", via, status: res.status }));
    return null;
  }
  const body = await res.arrayBuffer();
  if (!looksLikeJsonObject(body)) {
    console.warn(JSON.stringify({ event: "live_not_json", via, bytes: body.byteLength }));
    return null;
  }
  return { body, etag: res.headers.get("etag"), via, at: nowMs };
}

/** The newest copy GitHub will give: the API with the token, then the raw host; null when both fail. */
export async function fetchLive(name: string, token: string | undefined, doFetch: LiveFetch, nowMs: number): Promise<Copy | null> {
  const had = memory.get(name);
  if (token) {
    try {
      const got = await ask(doFetch, apiUrl(name), { Authorization: `Bearer ${token}`, Accept: "application/vnd.github.raw+json", "X-GitHub-Api-Version": "2022-11-28" }, "api", had, nowMs);
      if (got) return got;
    } catch (e) {
      console.warn(JSON.stringify({ event: "live_upstream_failed", via: "api", error: String(e) }));
    }
  }
  try {
    return await ask(doFetch, rawUrl(name), { Accept: "application/json" }, "raw", had, nowMs);
  } catch (e) {
    console.warn(JSON.stringify({ event: "live_upstream_failed", via: "raw", error: String(e) }));
    return null;
  }
}

function respond(copy: Copy, source: LiveSource, nowMs: number): Response {
  const age = Math.max(0, Math.floor((nowMs - copy.at) / 1000));
  return new Response(copy.body, {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      ...CORS,
      // a stale copy is offered for less time, so the page asks again soon
      "Cache-Control": `public, max-age=${source === "stale" ? 30 : FRESH_S}`,
      Age: String(age),
      "X-Live-Source": source,
      "X-Live-Via": copy.via,
    },
  });
}

/** The copy as the Cache API keeps it: expiring with its freshness, with where and when it came from in headers. */
function toCache(copy: Copy, nowMs: number): Response {
  const left = Math.max(1, FRESH_S - Math.floor((nowMs - copy.at) / 1000));
  return new Response(copy.body.slice(0), {
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": `public, max-age=${left}`, "X-Live-At": String(copy.at), "X-Live-Via": copy.via, ...(copy.etag ? { ETag: copy.etag } : {}) },
  });
}

async function fromCache(cache: LiveCache | undefined, key: string, nowMs: number): Promise<Copy | null> {
  if (!cache) return null;
  try {
    const hit = await cache.match(key);
    if (!hit) return null;
    const at = Number(hit.headers.get("X-Live-At"));
    if (!Number.isFinite(at) || nowMs - at >= FRESH_S * 1000) return null;
    const body = await hit.arrayBuffer();
    if (!looksLikeJsonObject(body)) return null;
    return { body, etag: hit.headers.get("ETag"), via: hit.headers.get("X-Live-Via") === "raw" ? "raw" : "api", at };
  } catch (e) {
    console.warn(JSON.stringify({ event: "live_cache_read_failed", error: String(e) }));
    return null;
  }
}

const defaultFetch: LiveFetch = (url, init) => fetch(url, init);

/** GET and HEAD /v1/live/<name>; index.ts answers OPTIONS and other methods before routing here. */
export async function live(request: Request, name: string, opts: LiveOptions = {}): Promise<Response> {
  const nowMs = (opts.now ?? new Date()).getTime();
  const head = (res: Response) => (request.method === "HEAD" ? new Response(null, { status: res.status, headers: res.headers }) : res);
  if (!LIVE_NAME.test(name)) return head(json({ error: "not found" }, 404, { "Cache-Control": "public, max-age=60" }));
  try {
    const warm = memory.get(name);
    if (warm && nowMs - warm.at < FRESH_S * 1000) return head(respond(warm, "memory", nowMs));

    // the cache is keyed by the path alone: the page's "?s=<sweep>" only keeps the browser from reusing an older list
    const key = `${new URL(request.url).origin}/v1/live/${name}`;
    const cached = await fromCache(opts.cache, key, nowMs);
    if (cached) {
      memory.set(name, cached);
      return head(respond(cached, "cache", nowMs));
    }

    let pending = inflight.get(name);
    if (!pending) {
      pending = fetchLive(name, opts.token, opts.fetch ?? defaultFetch, nowMs).finally(() => inflight.delete(name));
      inflight.set(name, pending);
    }
    const got = await pending;
    if (got) {
      memory.set(name, got);
      if (opts.cache && opts.ctx) {
        const cache = opts.cache;
        opts.ctx.waitUntil(cache.put(key, toCache(got, nowMs)).catch((e) => console.warn(JSON.stringify({ event: "live_cache_write_failed", error: String(e) }))));
      }
      return head(respond(got, got.via, nowMs));
    }
    if (warm && nowMs - warm.at < KEEP_S * 1000) return head(respond(warm, "stale", nowMs));
    return head(json({ error: "the live files are unavailable" }, 503, { "Cache-Control": "no-store", "Retry-After": "60" }));
  } catch (e) {
    console.error(JSON.stringify({ event: "unhandled", route: "/v1/live", error: String(e) }));
    return head(json({ error: "internal error" }, 500, { "Cache-Control": "no-store" }));
  }
}
