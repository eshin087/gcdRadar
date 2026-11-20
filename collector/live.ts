import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { loadBriefings, loadIncidents, loadStats } from "../lib/data";
import { buildLiveFiles } from "../lib/live/build";
import { LIVE_BRANCH, LIVE_FILE_PATTERN } from "../lib/live/shape";
import { errorMessage, log } from "./lib/log";

/**
 * The live layer's publisher. After a sweep, the files the home page and
 * the live board redraw from (lib/live/build.ts) are committed to the
 * branch `live` and pushed: one commit with no parent, replaced on every
 * sweep, so the branch is a bulletin board with no history and the
 * repository does not grow. The Cloudflare Worker reads the files from
 * there (worker/src/live.ts) and the pages swap them in.
 *
 * Why a branch of its own: every push to `main` makes a Vercel deployment,
 * and one that `ignoreCommand` skips still counts against the Hobby plan's
 * hundred a day. The branch carries its own vercel.json with deployments
 * switched off, so a sweep can publish every fifteen minutes without
 * touching that budget (checked on 2026-11-20 with a throwaway branch: no
 * deployment was created for it).
 *
 * The commit is made with git's plumbing through a scratch index, so the
 * working tree, the real index and the checked-out branch are never
 * touched. The push is forced and may only ever name the live branch.
 */

const exec = promisify(execFile);

/** Files that ride along on the branch: the switch that keeps Vercel off it, and a note for whoever opens it. */
export const LIVE_BRANCH_FILES: Record<string, string> = {
  "vercel.json": `${JSON.stringify({ $schema: "https://openapi.vercel.sh/vercel.json", git: { deploymentEnabled: false } }, null, 2)}\n`,
  "README.md": [
    "# gcdRadar: the newest sweep",
    "",
    "This branch holds one commit: the files the home page and the live board redraw from between site rebuilds.",
    "The collector replaces it after every sweep (`collector/live.ts` on `main`), so it has no history and is never merged.",
    "The Cloudflare Worker serves the files at `/v1/live/<name>`. `vercel.json` keeps Vercel from deploying this branch.",
    "",
  ].join("\n"),
};

export interface LivePublishResult {
  published: boolean;
  /** The commit pushed to the live branch. */
  sha?: string;
  files: number;
  bytes: number;
  /** Why nothing was published. */
  error?: string;
}

/** The sweep's files from the data directory as it stands: call after the run has saved its state and the stats stage has run. */
export async function liveFilesFromDisk(sweep: string): Promise<Record<string, string>> {
  const [{ incidents }, stats, briefings] = await Promise.all([loadIncidents(), loadStats(), loadBriefings()]);
  return buildLiveFiles({ incidents, stats, briefings, sweep });
}

/** The git identity for the commit, as environment variables (collector/git.ts uses the same names for data commits). */
export function liveIdentity(env: Record<string, string | undefined> = process.env): Record<string, string> {
  const name = env.COLLECTOR_GIT_NAME;
  const email = env.COLLECTOR_GIT_EMAIL;
  const who = name && email ? { name, email } : env.GITHUB_ACTIONS ? { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" } : null;
  return who ? { GIT_AUTHOR_NAME: who.name, GIT_AUTHOR_EMAIL: who.email, GIT_COMMITTER_NAME: who.name, GIT_COMMITTER_EMAIL: who.email } : {};
}

/** Refuses any name the Worker would not serve, so nothing else can ride onto the branch. */
export function checkLiveFiles(files: Record<string, string>): void {
  for (const name of Object.keys(files)) if (!LIVE_FILE_PATTERN.test(name)) throw new Error(`live: "${name}" is not a live file`);
}

/**
 * Commits `files` (and the branch's own two) as a parentless commit and
 * force-pushes it to the live branch. `cwd` is the repository; `push:
 * false` stops after the commit (tests). Never throws: a sweep whose
 * bulletin could not be posted is still a good sweep, the page keeps the
 * last one and its label keeps that one's time.
 */
export async function publishLive(files: Record<string, string>, sweep: string, opts: { cwd?: string; push?: boolean; remote?: string } = {}): Promise<LivePublishResult> {
  const cwd = opts.cwd ?? process.cwd();
  const all = { ...files, ...LIVE_BRANCH_FILES };
  const bytes = Object.values(files).reduce((n, s) => n + Buffer.byteLength(s), 0);
  const count = Object.keys(files).length;
  let scratch: string | null = null;
  try {
    checkLiveFiles(files);
    if (LIVE_BRANCH !== "live") throw new Error("live: the branch name changed; refusing to force-push anywhere else");
    scratch = await fs.mkdtemp(path.join(tmpdir(), "radar-live-"));
    const env = { ...process.env, ...liveIdentity(), GIT_INDEX_FILE: path.join(scratch, "index") };
    const git = async (args: string[]) => (await exec("git", args, { cwd, env, maxBuffer: 16 * 1024 * 1024 })).stdout.trim();
    for (const [name, content] of Object.entries(all).sort(([a], [b]) => a.localeCompare(b))) {
      const file = path.join(scratch, name);
      await fs.writeFile(file, content);
      // --no-filters: the bytes as written, whatever the checkout's line-ending settings
      const blob = await git(["hash-object", "-w", "--no-filters", "--", file]);
      await git(["update-index", "--add", "--cacheinfo", `100644,${blob},${name}`]);
    }
    const tree = await git(["write-tree"]);
    const sha = await git(["commit-tree", tree, "-m", `live: sweep ${sweep}`]);
    if (opts.push !== false) await git(["push", "--force", "--quiet", opts.remote ?? "origin", `${sha}:refs/heads/${LIVE_BRANCH}`]);
    log.info(`live: ${opts.push === false ? "built" : "published"} ${count} files (${Math.round(bytes / 1024)} KB)`, { sweep, sha: sha.slice(0, 8) });
    return { published: opts.push !== false, sha, files: count, bytes };
  } catch (err) {
    const error = errorMessage(err).slice(0, 400);
    log.warn("live: the sweep's files were not published; the page keeps the last ones", { error });
    return { published: false, files: count, bytes, error };
  } finally {
    if (scratch) await fs.rm(scratch, { recursive: true, force: true }).catch(() => undefined);
  }
}
