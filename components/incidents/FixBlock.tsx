import type { ReactNode } from "react";
import type { FixHref, FixPassage, FixVersionRow, FixView } from "@/lib/fixes";
import { bestFixLink } from "@/lib/fixes";
import { dateLabel } from "@/lib/format";

/**
 * "How do I fix this", at a glance: PATCH, WORKAROUND and DEADLINE, each on
 * its own labelled row, then one row of reference links and the numbered
 * sources (lib/fixes.ts builds the view). It is the one framed element on a
 * record's page and the body of the quick-look drawer, so it has no hooks
 * and no data imports: the page renders it on the server, the drawer in the
 * browser.
 *
 * Whose words are whose: a publisher's text sits in a quoted block with its
 * name under it and a numbered source; gcdRadar's own model-written sentence
 * is labelled as ours. Nothing here is invented: where no source lists a
 * workaround the row says so.
 *
 * Every external link opens in a new tab with rel="noopener noreferrer".
 * The check script reads `data-fixblock`, `data-fix-row`, `data-fix-link`
 * and `data-fix-ref` (scripts/check-incident.mjs).
 */

const EXT = { target: "_blank", rel: "noopener noreferrer" } as const;
/** A passage longer than this folds to its opening lines until asked for. */
const FOLD_CHARS = 340;
const VERSIONS_SHOWN = 6;
const LINKS_SHOWN = 4;

function Cite({ n, view }: { n: number; view: FixView }) {
  const c = view.citations.find((x) => x.n === n);
  if (!c) return null;
  return (
    <a href={c.url} {...EXT} data-fix-cite={n} title={`Source ${n}: ${c.publisher}, ${c.title}`} aria-label={`Source ${n}: ${c.publisher}, ${c.title}`} className="num ml-1 whitespace-nowrap text-[12px] text-accent hover:underline">
      [{n}]
    </a>
  );
}

function Row({ name, children }: { name: "patch" | "workaround" | "deadline"; children: ReactNode }) {
  return (
    <div data-fix-row={name} className="grid gap-x-5 gap-y-2 border-t border-line-soft px-4 py-4 sm:grid-cols-[7.5rem_minmax(0,1fr)] sm:px-5">
      <h3 className="font-mono text-[12.5px] font-medium uppercase tracking-[0.12em] text-accent sm:pt-0.5">{name}</h3>
      <div className="min-w-0 space-y-3 text-[14.5px] leading-relaxed text-soft">{children}</div>
    </div>
  );
}

function OutLink({ l, view }: { l: FixHref; view: FixView }) {
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-1.5">
      <a href={l.url} {...EXT} data-fix-link={l.kind} className="link text-ink">
        {l.label} ↗
      </a>
      <span className="num text-[12.5px] text-dim">{l.host}</span>
      <Cite n={l.cite} view={view} />
    </span>
  );
}

function Links({ links, view }: { links: FixHref[]; view: FixView }) {
  if (links.length === 0) return null;
  const shown = links.slice(0, LINKS_SHOWN);
  const rest = links.slice(LINKS_SHOWN);
  return (
    <div className="space-y-1.5">
      <ul className="flex flex-col gap-1.5">
        {shown.map((l) => (
          <li key={l.url}>
            <OutLink l={l} view={view} />
          </li>
        ))}
      </ul>
      {rest.length > 0 && (
        <details>
          <summary className="cursor-pointer select-none font-mono text-[12.5px] text-dim hover:text-ink">
            {rest.length} more {rest.length === 1 ? "link" : "links"}
          </summary>
          <ul className="mt-1.5 flex flex-col gap-1.5">
            {rest.map((l) => (
              <li key={l.url}>
                <OutLink l={l} view={view} />
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

/** A publisher's own words: quoted, attributed, cited. A long one shows its opening and unfolds in place. */
function Passage({ p, view, whose }: { p: FixPassage; view: FixView; whose: string }) {
  const long = p.text.length > FOLD_CHARS;
  const cutAt = long ? Math.max(p.text.lastIndexOf("\n", FOLD_CHARS), p.text.lastIndexOf(" ", FOLD_CHARS - 60)) : -1;
  const opening = long ? p.text.slice(0, cutAt > 120 ? cutAt : FOLD_CHARS).trimEnd() : p.text;
  const body = "whitespace-pre-line break-words text-[14.5px] leading-relaxed text-ink";
  return (
    <figure data-fix-text={p.kind} className="border-l-2 border-line pl-3.5">
      {long ? (
        <details className="group">
          <summary className="cursor-pointer list-none [&::-webkit-details-marker]:hidden">
            <span className={`${body} group-open:hidden`}>{opening}… </span>
            <span className="font-mono text-[12.5px] text-accent group-open:hidden">show all</span>
            <span className="hidden font-mono text-[12.5px] text-dim group-open:inline">show less</span>
          </summary>
          <blockquote className={`${body} mt-1`}>{p.text}</blockquote>
        </details>
      ) : (
        <blockquote className={body}>{p.text}</blockquote>
      )}
      <figcaption className="mt-1.5 text-[12.5px] text-dim">
        {whose}
        <Cite n={p.cite} view={view} />
        {p.cut && <span> · cut here, the source has the rest</span>}
      </figcaption>
    </figure>
  );
}

function whoseWords(p: FixPassage, what: string): string {
  if (p.kind === "vendor") return `${p.by}'s ${what}, from the CVE record`;
  if (p.kind === "cna") return `${what[0]!.toUpperCase()}${what.slice(1)} in the CVE record, written by ${p.by} as the CNA`;
  if (p.kind === "cisa") return `CISA's ${what}`;
  return `gcdRadar's ${what}`;
}

/** Fixed versions, grouped under the product they belong to. */
function Versions({ rows, more, view }: { rows: FixVersionRow[]; more: number; view: FixView }) {
  if (rows.length === 0) return null;
  const groups: { label: string; rows: FixVersionRow[] }[] = [];
  for (const r of rows) {
    const g = groups.find((x) => x.label === r.label);
    if (g) g.rows.push(r);
    else groups.push({ label: r.label, rows: [r] });
  }
  let budget = VERSIONS_SHOWN;
  const head: typeof groups = [];
  const tail: typeof groups = [];
  for (const g of groups) {
    const take = g.rows.slice(0, Math.max(0, budget));
    const left = g.rows.slice(take.length);
    budget -= take.length;
    if (take.length) head.push({ label: g.label, rows: take });
    if (left.length) tail.push({ label: g.label, rows: left });
  }
  const hidden = tail.reduce((n, g) => n + g.rows.length, 0);
  const list = (gs: typeof groups) =>
    gs.map((g) => (
      <div key={`${g.label}-${g.rows[0]!.version}`}>
        {g.label && <div className="text-[14.5px] font-medium text-ink">{g.label}</div>}
        <ul>
          {g.rows.map((r) => (
            <li key={`${r.version}-${r.from}`} data-fix-version="" className="flex flex-wrap items-baseline gap-x-2">
              <span className="text-[12.5px] text-dim">fixed in</span>
              <span className="num break-all text-[14.5px] text-patched">{r.version}</span>
              {r.from && <span className="num text-[12.5px] text-dim">for {r.from}</span>}
              <Cite n={r.cite} view={view} />
            </li>
          ))}
        </ul>
      </div>
    ));
  return (
    <div className="space-y-2">
      {list(head)}
      {hidden > 0 && (
        <details>
          <summary className="cursor-pointer select-none font-mono text-[12.5px] text-dim hover:text-ink">
            {hidden} more fixed {hidden === 1 ? "version" : "versions"}
          </summary>
          <div className="mt-2 space-y-2">{list(tail)}</div>
        </details>
      )}
      {more > 0 && <p className="text-[12.5px] text-dim">The CVE record lists {more} more.</p>}
    </div>
  );
}

function daysBetween(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86_400_000);
}

export interface FixBlockProps {
  view: FixView;
  /** The UTC day the block is read on: the build day on a page, today in the drawer. Decides whether a deadline has passed. */
  today: string;
  /** Extra classes on the frame. */
  className?: string;
}

export function FixBlock({ view, today, className = "" }: FixBlockProps) {
  const { patch, workaround, deadline } = view;
  const advisory = bestFixLink(view);
  // where a vendor would publish a workaround: its advisory when one is linked, else whatever leads the patch links
  const vendorPage = patch.links.find((l) => l.kind === "advisory") ?? advisory;
  const patchEmpty = patch.versions.length + patch.texts.length + patch.links.length + patch.recorded.length === 0;
  const left = deadline?.due ? daysBetween(today, deadline.due) : null;
  const many = (deadline?.cves.length ?? 0) > 1;
  return (
    <section data-fixblock="" data-fix-checked={view.checked ?? ""} aria-label="How to fix" className={`overflow-hidden rounded-[3px] border border-line bg-panel ${className}`}>
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-4 py-3 sm:px-5">
        <h2 className="font-mono text-[13px] font-medium uppercase tracking-[0.12em] text-ink">How to fix</h2>
        <p className="font-mono text-[12.5px] text-dim">{view.checked ? `sources read ${dateLabel(view.checked.slice(0, 10))}` : "fix sources not read for this one"}</p>
      </header>

      <Row name="patch">
        <Versions rows={patch.versions} more={patch.more} view={view} />
        {patch.recorded.length > 0 && (
          <ul>
            {patch.recorded.map((r) => (
              <li key={r.version} data-fix-version="" className="flex flex-wrap items-baseline gap-x-2">
                <span className="text-[12.5px] text-dim">fixed in</span>
                <span className="num text-[14.5px] text-patched">{r.version}</span>
                <Cite n={r.cite} view={view} />
              </li>
            ))}
          </ul>
        )}
        {patch.texts.map((p) => (
          <Passage key={p.text.slice(0, 60)} p={p} view={view} whose={whoseWords(p, "solution")} />
        ))}
        <Links links={patch.links} view={view} />
        {patchEmpty && (
          <p data-fix-empty="patch" className="text-dim">
            {workaround.state === "unchecked"
              ? "Not looked up. Fix details are read for live records and for CISA's listings of the last 90 days."
              : workaround.state === "no_record"
                ? "The CVE Program has not published a record for this id yet, so there is no fixed version to quote."
                : "No fixed version or patch link in the CVE record, CISA's entry, NVD or GitHub's advisories yet."}
          </p>
        )}
      </Row>

      <Row name="workaround">
        {workaround.texts.map((p) => (
          <Passage key={p.text.slice(0, 60)} p={p} view={view} whose={whoseWords(p, "workaround")} />
        ))}
        <Links links={workaround.links} view={view} />
        {workaround.state === "stated_none" && workaround.none && (
          <p data-fix-empty="workaround">
            {workaround.none.by} lists no workaround.
            <Cite n={workaround.none.cite} view={view} />
          </p>
        )}
        {workaround.state === "none_listed" && (
          <p data-fix-empty="workaround">
            No workaround published in the CVE record or by CISA yet.
            {vendorPage && (
              <>
                {" "}
                The vendor&rsquo;s own page may list one:{" "}
                <a href={vendorPage.url} {...EXT} className="link text-ink">
                  {vendorPage.host} ↗
                </a>
                <Cite n={vendorPage.cite} view={view} />
              </>
            )}
          </p>
        )}
        {workaround.state === "no_record" && (
          <p data-fix-empty="workaround" className="text-dim">
            The CVE Program has not published a record for this id yet, so no workaround can be quoted.
          </p>
        )}
        {workaround.state === "unchecked" && (
          <p data-fix-empty="workaround" className="text-dim">
            Not looked up. The CVE record, linked below, has what the vendor published.
          </p>
        )}
      </Row>

      <Row name="deadline">
        {deadline ? (
          <>
            <p>
              {deadline.due ? (
                <>
                  <span data-fix-due={deadline.due} className={`num text-[16px] font-medium ${left !== null && left >= 0 ? "text-accent" : "text-ink"}`}>
                    {dateLabel(deadline.due)}
                  </span>{" "}
                  <span className="text-dim">
                    {left === null ? "" : left > 1 ? `in ${left} days` : left === 1 ? "tomorrow" : left === 0 ? "today" : left === -1 ? "passed yesterday" : `passed ${-left} days ago`}
                  </span>
                  <br />
                </>
              ) : null}
              {/* with several CVEs on CISA's list, the date is one CVE's: say whose */}
              US federal agencies {deadline.due ? (left !== null && left < 0 ? "had to fix" : "must fix") : "must fix"} {many ? <span className="num">{deadline.cve}</span> : "this"}
              {deadline.due ? " by then" : "; CISA set no date"}. CISA lists it as exploited in the wild since <span className="num">{dateLabel(deadline.added)}</span>
              {many ? `, and ${deadline.cves.length - 1} more of this record's CVEs with it` : ""}.
              <Cite n={deadline.cite} view={view} />
            </p>
            {deadline.action && <Passage p={{ text: deadline.action, cut: false, by: "CISA", kind: "cisa", cite: deadline.cite }} view={view} whose="CISA's required action" />}
            {deadline.note && <p className="text-[13.5px] text-dim">CISA notes: {deadline.note}</p>}
            {deadline.guidance.length > 0 && (
              <p className="flex flex-wrap gap-x-4 gap-y-1 text-[13.5px]">
                {deadline.guidance.map((g) => (
                  <a key={g.url} href={g.url} {...EXT} className="link">
                    {g.label} ↗
                  </a>
                ))}
              </p>
            )}
          </>
        ) : (
          <p data-fix-empty="deadline" className="text-dim">
            Not on CISA&rsquo;s list of known exploited vulnerabilities, so no federal deadline.
          </p>
        )}
      </Row>

      {view.summary && (
        <div data-fix-row="summary" className="grid gap-x-5 gap-y-2 border-t border-line-soft px-4 py-4 sm:grid-cols-[7.5rem_minmax(0,1fr)] sm:px-5">
          <h3 className="font-mono text-[12.5px] font-medium uppercase tracking-[0.12em] text-dim sm:pt-0.5">in short</h3>
          <div className="min-w-0 text-[14.5px] leading-relaxed">
            <p className="text-ink">{view.summary.text}</p>
            <p className="mt-1.5 text-[12.5px] text-dim">
              gcdRadar&rsquo;s summary, written by a language model from this record&rsquo;s sources; not the vendor&rsquo;s words.
              <Cite n={view.summary.cite} view={view} />
            </p>
          </div>
        </div>
      )}

      <footer className="space-y-3 border-t border-line-soft bg-panel-2/60 px-4 py-3.5 sm:px-5">
        <ul className="space-y-1.5 text-[13.5px]">
          {view.refs.map((r, i) => (
            <li key={r.cve} className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
              <span className="num text-ink">{r.cve}</span>
              {r.links.map((l) => (
                <a key={l.key} href={l.url} {...EXT} data-fix-ref={l.key} className="link">
                  {l.label} ↗
                </a>
              ))}
              {i === 0 && advisory && (
                <a href={advisory.url} {...EXT} data-fix-ref="advisory" className="link">
                  {advisory.label} ↗
                </a>
              )}
            </li>
          ))}
        </ul>
        {view.citations.length > 0 && (
          <ol data-fix-citations="" className="space-y-1 text-[12.5px] leading-snug text-dim">
            {view.citations.map((c) => (
              <li key={c.n} className="grid grid-cols-[1.75rem_minmax(0,1fr)]">
                <span className="num text-accent">[{c.n}]</span>
                <span className="min-w-0 break-words">
                  <span className="text-soft">{c.publisher}</span> · {c.title} ·{" "}
                  <a href={c.url} {...(c.url.startsWith("http") ? EXT : {})} className="link break-all">
                    {c.url.replace(/^https?:\/\//, "").slice(0, 90)}
                  </a>
                </span>
              </li>
            ))}
          </ol>
        )}
      </footer>
    </section>
  );
}
