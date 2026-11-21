import type { ReactNode } from "react";

/**
 * A section's heading on the record page: a clear label, then a dotted rule
 * to the right edge, so each part of the page starts on a line of its own
 * that the eye can find. Sections are spaced further apart than the rows
 * inside them (the page's `space-y`); the label is the same for every
 * section, so only the fix block, the one framed element, stands out.
 */
export function SectionHead({ children, count, as: Tag = "h2", id, aside }: { children: ReactNode; count?: number; as?: "h2" | "h3"; id?: string; aside?: ReactNode }) {
  return (
    <Tag id={id} data-section-head="" className="mb-4 flex scroll-mt-24 items-center gap-3">
      <span className="font-mono text-[13px] font-medium uppercase tracking-[0.12em] text-ink">{children}</span>
      {count !== undefined && <span className="num text-[13px] font-normal text-dim">{count}</span>}
      <span aria-hidden className="h-px min-w-6 flex-1 border-t border-dotted border-faint" />
      {aside && <span className="font-mono text-[12px] font-normal normal-case tracking-normal text-dim">{aside}</span>}
    </Tag>
  );
}
