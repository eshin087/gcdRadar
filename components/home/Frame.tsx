import type { ReactNode } from "react";

/**
 * A section of the home page: a hairline with a tick at each end, the
 * section's title cut into the line at the left and one control at the
 * right (app/globals.css .hp-frame). `title` is the heading itself (an h2,
 * or a tab list whose selected tab is the heading); `control` is a link or a
 * button and a few words. On a phone a long control would run into the
 * title, so a section may keep it off the line there (`controlFrom="sm"`)
 * and repeat it under its rows.
 */
export function Frame({ id, label, title, control, controlFrom, className = "", children, ...rest }: { id?: string; label: string; title: ReactNode; control?: ReactNode; controlFrom?: "sm"; className?: string; children: ReactNode } & Record<`data-${string}`, string | number | undefined>) {
  return (
    <section id={id} aria-label={label} className={`hp-frame scroll-mt-8 ${className}`} {...rest}>
      <div className="hp-frame-title">{title}</div>
      {control && <div className={`hp-frame-ctl ${controlFrom === "sm" ? "hp-from-sm" : ""}`}>{control}</div>}
      {children}
    </section>
  );
}
