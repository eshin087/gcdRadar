/**
 * The deadline arithmetic the ledger's rules (lib/panel/ledger.ts) and the
 * browser share, so the page judges a deadline by the visitor's clock with
 * the same rule the build used. No imports, so the page's script stays
 * small.
 */

const DAY_MS = 86_400_000;

/** A deadline is "this week" through the seventh calendar day after today. */
export const LEDGER_SOON_DAYS = 7;

/** The moment a CISA deadline passes: the end of its UTC day. */
export function dueEnd(due: string): number {
  return Date.parse(`${due}T00:00:00Z`) + DAY_MS;
}

/**
 * How much of CISA's window is used at `now`, from the day it listed the
 * entry to the end of the due day: 0 on the listing day, 1 at the deadline.
 */
export function windowUsed(added: string, due: string, now: number): number {
  const start = Date.parse(`${added}T00:00:00Z`);
  const end = dueEnd(due);
  if (!(end > start)) return 1;
  return Math.min(1, Math.max(0, (now - start) / (end - start)));
}
