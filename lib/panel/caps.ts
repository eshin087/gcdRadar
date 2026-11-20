/**
 * How much of its lists the home page shows (the rules are in
 * lib/panel/ledger.ts and lib/panel/news.ts). Kept apart so the browser's
 * components can import the caps without the dataset modules behind the
 * rules.
 */

/** "Next due": the nearest deadline leads with its countdown, and this many rows follow it. */
export const NEXT_DUE_ROWS = 6;
/** My stack draws this many products that need action before "+N more". */
export const STACK_ROWS = 9;
/** The new critical CVEs named under My stack. */
export const STACK_CRITS_NAMED = 4;
