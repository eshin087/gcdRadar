import { clockFrom } from "./clock";
import { lastUpdated, loadIncidents } from "./data";
import { buildLive, type LiveData } from "./live";

/** Build-time payload for the live board (lib/live.ts over the published records), computed for the build's one clock (lib/clock.ts). */
export async function getLiveData(): Promise<LiveData> {
  const [{ incidents }, updated] = await Promise.all([loadIncidents(), lastUpdated()]);
  return buildLive(incidents, clockFrom(updated, Date.now()), updated);
}
