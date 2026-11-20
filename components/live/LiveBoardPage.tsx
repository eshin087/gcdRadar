"use client";

import { FreshLinks } from "@/components/live/FreshLinks";
import { LivePage } from "@/components/live/LivePage";
import { useLive } from "@/components/live/useLive";
import { BOARD_VIEW_KEYS, LIVE_FILES, type BoardView } from "@/lib/live/shape";

/**
 * The live board with its live layer: built from a BoardView at deploy
 * time, redrawn from a newer sweep's when the Worker has one
 * (components/live/useLive.ts). The board's rows carry what a record's
 * drawer needs, and a record newer than the site's last rebuild opens in
 * one instead of a page it does not have yet (FreshLinks).
 */
export function LiveBoardPage({ built }: { built: BoardView }) {
  const live = useLive<BoardView>(LIVE_FILES.board, built, built.lastUpdated, BOARD_VIEW_KEYS);
  return (
    <>
      <LivePage data={live.view} variant="board" />
      <FreshLinks records={live.fresh} />
    </>
  );
}
