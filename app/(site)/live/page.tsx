import type { Metadata } from "next";
import { LiveBoardPage } from "@/components/live/LiveBoardPage";
import { boardView } from "@/lib/live/build";
import { getLiveData } from "@/lib/live-data";

export const metadata: Metadata = {
  title: "Live board",
  description: "Every live security incident in the four lanes: patch now, breaches and attacks, supply chain, research. Lane tabs, an AI-only switch, search, the twelve-month calendar and the live tags.",
};

export default async function Live() {
  const data = await getLiveData();
  // the part of the model the board draws, in the shape a sweep publishes: the browser swaps in a newer one
  return <LiveBoardPage built={boardView(data)} />;
}
