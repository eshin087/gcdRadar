import type { Metadata } from "next";
import { HomePage } from "@/components/home/HomePage";
import { getHomeView } from "@/lib/home-data";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: { absolute: `${SITE.name} — ${SITE.tagline}` },
  description: SITE.description,
  openGraph: { images: ["/og/default.png"] },
};

export default async function Home() {
  // the part of the model the page draws, in the shape a sweep publishes: the browser swaps in a newer one
  const data = await getHomeView();
  return <HomePage data={data} />;
}
