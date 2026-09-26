import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HackForge | SAI",
  description: "SAI Security Scanner and SAI Assistant for hackathon teams. SAI Scanner finds it. SAI Assistant explains it.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
