import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HackForge | Build Fast. Ship Secure.",
  description: "A developer security workspace. SAI Scanner finds it. SAI Assistant explains it. HackForge verifies the fix.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
