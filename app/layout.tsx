import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "FM Career Hub",
  description: "O centro de comando da tua carreira no Football Manager."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="pt-PT">
      <body>{children}</body>
    </html>
  );
}
