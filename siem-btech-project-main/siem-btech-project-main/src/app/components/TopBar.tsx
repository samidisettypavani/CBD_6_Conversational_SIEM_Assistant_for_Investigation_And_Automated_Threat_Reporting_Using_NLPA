"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import ThemeToggle from "./ThemeToggle";

export default function TopBar() {
  const pathname = usePathname();

  return (
    <div className="mb-4 flex items-center justify-between">
      <div>
        <div className="text-2xl font-bold tracking-tight text-black dark:text-white">
          SOC Console
        </div>
        <div className="text-sm text-gray-600 dark:text-zinc-400">
          Conversational SIEM Assistant - Local Mode
        </div>
        <div className="mt-3 flex items-center gap-2 text-xs">
          <Link
            className={`rounded-full border px-3 py-1 ${
              pathname === "/" ? "bg-black text-white dark:bg-white dark:text-black" : "text-black dark:text-white"
            }`}
            href="/"
          >
            Investigate
          </Link>
          <Link
            className={`rounded-full border px-3 py-1 ${
              pathname === "/live" ? "bg-black text-white dark:bg-white dark:text-black" : "text-black dark:text-white"
            }`}
            href="/live"
          >
            Live Monitor
          </Link>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <ThemeToggle />
      </div>
    </div>
  );
}
