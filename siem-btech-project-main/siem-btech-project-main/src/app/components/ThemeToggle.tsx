"use client";

import { useEffect, useState } from "react";

export default function ThemeToggle() {
  const [dark, setDark] = useState(() => {
    if (typeof window === "undefined") {
      return false;
    }

    return window.localStorage.getItem("theme") === "dark";
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  function toggle() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("theme", next ? "dark" : "light");
  }

  return (
    <button
      onClick={toggle}
      className="rounded-xl border px-3 py-2 text-xs font-semibold
                 bg-white text-black hover:bg-gray-50
                 dark:bg-zinc-900 dark:text-white dark:border-zinc-700 dark:hover:bg-zinc-800"
    >
      {dark ? "Dark" : "Light"}
    </button>
  );
}
