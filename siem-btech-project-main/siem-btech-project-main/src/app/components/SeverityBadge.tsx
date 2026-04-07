import clsx from "clsx";

export default function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "medium").toLowerCase();

  const className = clsx(
    "inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold border",
    {
      "bg-green-50 text-green-800 border-green-200 dark:bg-green-950 dark:text-green-200 dark:border-green-900":
        s === "low",
      "bg-yellow-50 text-yellow-800 border-yellow-200 dark:bg-yellow-950 dark:text-yellow-200 dark:border-yellow-900":
        s === "medium",
      "bg-orange-50 text-orange-800 border-orange-200 dark:bg-orange-950 dark:text-orange-200 dark:border-orange-900":
        s === "high",
      "bg-red-50 text-red-800 border-red-200 dark:bg-red-950 dark:text-red-200 dark:border-red-900":
        s === "critical",
    }
  );

  return <span className={className}>{s.toUpperCase()}</span>;
}