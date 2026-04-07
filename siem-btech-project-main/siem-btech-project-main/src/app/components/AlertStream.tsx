import type { AlertRecord, SimulationStatus } from "@/lib/siemTypes";

function sourceBadgeClass(source: string) {
  if (source === "ml_detection") {
    return "border-amber-300/60 bg-amber-50 text-amber-800 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200";
  }

  if (source === "detection") {
    return "border-cyan-300/60 bg-cyan-50 text-cyan-800 dark:border-cyan-500/40 dark:bg-cyan-500/10 dark:text-cyan-200";
  }

  return "border-zinc-300 bg-zinc-50 text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300";
}

function sourceLabel(source: string) {
  if (source === "ml_detection") {
    return "ML Detection";
  }

  if (source === "detection") {
    return "Rule Detection";
  }

  return source.replace(/_/g, " ");
}

export default function AlertStream({
  alerts,
  simulation,
  onStart,
  onStop,
  onTick,
  onSelectAlert,
}: {
  alerts: AlertRecord[];
  simulation: SimulationStatus | null;
  onStart: () => void;
  onStop: () => void;
  onTick: () => void;
  onSelectAlert?: (alert: AlertRecord) => void;
}) {
  return (
    <div className="h-full min-h-0 overflow-auto rounded-2xl border bg-white p-4 dark:bg-zinc-950 dark:border-zinc-800">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-black dark:text-white">Alert Stream</div>
          <div className="text-xs text-gray-500 dark:text-zinc-400">
            Simulator: {simulation?.running ? `running every ${simulation.interval_seconds}s` : "stopped"}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            className="rounded-lg border px-2 py-1 text-xs text-black hover:bg-gray-50 dark:border-zinc-700 dark:text-white dark:hover:bg-zinc-800"
            onClick={onTick}
            type="button"
          >
            Pulse
          </button>
          {simulation?.running ? (
            <button
              className="rounded-lg border px-2 py-1 text-xs text-black hover:bg-gray-50 dark:border-zinc-700 dark:text-white dark:hover:bg-zinc-800"
              onClick={onStop}
              type="button"
            >
              Stop
            </button>
          ) : (
            <button
              className="rounded-lg border px-2 py-1 text-xs text-black hover:bg-gray-50 dark:border-zinc-700 dark:text-white dark:hover:bg-zinc-800"
              onClick={onStart}
              type="button"
            >
              Start
            </button>
          )}
        </div>
      </div>
      {alerts.length === 0 ? (
        <div className="text-sm text-gray-600 dark:text-zinc-400">No alerts yet.</div>
      ) : (
        <div className="space-y-3">
          {alerts.map((a, i) => (
            <button
              key={i}
              className="w-full rounded-xl border p-3 text-left dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-900"
              onClick={() => onSelectAlert?.(a)}
              type="button"
            >
              <div className="flex items-center justify-between">
                <div className="text-sm font-semibold text-black dark:text-white">
                  {a.title}
                </div>
                <div className="text-xs text-gray-500 dark:text-zinc-500">{a.ts}</div>
              </div>
              <div className="mt-1 text-sm text-gray-700 dark:text-zinc-300">
                {a.summary}
              </div>
              <div className="mt-2 flex items-center justify-between text-xs">
                <div className="font-semibold">{a.severity.toUpperCase()}</div>
                <div
                  className={`rounded-full border px-2 py-1 font-medium ${sourceBadgeClass(a.source)}`}
                >
                  {sourceLabel(a.source)}
                </div>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
