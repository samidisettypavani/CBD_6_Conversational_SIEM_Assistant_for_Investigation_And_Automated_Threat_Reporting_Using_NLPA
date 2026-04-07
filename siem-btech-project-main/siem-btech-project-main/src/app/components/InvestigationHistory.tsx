import type { InvestigationRecord } from "@/lib/siemTypes";

export default function InvestigationHistory({
  investigations,
  onSelect,
}: {
  investigations: InvestigationRecord[];
  onSelect: (record: InvestigationRecord) => void;
}) {
  return (
    <div className="h-full min-h-0 overflow-auto rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="mb-2 text-sm font-semibold text-black dark:text-white">Investigation History</div>
      <div className="mb-3 text-xs text-gray-500 dark:text-zinc-400">
        Recent prompts and plans saved from the chat workflow.
      </div>
      {investigations.length === 0 ? (
        <div className="text-sm text-gray-600 dark:text-zinc-400">No investigations yet.</div>
      ) : (
        <div className="space-y-3">
          {investigations.map((item) => (
            <button
              key={item.id}
              className="w-full rounded-xl border p-3 text-left hover:bg-gray-50 dark:border-zinc-800 dark:hover:bg-zinc-900"
              onClick={() => onSelect(item)}
              type="button"
            >
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-semibold text-black dark:text-white">
                  {item.plan_json.intent.replaceAll("_", " ").toUpperCase()}
                </div>
                <div className="text-xs text-gray-500 dark:text-zinc-500">
                  {new Date(item.created_at).toLocaleString()}
                </div>
              </div>
              <div className="mt-1 text-sm text-gray-700 dark:text-zinc-300">{item.user_prompt}</div>
              <div className="mt-2 flex flex-wrap gap-2 text-xs">
                <span className="rounded-full border px-2 py-1 dark:border-zinc-700">
                  sev: {(item.plan_json.severity ?? "medium").toUpperCase()}
                </span>
                <span className="rounded-full border px-2 py-1 dark:border-zinc-700">
                  output: {item.plan_json.output ?? "summary"}
                </span>
                <span className="rounded-full border px-2 py-1 dark:border-zinc-700">
                  time: {item.plan_json.time_range ?? "not specified"}
                </span>
                <span className="rounded-full border px-2 py-1 dark:border-zinc-700">
                  matches: {item.execution_json?.stats?.total ?? 0}
                </span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
