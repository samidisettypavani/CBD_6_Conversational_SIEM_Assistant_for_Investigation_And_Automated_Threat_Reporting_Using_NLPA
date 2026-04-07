import type { InvestigationReport } from "@/lib/siemTypes";

export default function ReportPanel({
  report,
  onGenerate,
  disabled,
}: {
  report: InvestigationReport | null;
  onGenerate: () => void;
  disabled: boolean;
}) {
  return (
    <div className="h-full min-h-0 overflow-auto rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-black dark:text-white">Investigation Report</div>
          <div className="text-xs text-gray-500 dark:text-zinc-400">
            Generate a summary from the currently selected investigation snapshot.
          </div>
        </div>
        <button
          className="rounded-lg border px-3 py-1 text-xs text-black hover:bg-gray-50 disabled:opacity-50 dark:border-zinc-700 dark:text-white dark:hover:bg-zinc-800"
          disabled={disabled}
          onClick={onGenerate}
          type="button"
        >
          Generate Report
        </button>
      </div>
      {!report ? (
        <div className="text-sm text-gray-600 dark:text-zinc-400">No report generated yet.</div>
      ) : (
        <div className="space-y-4">
          <div>
            <div className="text-lg font-semibold text-black dark:text-white">{report.title}</div>
            <div className="mt-1 text-xs text-gray-500 dark:text-zinc-500">
              Generated {new Date(report.generated_at).toLocaleString()}
            </div>
          </div>
          <div className="rounded-xl border p-3 text-sm dark:border-zinc-800">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
              Summary
            </div>
            <div className="text-black dark:text-white">{report.summary}</div>
          </div>
          <div className="rounded-xl border p-3 text-sm dark:border-zinc-800">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
              Findings
            </div>
            <ul className="space-y-1 text-black dark:text-white">
              {report.findings.map((item) => (
                <li key={item}>- {item}</li>
              ))}
            </ul>
          </div>
          <div className="rounded-xl border p-3 text-sm dark:border-zinc-800">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
              Evidence
            </div>
            <ul className="space-y-1 text-black dark:text-white">
              {report.evidence.map((item) => (
                <li key={item}>- {item}</li>
              ))}
            </ul>
          </div>
          <div className="rounded-xl border p-3 text-sm dark:border-zinc-800">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
              Recommended Actions
            </div>
            <ul className="space-y-1 text-black dark:text-white">
              {report.recommended_actions.map((item) => (
                <li key={item}>- {item}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
