import SeverityBadge from "./SeverityBadge";
import type { ExecutionEvent, ExecutionPayload, InvestigationPlan } from "@/lib/siemTypes";

type Entity = { type: string; value: string; confidence?: number };
type PlanPayload = { investigation_plan: InvestigationPlan };

export default function DashboardPanel({
  entities,
  plan,
  execution,
}: {
  entities: Entity[];
  plan: PlanPayload | null;
  execution: ExecutionPayload | null;
}) {
  return (
    <div className="h-full min-h-0 overflow-auto rounded-2xl border border-gray-300 bg-white shadow-sm p-4 text-black">
      <div className="mb-4 flex items-start justify-between">
        <div>
          <div className="text-lg font-semibold text-black dark:text-white">
            SOC Console
          </div>
          <div className="text-sm text-gray-700 dark:text-zinc-400">
            Phase 1: Mock SIEM Mode – No real logs connected (logs come in Phase 2).
          </div>
        </div>

        <SeverityBadge severity={plan?.investigation_plan?.severity} />
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-xl border p-3">
          <div className="text-xs text-gray-800">Status</div>
          <div className="text-sm font-semibold text-black">Demo Mode</div>
        </div>
        <div className="rounded-xl border p-3">
          <div className="text-xs text-gray-800">Intent</div>
          <div className="text-sm font-semibold text-black">{plan?.investigation_plan?.intent ?? "-"}</div>
        </div>
        <div className="rounded-xl border p-3">
          <div className="text-xs text-gray-800">Output</div>
          <div className="text-sm font-semibold text-black">{plan?.investigation_plan?.output ?? "-"}</div>
        </div>
      </div>

      {/* Detected entities */}
      <div className="mt-6">
        <div className="mb-2 text-sm font-semibold">Detected Entities</div>
        {entities.length === 0 ? (
          <div className="text-sm text-gray-500">No entities detected yet.</div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {entities.map((e, idx) => (
              <span
                key={idx}
                className="rounded-full border bg-gray-50 px-3 py-1 text-xs"
                title={e.confidence ? `confidence: ${e.confidence}` : ""}
              >
                <span className="font-semibold">{e.type}</span>: {e.value}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Results */}
      <div className="mt-6">
        <div className="mb-2 flex items-center justify-between">
          <div className="text-sm font-semibold text-black dark:text-white">Query Results</div>
          <div className="text-xs text-gray-600 dark:text-zinc-400">
            Window: {execution?.stats?.timeWindowUsed ?? "-"}
          </div>
        </div>

        <div className="grid grid-cols-4 gap-3">
          <div className="rounded-xl border p-3 dark:border-zinc-800">
            <div className="text-xs text-gray-600 dark:text-zinc-400">Matches</div>
            <div className="mt-1 text-sm font-semibold text-black">
              {execution?.stats?.total ?? 0}
            </div>
          </div>
          <div className="rounded-xl border p-3 dark:border-zinc-800">
            <div className="text-xs text-gray-600 dark:text-zinc-400">Top Source IP</div>
            <div className="mt-1 text-sm font-semibold text-black">
              {execution?.stats?.topSourceIps?.[0]?.value ?? "-"}
            </div>
          </div>
          <div className="rounded-xl border p-3 dark:border-zinc-800">
            <div className="text-xs text-gray-600 dark:text-zinc-400">Top User</div>
            <div className="mt-1 text-sm font-semibold text-black">
              {execution?.stats?.topUsers?.[0]?.value ?? "-"}
            </div>
          </div>
          <div className="rounded-xl border p-3 dark:border-zinc-800">
            <div className="text-xs text-gray-600 dark:text-zinc-400">Top Host</div>
            <div className="mt-1 text-sm font-semibold text-black">
              {execution?.stats?.topHosts?.[0]?.value ?? "-"}
            </div>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs">
          <div className="rounded-full border bg-white px-3 py-1 text-black">
            High/Critical:{" "}
            {(execution?.stats?.bySeverity?.high ?? 0) +
              (execution?.stats?.bySeverity?.critical ?? 0)}
          </div>
          <div className="rounded-full border bg-white px-3 py-1 text-xs text-black">
            Brute force:{" "}
            <span className="font-semibold">
              {execution?.stats?.bruteForceDetected ? "YES" : "NO"}
            </span>
          </div>
        </div>

        <div className="mt-4">
          <div className="mb-2 text-sm font-semibold text-black dark:text-white">
            Recent Matching Events
          </div>
          <div className="max-h-44 overflow-auto rounded-xl border dark:border-zinc-800">
            {(execution?.matched ?? []).slice(0, 12).map((e: ExecutionEvent, idx: number) => (
              <div
                key={idx}
                className="border-b p-3 text-sm last:border-b-0 dark:border-zinc-800"
              >
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-black dark:text-white">{e.event_type}</div>
                  <div className="text-xs text-gray-500 dark:text-zinc-500">
                    {new Date(e.ts).toLocaleString()}
                  </div>
                </div>
                <div className="mt-1 text-xs text-gray-700 dark:text-zinc-300">
                  {e.message}
                </div>
                <div className="mt-1 text-xs text-gray-500 dark:text-zinc-500">
                  src: {e.source_ip} • host: {e.host ?? "-"} • sev: {e.severity}
                </div>
              </div>
            ))}
            {(execution?.matched ?? []).length === 0 && (
              <div className="p-3 text-sm text-gray-600 dark:text-zinc-400">
                No matching events for current plan.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Plan preview */}
      <div className="mt-6">
        <div className="mb-2 text-sm font-semibold text-black">Executed SQL</div>
        <pre className="max-h-44 overflow-auto rounded-xl border bg-gray-50 p-3 text-xs whitespace-pre-wrap break-all">
{plan?.investigation_plan?.query_sql ?? "No SQL executed yet."}
        </pre>
      </div>

      <div className="mt-6">
        <div className="mb-2 text-sm font-semibold text-black">Investigation Plan (JSON)</div>
        <pre className="max-h-[45vh] overflow-auto rounded-xl border bg-gray-50 p-3 text-xs">
{plan ? JSON.stringify(plan.investigation_plan, null, 2) : "No plan yet."}
        </pre>
      </div>
    </div>
  );
}
