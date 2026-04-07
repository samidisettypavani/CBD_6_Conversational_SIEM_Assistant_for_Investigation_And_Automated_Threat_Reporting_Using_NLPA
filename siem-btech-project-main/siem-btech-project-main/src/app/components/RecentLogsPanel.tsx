import type { ExecutionEvent } from "@/lib/siemTypes";

export default function RecentLogsPanel({ logs }: { logs: ExecutionEvent[] }) {
  return (
    <div className="h-full min-h-0 overflow-auto rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="mb-2 text-sm font-semibold text-black dark:text-white">Recent Logs</div>
      <div className="mb-3 text-xs text-gray-500 dark:text-zinc-400">
        Latest events flowing into PostgreSQL.
      </div>
      {logs.length === 0 ? (
        <div className="text-sm text-gray-600 dark:text-zinc-400">No recent logs available.</div>
      ) : (
        <div className="space-y-3">
          {logs.map((log, idx) => (
            <div key={`${log.ts}-${idx}`} className="rounded-xl border p-3 dark:border-zinc-800">
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-semibold text-black dark:text-white">{log.event_type}</div>
                <div className="text-xs text-gray-500 dark:text-zinc-500">
                  {new Date(log.ts).toLocaleString()}
                </div>
              </div>
              <div className="mt-1 text-sm text-gray-700 dark:text-zinc-300">{log.message}</div>
              <div className="mt-2 text-xs text-gray-500 dark:text-zinc-500">
                src: {log.source_ip} | host: {log.host ?? "-"} | user: {log.user ?? "-"} | sev: {log.severity}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
