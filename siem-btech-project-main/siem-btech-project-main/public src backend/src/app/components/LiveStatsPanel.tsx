import type { LiveStats } from "@/lib/siemTypes";

function maxValue(values: number[]) {
  return Math.max(...values, 1);
}

function HoverBar({
  label,
  value,
  widthPercent,
}: {
  label: string;
  value: number;
  widthPercent: number;
}) {
  return (
    <div className="group relative">
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="text-black dark:text-white">{label}</span>
        <span className="text-gray-500 dark:text-zinc-400">{value}</span>
      </div>
      <div className="h-2 rounded-full bg-gray-100 dark:bg-zinc-800">
        <div
          className="h-2 rounded-full bg-black dark:bg-white"
          style={{ width: `${widthPercent}%` }}
        />
      </div>
      <div className="pointer-events-none absolute -top-7 right-0 rounded-md bg-black px-2 py-1 text-[10px] text-white opacity-0 shadow-sm transition-opacity group-hover:opacity-100 dark:bg-white dark:text-black">
        {label}: {value}
      </div>
    </div>
  );
}

function HoverTimelineBar({
  bucket,
  count,
  heightPercent,
}: {
  bucket: string;
  count: number;
  heightPercent: number;
}) {
  return (
    <div className="group flex flex-1 flex-col items-center gap-2">
      <div className="relative flex h-28 w-full items-end">
        <div
          className="mx-auto w-full max-w-12 rounded-t-lg bg-black dark:bg-white"
          style={{ height: `${heightPercent}%` }}
        />
        <div className="pointer-events-none absolute -top-7 left-1/2 -translate-x-1/2 rounded-md bg-black px-2 py-1 text-[10px] text-white opacity-0 shadow-sm transition-opacity group-hover:opacity-100 dark:bg-white dark:text-black whitespace-nowrap">
          {count}
        </div>
      </div>
      <div className="text-center text-[10px] text-gray-500 dark:text-zinc-400">{bucket}</div>
    </div>
  );
}

export function ActivityTimelinePanel({ stats }: { stats: LiveStats | null }) {
  const timeline = stats?.timeline ?? [];
  const timelineMax = maxValue(timeline.map((item) => item.count));

  return (
    <div className="h-full min-h-0 overflow-auto rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="mb-3 text-sm font-semibold text-black dark:text-white">Activity Timeline</div>
      <div className="flex h-40 items-end gap-3">
        {timeline.length === 0 ? (
          <div className="text-sm text-gray-600 dark:text-zinc-400">No recent timeline data.</div>
        ) : (
          timeline.map((item) => (
            <HoverTimelineBar
              key={item.bucket}
              bucket={item.bucket}
              count={item.count}
              heightPercent={(item.count / timelineMax) * 100}
            />
          ))
        )}
      </div>
    </div>
  );
}

export default function LiveStatsPanel({ stats }: { stats: LiveStats | null }) {
  const severityEntries = Object.entries(stats?.by_severity ?? {});
  const eventTypeEntries = Object.entries(stats?.by_event_type ?? {});
  const topIps = stats?.top_source_ips ?? [];
  const severityMax = maxValue(severityEntries.map(([, value]) => value));
  const eventTypeMax = maxValue(eventTypeEntries.map(([, value]) => value));

  return (
    <div className="grid h-full min-h-0 grid-cols-2 gap-4">
      <div className="rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
        <div className="mb-3 text-sm font-semibold text-black dark:text-white">Overview</div>
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-xl border p-3 dark:border-zinc-800">
            <div className="text-xs text-gray-500 dark:text-zinc-400">Events (24h)</div>
            <div className="mt-1 text-lg font-semibold text-black dark:text-white">{stats?.total_events ?? 0}</div>
          </div>
          <div className="rounded-xl border p-3 dark:border-zinc-800">
            <div className="text-xs text-gray-500 dark:text-zinc-400">Detection Alerts</div>
            <div className="mt-1 text-lg font-semibold text-black dark:text-white">{stats?.detection_alerts ?? 0}</div>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
        <div className="mb-3 text-sm font-semibold text-black dark:text-white">Top Source IPs</div>
        <div className="space-y-3">
          {topIps.length === 0 ? (
            <div className="text-sm text-gray-600 dark:text-zinc-400">No recent IP activity.</div>
          ) : (
            topIps.map((item) => (
              <HoverBar
                key={item.value}
                label={item.value}
                value={item.count}
                widthPercent={(item.count / maxValue(topIps.map((ip) => ip.count))) * 100}
              />
            ))
          )}
        </div>
      </div>

      <div className="rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
        <div className="mb-3 text-sm font-semibold text-black dark:text-white">Severity Distribution</div>
        <div className="space-y-3">
          {severityEntries.length === 0 ? (
            <div className="text-sm text-gray-600 dark:text-zinc-400">No recent severity data.</div>
          ) : (
            severityEntries.map(([label, value]) => (
              <HoverBar
                key={label}
                label={label.toUpperCase()}
                value={value}
                widthPercent={(value / severityMax) * 100}
              />
            ))
          )}
        </div>
      </div>

      <div className="rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
        <div className="mb-3 text-sm font-semibold text-black dark:text-white">Event Types</div>
        <div className="space-y-3">
          {eventTypeEntries.length === 0 ? (
            <div className="text-sm text-gray-600 dark:text-zinc-400">No recent event type data.</div>
          ) : (
            eventTypeEntries.map(([label, value]) => (
              <HoverBar
                key={label}
                label={label}
                value={value}
                widthPercent={(value / eventTypeMax) * 100}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
