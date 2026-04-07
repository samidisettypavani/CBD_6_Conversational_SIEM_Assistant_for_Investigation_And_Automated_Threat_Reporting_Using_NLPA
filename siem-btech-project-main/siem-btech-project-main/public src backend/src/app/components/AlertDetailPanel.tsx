import type { AlertRecord } from "@/lib/siemTypes";

function prettifyKey(key: string) {
  return key.replace(/_/g, " ");
}

function formatValue(value: unknown) {
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value === "object" && value !== null) {
    return JSON.stringify(value);
  }
  return String(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isRecordArray(value: unknown): value is Record<string, unknown>[] {
  return Array.isArray(value) && value.every((item) => isRecord(item));
}

function FeatureComparisonPanel({
  current,
  baseline,
}: {
  current: Record<string, unknown>;
  baseline: Record<string, unknown>;
}) {
  const keys = Array.from(new Set([...Object.keys(current), ...Object.keys(baseline)]));

  return (
    <div className="rounded-xl border p-3 dark:border-zinc-800">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
        Feature Metrics / Baseline Averages
      </div>
      <div className="grid grid-cols-2 gap-2">
        {keys.map((featureKey) => (
          <div key={featureKey} className="rounded-lg border p-2 dark:border-zinc-800">
            <div className="text-[11px] font-medium uppercase tracking-wide text-gray-500 dark:text-zinc-500">
              {prettifyKey(featureKey)}
            </div>
            <div className="mt-1 text-sm font-semibold text-black dark:text-white">
              {formatValue(current[featureKey])} / {formatValue(baseline[featureKey] ?? "-")}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SummaryMapPanel({ title }: { title: string }) {
  return (
    <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
      {title}
    </div>
  );
}

function DeviationPanel({ value }: { value: Record<string, unknown>[] }) {
  return (
    <div className="rounded-xl border p-3 dark:border-zinc-800">
      <SummaryMapPanel title="Top Feature Deviations" />
      <div className="space-y-2">
        {value.map((item, index) => (
          <div key={`${item.feature ?? "feature"}-${index}`} className="rounded-lg border p-2 dark:border-zinc-800">
            <div className="text-sm font-semibold text-black dark:text-white">{formatValue(item.feature)}</div>
            <div className="mt-1 grid grid-cols-2 gap-2 text-xs text-gray-700 dark:text-zinc-300">
              <div>current: {formatValue(item.current)}</div>
              <div>baseline: {formatValue(item.baseline_avg)}</div>
              <div>delta: {formatValue(item.delta)}</div>
              <div>deviation: {formatValue(item.deviation_pct)}%</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EntityAnomaliesPanel({ value }: { value: Record<string, unknown> }) {
  return (
    <div className="rounded-xl border p-3 dark:border-zinc-800">
      <SummaryMapPanel title="Entity Anomalies" />
      <div className="space-y-3">
        {Object.entries(value).map(([groupKey, groupValue]) => (
          <div key={groupKey}>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
              {prettifyKey(groupKey)}
            </div>
            {isRecordArray(groupValue) && groupValue.length > 0 ? (
              <div className="space-y-2">
                {groupValue.map((item, index) => (
                  <div key={`${groupKey}-${index}`} className="rounded-lg border p-2 text-xs dark:border-zinc-800">
                    {Object.entries(item).map(([itemKey, itemValue]) => (
                      <div key={itemKey} className="flex items-center justify-between gap-3 py-0.5">
                        <span className="text-gray-500 dark:text-zinc-500">{prettifyKey(itemKey)}</span>
                        <span className="font-medium text-black dark:text-white">{formatValue(itemValue)}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-gray-600 dark:text-zinc-400">No notable entities in this group.</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function MitreAttackPanel({ value }: { value: Record<string, unknown> }) {
  return (
    <div className="rounded-xl border p-3 dark:border-zinc-800">
      <SummaryMapPanel title="MITRE ATT&CK Mapping" />
      <div className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-3">
        <div className="rounded-lg border p-2 dark:border-zinc-800">
          <div className="text-[11px] font-medium uppercase tracking-wide text-gray-500 dark:text-zinc-500">
            Tactic
          </div>
          <div className="mt-1 font-semibold text-black dark:text-white">{formatValue(value.tactic ?? "-")}</div>
        </div>
        <div className="rounded-lg border p-2 dark:border-zinc-800">
          <div className="text-[11px] font-medium uppercase tracking-wide text-gray-500 dark:text-zinc-500">
            Technique
          </div>
          <div className="mt-1 font-semibold text-black dark:text-white">{formatValue(value.technique ?? "-")}</div>
        </div>
        <div className="rounded-lg border p-2 dark:border-zinc-800">
          <div className="text-[11px] font-medium uppercase tracking-wide text-gray-500 dark:text-zinc-500">
            ATT&CK ID
          </div>
          <div className="mt-1 font-semibold text-black dark:text-white">{formatValue(value.technique_id ?? "-")}</div>
        </div>
      </div>
    </div>
  );
}

export default function AlertDetailPanel({ alert }: { alert: AlertRecord | null }) {
  const details = alert?.details_json ?? null;
  const featureMap = isRecord(details?.feature_map) ? details.feature_map : null;
  const baselineSummary = isRecord(details?.baseline_summary) ? details.baseline_summary : null;

  return (
    <div className="h-full min-h-0 overflow-auto rounded-2xl border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="mb-2 text-sm font-semibold text-black dark:text-white">Alert Detail</div>
      {!alert ? (
        <div className="text-sm text-gray-600 dark:text-zinc-400">Select an alert to view its explanation.</div>
      ) : (
        <div className="space-y-4">
          <div>
            <div className="text-lg font-semibold text-black dark:text-white">{alert.title}</div>
            <div className="mt-1 text-xs text-gray-500 dark:text-zinc-500">{alert.ts}</div>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="rounded-full border px-2 py-1 dark:border-zinc-700">
              severity: {alert.severity.toUpperCase()}
            </span>
            <span className="rounded-full border px-2 py-1 dark:border-zinc-700">
              source: {alert.source}
            </span>
          </div>
          <div className="text-sm text-gray-700 dark:text-zinc-300">{alert.summary}</div>
          <div>
            <div className="mb-2 text-sm font-semibold text-black dark:text-white">Explanation</div>
            {details && Object.keys(details).length > 0 ? (
              <div className="space-y-2">
                {featureMap && baselineSummary ? (
                  <FeatureComparisonPanel current={featureMap} baseline={baselineSummary} />
                ) : null}
                {Object.entries(details).map(([key, value]) =>
                  key === "feature_map" || key === "baseline_summary" ? null : key === "top_feature_deviations" && isRecordArray(value) ? (
                    <DeviationPanel key={key} value={value} />
                  ) : key === "entity_anomalies" && isRecord(value) ? (
                    <EntityAnomaliesPanel key={key} value={value} />
                  ) : key === "mitre_attack" && isRecord(value) ? (
                    <MitreAttackPanel key={key} value={value} />
                  ) : (
                    <div key={key} className="rounded-xl border p-3 text-sm dark:border-zinc-800">
                      <div className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-zinc-500">
                        {prettifyKey(key)}
                      </div>
                      <div className="mt-1 text-black dark:text-white">{formatValue(value)}</div>
                    </div>
                  ),
                )}
              </div>
            ) : (
              <div className="text-sm text-gray-600 dark:text-zinc-400">
                No extra explanation data is available for this alert.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
