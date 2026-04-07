"use client";

import { useEffect, useState } from "react";
import Chat from "./components/Chat";
import DashboardPanel from "./components/DashboardPanel";
import InvestigationHistory from "./components/InvestigationHistory";
import ReportPanel from "./components/ReportPanel";
import TopBar from "./components/TopBar";
import type {
  ExecutionPayload,
  InvestigationPlan,
  InvestigationRecord,
  InvestigationReport,
  ServerResponse,
} from "@/lib/siemTypes";

type Entity = InvestigationPlan["detected_entities"][number];
const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export default function Home() {
  const [entities, setEntities] = useState<Entity[]>([]);
  const [planPayload, setPlanPayload] = useState<{ investigation_plan: InvestigationPlan } | null>(null);
  const [chatOpen, setChatOpen] = useState(true);
  const [execution, setExecution] = useState<ExecutionPayload | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<number | null>(null);
  const [report, setReport] = useState<InvestigationReport | null>(null);

  async function refreshHistory() {
    const investigationsRes = await fetch(`${API_BASE_URL}/investigations`);
    if (!investigationsRes.ok) {
      throw new Error("Investigation history refresh failed");
    }
    setInvestigations((await investigationsRes.json()) as InvestigationRecord[]);
  }

  useEffect(() => {
    let cancelled = false;

    async function safeRefresh() {
      try {
        await refreshHistory();
      } catch (error) {
        if (!cancelled) {
          console.error(error);
        }
      }
    }

    void safeRefresh();
    const timer = window.setInterval(() => {
      void safeRefresh();
    }, 4000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <main className="h-screen overflow-hidden p-4">
      <div className="flex h-full flex-col gap-4">
        <div className="shrink-0">
          <TopBar />
        </div>

        <div className="grid flex-1 min-h-0 grid-cols-12 gap-4">
          <div className="col-span-8 flex min-h-0 flex-col gap-4">
            <div className="flex-[5] min-h-0">
              <DashboardPanel entities={entities} plan={planPayload} execution={execution} />
            </div>
            <div className="grid flex-[5] min-h-0 grid-cols-2 gap-4">
              <div className="min-h-0">
                <InvestigationHistory
                  investigations={investigations}
                  onSelect={(record) => {
                    setSelectedInvestigationId(record.id);
                    setPlanPayload({ investigation_plan: record.plan_json });
                    setEntities(record.plan_json.detected_entities ?? []);
                    setExecution(record.execution_json ?? null);
                  }}
                />
              </div>
              <div className="min-h-0">
                <ReportPanel
                  report={report}
                  disabled={selectedInvestigationId === null}
                  onGenerate={() => {
                    if (selectedInvestigationId === null) return;
                    void fetch(`${API_BASE_URL}/investigations/${selectedInvestigationId}/report`)
                      .then((res) => {
                        if (!res.ok) throw new Error("Report generation failed");
                        return res.json();
                      })
                      .then((data) => setReport(data as InvestigationReport))
                      .catch(console.error);
                  }}
                />
              </div>
            </div>
          </div>

          <div className="col-span-4 flex min-h-0 flex-col">
            <div className="mb-2 flex shrink-0 items-center gap-2">
              <button
                onClick={() => setChatOpen((v) => !v)}
                className="rounded-lg border px-2 py-1 text-xs text-black hover:bg-gray-50 dark:border-zinc-700 dark:text-white dark:hover:bg-zinc-800"
                type="button"
                title={chatOpen ? "Minimize chat" : "Maximize chat"}
              >
                {chatOpen ? "_" : "[]"}
              </button>
              <div className="text-sm font-semibold text-black dark:text-white">Chat</div>
            </div>

            <div className="relative min-h-0 flex-1">
              <div className={chatOpen ? "h-full" : "hidden"}>
                <Chat
                  onPlan={(payload) => {
                    const typedPayload = payload as ServerResponse;
                    setPlanPayload(payload);
                    setEntities(typedPayload.investigation_plan.detected_entities ?? []);
                    setExecution(typedPayload.execution ?? null);
                    if (typedPayload.investigation_id) {
                      setSelectedInvestigationId(typedPayload.investigation_id);
                    }
                    setReport(null);
                    void refreshHistory().catch(console.error);
                  }}
                />
              </div>

              {!chatOpen && (
                <button
                  onClick={() => setChatOpen(true)}
                  className="absolute bottom-0 left-0 right-0 flex items-center justify-between rounded-2xl border bg-white px-4 py-3 text-sm font-semibold text-black hover:bg-gray-50 dark:border-zinc-800 dark:bg-zinc-950 dark:text-white dark:hover:bg-zinc-900"
                  type="button"
                  title="Open chat"
                >
                  <span>Chat minimized</span>
                  <span className="rounded-lg border px-2 py-1 text-xs dark:border-zinc-700">[]</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
