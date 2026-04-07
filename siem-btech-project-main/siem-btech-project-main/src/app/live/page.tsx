"use client";

import { useEffect, useState } from "react";
import AlertDetailPanel from "../components/AlertDetailPanel";
import AlertStream from "../components/AlertStream";
import LiveStatsPanel, { ActivityTimelinePanel } from "../components/LiveStatsPanel";
import RecentLogsPanel from "../components/RecentLogsPanel";
import TopBar from "../components/TopBar";
import type { AlertRecord, ExecutionEvent, LiveStats, SimulationStatus } from "@/lib/siemTypes";

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export default function LivePage() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [logs, setLogs] = useState<ExecutionEvent[]>([]);
  const [simulation, setSimulation] = useState<SimulationStatus | null>(null);
  const [stats, setStats] = useState<LiveStats | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);

  async function refreshLiveState() {
    const [alertsRes, simRes, logsRes, statsRes] = await Promise.all([
      fetch(`${API_BASE_URL}/alerts?source=detection,ml_detection`),
      fetch(`${API_BASE_URL}/simulation/status`),
      fetch(`${API_BASE_URL}/logs/recent?limit=20`),
      fetch(`${API_BASE_URL}/stats/live?window_hours=24`),
    ]);

    if (!alertsRes.ok || !simRes.ok || !logsRes.ok || !statsRes.ok) {
      throw new Error("Live state refresh failed");
    }

    const [alertsData, simData, logsData, statsData] = (await Promise.all([
      alertsRes.json(),
      simRes.json(),
      logsRes.json(),
      statsRes.json(),
    ])) as [AlertRecord[], SimulationStatus, ExecutionEvent[], LiveStats];

    setAlerts(alertsData);
    setSimulation(simData);
    setLogs(logsData);
    setStats(statsData);
  }

  useEffect(() => {
    let cancelled = false;

    async function safeRefresh() {
      try {
        await refreshLiveState();
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

  async function updateSimulation(endpoint: "start" | "stop" | "tick") {
    try {
      const res = await fetch(`${API_BASE_URL}/simulation/${endpoint}`, {
        method: "POST",
      });
      if (!res.ok) {
        throw new Error(`Simulation ${endpoint} failed`);
      }
      await refreshLiveState();
    } catch (error) {
      console.error(error);
    }
  }

  return (
    <main className="h-screen overflow-hidden p-4">
      <div className="flex h-full flex-col gap-4">
        <div className="shrink-0">
          <TopBar />
        </div>

        <div className="grid min-h-0 flex-1 grid-cols-12 gap-4">
          <div className="col-span-5 min-h-0">
            <AlertStream
              alerts={alerts}
              simulation={simulation}
              onStart={() => void updateSimulation("start")}
              onStop={() => void updateSimulation("stop")}
              onTick={() => void updateSimulation("tick")}
              onSelectAlert={(alert) => {
                void fetch(`${API_BASE_URL}/alerts/${alert.id}`)
                  .then((res) => {
                    if (!res.ok) throw new Error("Alert detail fetch failed");
                    return res.json();
                  })
                  .then((data) => setSelectedAlert(data as AlertRecord))
                  .catch(console.error);
              }}
            />
          </div>
          <div className="col-span-7 grid min-h-0 grid-rows-[minmax(0,1fr)_320px_260px] gap-4">
            <div className="min-h-0">
              <LiveStatsPanel stats={stats} />
            </div>
            <div className="grid min-h-0 grid-cols-2 gap-4">
              <div className="min-h-0">
                <ActivityTimelinePanel stats={stats} />
              </div>
              <div className="min-h-0">
                <AlertDetailPanel alert={selectedAlert} />
              </div>
            </div>
            <div className="min-h-0">
              <RecentLogsPanel logs={logs} />
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
