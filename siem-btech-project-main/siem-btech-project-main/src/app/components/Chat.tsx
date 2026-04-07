"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { ServerResponse } from "@/lib/siemTypes";

type Msg = { role: "user" | "assistant"; content: string };

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const SESSION_STORAGE_KEY = "siem-chat-session-id";

function getOrCreateSessionId() {
  if (typeof window === "undefined") {
    return "server-render";
  }

  const existing = window.localStorage.getItem(SESSION_STORAGE_KEY);
  if (existing) {
    return existing;
  }

  const generated = `session-${crypto.randomUUID()}`;
  window.localStorage.setItem(SESSION_STORAGE_KEY, generated);
  return generated;
}

export default function Chat({
  onPlan,
}: {
  onPlan: (payload: ServerResponse) => void;
}) {
  const [messages, setMessages] = useState<Msg[]>([
    {
      role: "assistant",
      content:
        "Hi! I'm your SIEM assistant. Try: \"Show suspicious login attempts in the last 24 hours.\"",
    },
  ]);
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [sessionId, setSessionId] = useState("local-session");
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setSessionId(getOrCreateSessionId());
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const quickPrompts = useMemo(
    () => [
      "List failed login attempts in the last 24 hours",
      "What indicators suggest a brute-force attack?",
      "How should I triage repeated login failures from one IP?",
      "Generate a short incident summary for suspicious logins",
    ],
    []
  );

  async function sendMessage(text: string) {
    const trimmed = text.trim();
    if (!trimmed || isSending) return;

    const newMessages: Msg[] = [...messages, { role: "user", content: trimmed }];
    setMessages(newMessages);
    setInput("");
    setIsSending(true);

    try {
      const res = await fetch(`${API_BASE_URL}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          message: trimmed,
          messages: newMessages,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data?.detail || data?.error || "Request failed");
      }

      const payload = data as ServerResponse;
      const assistantMsg: Msg = {
        role: "assistant",
        content: payload.assistant_text,
      };

      setMessages([...newMessages, assistantMsg]);
      onPlan(payload);
    } catch (e) {
      const error = e instanceof Error ? e.message : "Unknown error";
      const errorMsg: Msg = {
        role: "assistant",
        content: `Error: I couldn't reach the FastAPI backend at ${API_BASE_URL}. ${error}`,
      };
      setMessages([...newMessages, errorMsg]);
      console.error(e);
    } finally {
      setIsSending(false);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col rounded-2xl border border-gray-300 bg-white shadow-sm">
      <div className="shrink-0 border-b p-4">
        <div className="text-lg font-semibold text-black">Conversational SIEM Assistant</div>
        <div className="text-sm text-gray-500">FastAPI backend + local mode</div>
      </div>

      <div className="shrink-0 flex gap-2 overflow-x-auto border-b p-3">
        {quickPrompts.map((p) => (
          <button
            key={p}
            className="whitespace-nowrap rounded-full border px-3 py-1 text-sm text-black hover:bg-gray-50"
            onClick={() => sendMessage(p)}
            disabled={isSending}
            type="button"
          >
            {p}
          </button>
        ))}
      </div>

      <div className="flex-1 min-h-0 overflow-auto p-4">
        <div className="space-y-3">
          {messages.map((m, idx) => (
            <div key={idx} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[80%] rounded-2xl px-4 py-2 text-sm leading-relaxed ${
                  m.role === "user" ? "bg-black text-white" : "bg-gray-100 text-gray-900"
                }`}
              >
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{m.content}</ReactMarkdown>
              </div>
            </div>
          ))}

          {isSending && (
            <div className="flex justify-start">
              <div className="rounded-2xl bg-gray-100 px-4 py-2 text-sm text-gray-700">Thinking...</div>
            </div>
          )}

          <div ref={endRef} />
        </div>
      </div>

      <form
        className="shrink-0 border-t p-3"
        onSubmit={(e) => {
          e.preventDefault();
          sendMessage(input);
        }}
      >
        <div className="mb-2 text-xs text-gray-500">API: {API_BASE_URL}</div>
        <div className="flex gap-2">
          <input
            className="flex-1 rounded-xl border px-3 py-2 text-sm text-black outline-none focus:ring-2 focus:ring-black/10"
            placeholder='Try: "Summarize suspicious activity for the past day"'
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isSending}
          />
          <button
            className="rounded-xl bg-black px-4 py-2 text-sm text-white disabled:opacity-50"
            disabled={isSending || !input.trim()}
            type="submit"
          >
            Send
          </button>
        </div>
      </form>
    </div>
  );
}
