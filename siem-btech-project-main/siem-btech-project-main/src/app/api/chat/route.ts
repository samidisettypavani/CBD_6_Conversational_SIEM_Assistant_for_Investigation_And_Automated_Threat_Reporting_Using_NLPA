import { NextResponse } from "next/server";
import { GoogleGenAI } from "@google/genai";
import { z } from "zod";
import { generateMockLogs } from "@/lib/mockLogs";
import { executeInvestigationPlan } from "@/lib/executePlan";

export const runtime = "nodejs";

/** ----- 1) Define the structured schema Gemini MUST return ----- */
// Flat entity
const EntitySchema = z.object({
  type: z.string(),  // "ip" | "user" | "event_type" etc (keep flexible)
  value: z.string(),
  confidence: z.number().min(0).max(1).optional(),
});

// ✅ Shallow investigation plan (minimal nesting)
const InvestigationPlanSchema = z.object({
  intent: z.enum(["search_logs", "detect_threat", "generate_report", "ask_clarifying_question"]),
  time_range: z.string().optional(),        // e.g. "last 24 hours" or "2026-01-01 to 2026-01-02"
  filters: z
    .record(z.string(), z.string())
    .optional(),                            // flat key/value map
  output: z.enum(["summary", "raw", "timeline"]).default("summary"),
  severity: z.enum(["low", "medium", "high", "critical"]).default("medium"),
  limit: z.number().int().min(1).max(500).default(100),
  detected_entities: z.array(EntitySchema).default([]),
  assumptions: z.array(z.string()).default([]),
  next_questions: z.array(z.string()).default([]),
});

// Final response
const ResponseSchema = z.object({
  assistant_text: z.string(),
  investigation_plan: InvestigationPlanSchema,
});

type ChatMessage = { role: "user" | "assistant"; content: string };

const MOCK_LOGS = generateMockLogs(350);

export async function POST(req: Request) {
  try {
    const { messages } = (await req.json()) as { messages: ChatMessage[] };

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return NextResponse.json({ error: "Missing GEMINI_API_KEY in .env.local" }, { status: 500 });
    }

    const ai = new GoogleGenAI({ apiKey });

    /** ----- 2) System instruction: SIEM style + strict JSON output ----- */
    const systemInstruction = `
You are a Conversational SIEM Assistant.

Return ONLY valid JSON with EXACTLY these top-level keys:
1) "assistant_text" (string, markdown allowed inside this string)
2) "investigation_plan" (object)

Do not include any other top-level keys.
Do not wrap the JSON in backticks.
Return compact JSON. Do not add explanations outside JSON.

investigation_plan format:
{
  "intent": "search_logs" | "detect_threat" | "generate_report" | "ask_clarifying_question",
  "time_range": "<string or empty>",
  "filters": { "<key>": "<value>" },
  "output": "summary" | "raw" | "timeline",
  "severity": "low" | "medium" | "high" | "critical",
  "limit": 100,
  "detected_entities": [{"type":"ip|user|event_type|time_range|severity|other","value":"...","confidence":0.0}],
  "assumptions": ["..."],
  "next_questions": ["..."]
}

Rules:
- If user didn't specify a time range, set intent="ask_clarifying_question" and add 1-3 next_questions.
- If no filters are needed, set "filters": {}.
- If logs are not provided, do NOT claim you queried logs; add assumptions.
- assistant_text must include headings: "Summary", "Key Findings", "Suggested Next Questions".
- Always set investigation_plan.severity. Default to "medium" if unsure.
- Use "critical" only for clear compromise indicators, otherwise "high" for strong suspicion.
- Only use filter keys from this allowed list: event_type, source_ip, destination_ip, user, host, severity.
- If the user asks for IP, use "source_ip".
`;

    const conversationText = messages.map((m) => `${m.role.toUpperCase()}: ${m.content}`).join("\n");

    const prompt = `
    ${systemInstruction}

    Conversation:
    ${conversationText}

    JSON TEMPLATE (fill values, keep keys unchanged):
    {
      "assistant_text": "## Summary\\n...\\n\\n## Key Findings\\n- ...\\n\\n## Suggested Next Questions\\n- ...",
      "investigation_plan": {
        "intent": "search_logs",
        "time_range": "last 24 hours",
        "filters": {"event_type":"login_failed"},
        "output": "summary",
        "severity": "medium",
        "limit": 100,
        "detected_entities": [
          {"type":"event_type","value":"login_failed","confidence":0.9},
          {"type":"severity","value":"medium","confidence":0.7}
        ],
        "assumptions": [],
        "next_questions": []
      }
    }

    Return ONLY the JSON object.
    `;

    /** ----- 3) Ask Gemini for STRUCTURED OUTPUT (JSON Schema) ----- */
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: {
        responseMimeType: "application/json",
      },
    });

    const rawText = response.text;
    if (!rawText) {
      return NextResponse.json({ error: "Empty response from Gemini" }, { status: 500 });
    }

    function extractJson(raw: string) {
      // Remove ```json fences if present
      const cleaned = raw
        .replace(/```json\s*/i, "")
        .replace(/```/g, "")
        .trim();

      // Try direct parse
      try {
        return JSON.parse(cleaned);
      } catch {}
    
      // Try to extract the first {...}
      const match = cleaned.match(/\{[\s\S]*\}/);
      if (!match) throw new Error("No JSON object found");
      return JSON.parse(match[0]);
    }

    const json = extractJson(rawText);
    const parsed = ResponseSchema.safeParse(json);
    if (!parsed.success) {
      // Fallback payload so UI doesn't break
      return NextResponse.json({
        assistant_text:
          "⚠️ I returned an invalid plan format. Try again with a clearer time range (e.g., 'last 24 hours').",
        investigation_plan: {
          intent: "ask_clarifying_question",
          time_range: undefined,
          filters: {},
          output: "summary",
          limit: 100,
          detected_entities: [],
          assumptions: ["Model output failed schema validation."],
          next_questions: ["What time range should I use (last 24 hours / last 7 days)?"],
        },
        execution: null,
      });
    }

    const execution = executeInvestigationPlan(parsed.data.investigation_plan, MOCK_LOGS);

    return NextResponse.json({
      ...parsed.data,
      execution,
    });
  } catch (err: unknown) {
    const msg = String(err instanceof Error ? err.message : err ?? "");
    if (msg.includes("RESOURCE_EXHAUSTED") || msg.includes("429")) {
      return NextResponse.json({
        assistant_text:
          "## Summary\nDemo mode fallback (Gemini quota hit).\n\n## Key Findings\n- Using mock response\n\n## Suggested Next Questions\n- Try again in 30 seconds",
        investigation_plan: {
          intent: "search_logs",
          time_range: "last 24 hours",
          filters: {},
          output: "summary",
          severity: "medium",
          limit: 100,
          detected_entities: [],
          assumptions: ["Quota exceeded; fallback used."],
          next_questions: ["Try again in 30 seconds."],
        },
        execution: null,
      });
    }

    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Unknown error" },
      { status: 500 }
    );
  }
}
