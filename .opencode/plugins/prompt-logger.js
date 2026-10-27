// prompt-logger.js -- OpenCode plugin that records prompts + agent events to a
// file, so the testbed captures the user prompt (which the MCP proxy cannot see).
//
// Writes two files under <project>/logs/:
//   prompts.jsonl        -- clean records (user prompts, and assistant text)
//   opencode_events.jsonl-- raw message/tool events (for shape discovery + audit)
//
// Correlates with proxy MCP logs via MCP_RUN_ID (set by opencode_batch.ps1); in
// the interactive TUI there is no MCP_RUN_ID, so records fall back to sessionID.
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

export const PromptLogger = async ({ directory }) => {
  const base = directory || "F:/project0/MCP-Project";
  // Centralize logs with MCP_LOG_DIR (useful when the plugin is installed
  // globally and used across projects); otherwise write to <project>/logs.
  const logDir = process.env.MCP_LOG_DIR || join(base, "logs");
  try { mkdirSync(logDir, { recursive: true }); } catch (_) {}
  const promptsFile = join(logDir, "prompts.jsonl");
  const eventsFile = join(logDir, "opencode_events.jsonl");
  const runId = process.env.MCP_RUN_ID || null;

  const append = (file, rec) => {
    try { appendFileSync(file, JSON.stringify(rec) + "\n"); } catch (_) {}
  };

  // messageID -> role, learned from message.updated (role lives there, not in
  // the text part), so we can label each text part user vs assistant.
  const roleOf = {};
  // De-dupe streamed user parts (same part id updates as text grows).
  const seenUserPart = new Set();

  return {
    event: async ({ event }) => {
      try {
        const type = event?.type || "";
        if (type !== "message.updated" && type !== "message.part.updated") return;
        const props = event?.properties || {};
        // Raw capture (bounded) so the exact payload shape stays auditable.
        append(eventsFile, { ts: new Date().toISOString(), run_id: runId, type, properties: props });

        if (type === "message.updated") {
          const info = props.info || {};
          if (info.id) roleOf[info.id] = info.role;
          return;
        }
        // message.part.updated: log USER text prompts cleanly.
        const part = props.part || {};
        if (part.type !== "text" || !part.text) return;
        const role = roleOf[part.messageID] || "unknown";
        if (role !== "user") return;                 // assistant text stays in events file
        if (part.id && seenUserPart.has(part.id)) return;
        if (part.id) seenUserPart.add(part.id);
        append(promptsFile, {
          ts: new Date().toISOString(), run_id: runId, source: "plugin",
          label: "opencode", role: "user",
          sessionID: props.sessionID || part.sessionID || null,
          messageID: part.messageID || null,
          text: part.text,
        });
      } catch (_) {}
    },
    "tool.execute.before": async (input, output) => {
      append(eventsFile, {
        ts: new Date().toISOString(), run_id: runId, type: "tool.execute.before",
        tool: input?.tool, sessionID: input?.sessionID, callID: input?.callID,
        args: output?.args,
      });
    },
  };
};
