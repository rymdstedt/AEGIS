import { useState, useEffect, useRef, useCallback } from "react";
import ApplicationResearch from "./ApplicationResearch";

const fragmentToken = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
let sessionToken = "";
try {
  sessionToken = sessionStorage.getItem("aegis.launch-token") || "";
  if (fragmentToken) sessionStorage.setItem("aegis.launch-token", fragmentToken);
} catch {
  // Some hardened browser contexts disable storage. The one-time fragment
  // still lets the initial desktop page load work in that environment.
}
const authToken = fragmentToken || sessionToken || import.meta.env.VITE_AEGIS_AUTH_TOKEN || "";
if (fragmentToken) history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);

function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
  return fetch(url, { ...options, headers });
}

function makeScanId() {
  const random = crypto.randomUUID
    ? crypto.randomUUID().replaceAll("-", "")
    : Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
  return `scan_${random}`;
}

function currentScanId() {
  try {
    const saved = sessionStorage.getItem("aegis.scan-id") || "";
    if (/^scan_[A-Za-z0-9_-]{16,96}$/.test(saved)) return saved;
  } catch { /* Hardened browser storage may be unavailable. */ }
  const created = makeScanId();
  try { sessionStorage.setItem("aegis.scan-id", created); } catch { /* Optional. */ }
  return created;
}

const theme = {
  bg: "#0a0e17", surface: "#111827", surfaceAlt: "#1a2235", border: "#1e293b",
  text: "#e2e8f0", textDim: "#64748b", accent: "#3b82f6",
  accentGlow: "rgba(59,130,246,0.15)", critical: "#ef4444", high: "#f97316",
  medium: "#eab308", low: "#3b82f6", info: "#6b7280", green: "#22c55e",
  terminal: "#0d1117",
};
const sev_colors = { critical: theme.critical, high: theme.high, medium: theme.medium, low: theme.low, info: theme.info };

function getLogColor(type) {
  switch (type) {
    case "error": return theme.critical;
    case "finding": return theme.high;
    case "tool": return theme.accent;
    case "agent": return "#a78bfa";
    default: return theme.text;
  }
}

function useAgent() {
  const ws = useRef(null);
  const wsCleanup = useRef(null);
  const isMounted = useRef(false);
  const [connected, setConnected] = useState(false);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scanState, setScanState] = useState("idle");
  const [currentPhase, setCurrentPhase] = useState("");
  const [approval, setApproval] = useState(null);
  const [report, setReport] = useState("");
  const [toolOutput, setToolOutput] = useState([]);
  const [lastTool, setLastTool] = useState(null);
  const [loot, setLoot] = useState([]);  // Phase 2: collected creds/access from actual exploits
  const [exploitationApproved, setExploitationApproved] = useState([]);  // approved finding summaries
  const [exploitDecision, setExploitDecision] = useState(null);
  const [discoveryDecision, setDiscoveryDecision] = useState(null);
  const [coverage, setCoverage] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const scanId = useRef(null);
  if (!scanId.current) scanId.current = currentScanId();

  const connect = useCallback(() => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) return;
    if (ws.current) { ws.current.onclose = null; ws.current.close(); }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    // Use current page host (incl. port) so:
    // - prod serve on :8000 works
    // - vite dev on :3000 + proxy for /ws works (no hardcoded 8000)
    const host = window.location.host || "localhost:8000";
    // Keep the launch credential out of URLs and access logs. WebSocket
    // subprotocols are request headers and still work through the Vite proxy.
    const socket = new WebSocket(
      `${protocol}//${host}/ws/${scanId.current}`,
      ["aegis.v1", `aegis.auth.${authToken}`],
    );

    socket.onopen = () => { setConnected(true); isMounted.current = true; };
    socket.onclose = () => {
      setConnected(false);
      setScanState(current => ["starting", "running", "paused"].includes(current) ? "disconnected" : current);
      if (isMounted.current) wsCleanup.current = setTimeout(() => connect(), 1500);
    };
    socket.onerror = (err) => console.error("WS error:", err);

    socket.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        const ev = msg.event;
        const ts = new Date().toLocaleTimeString();

        if (ev === "scan_snapshot") {
          const saved = msg.snapshot || {};
          setScanState(saved.status || "idle");
          setCurrentPhase(saved.phase || "");
          setFindings(saved.findings || []);
          setCoverage(saved.coverage || null);
          setEvidence(saved.evidence || null);
          setReport(saved.report || "");
          setApproval(saved.approval || null);
          setExploitDecision(saved.exploit_decision || null);
          setDiscoveryDecision(saved.discovery_decision || null);
          setExploitationApproved(saved.exploitation_approved || []);
          setLogs(p => { const n = [...p, { type: "info", message: "Reattached to the in-memory scan. Earlier terminal lines are not replayed; Evidence and Report retain the scan record.", ts }]; return n.length > 800 ? n.slice(-800) : n; });
        } else if (ev === "scan_missing") {
          setScanState(current => current === "disconnected" ? "stopped" : current);
          setLogs(p => p.length ? [...p, { type: "error", message: "The previous scan is no longer running in this backend. Start a fresh scan; old port observations cannot be reused as current coverage.", ts }] : p);
        } else if (ev === "log") {
          setLogs(p => { const n = [...p, { ...msg, ts }]; return n.length > 800 ? n.slice(-800) : n; });
        } else if (ev === "scan_started") {
          setScanState("running");
          setCurrentPhase(msg.phase || msg.phases?.[0] || "");
          setDiscoveryDecision(null); setCoverage(null); setEvidence(null);
        } else if (ev === "scan_stopped") {
          setExploitDecision(null);
          setDiscoveryDecision(null);
          setScanState(current => current === "error" ? current : "stopped");
        } else if (ev === "scan_complete") {
          setExploitDecision(null);
          setDiscoveryDecision(null);
          setScanState(["inconclusive", "partial"].includes(msg.outcome) ? msg.outcome : "complete");
          if (msg.coverage) setCoverage(msg.coverage);
          if (msg.summary) setReport(msg.summary);
          if (msg.findings) setFindings(msg.findings);
          if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ action: "evidence" }));
        } else if (ev === "finding") {
          setFindings(p => [...p, msg]);
          setLogs(p => { const n = [...p, { type: "finding", message: `[${(msg.severity || "").toUpperCase()}] ${msg.title}`, ts }]; return n.length > 800 ? n.slice(-800) : n; });
          if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ action: "evidence" }));
        } else if (ev === "finding_updated") {
          setFindings(p => p.map(item => item.id === msg.id ? msg : item));
          if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ action: "evidence" }));
        } else if (ev === "tool_start") {
          setLastTool(msg);
          setToolOutput(p => { const n = [...p, `\n━━━ ${msg.tool} ━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`]; return n.length > 600 ? n.slice(-600) : n; });
        } else if (ev === "tool_output") {
          setToolOutput(p => { const n = [...p, msg.line]; return n.length > 600 ? n.slice(-600) : n; });
        } else if (ev === "tool_done") {
          setLastTool(prev => prev ? { ...prev, done: true } : null);
        } else if (ev === "coverage_update") {
          setCoverage(msg.coverage);
          if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ action: "evidence" }));
        } else if (ev === "discovery_decision_needed") {
          setDiscoveryDecision(msg);
          if (msg.coverage) setCoverage(msg.coverage);
          setScanState("paused");
          setLogs(p => { const n = [...p, { type: "error", message: "TCP discovery is incomplete. Retry unfinished port windows or continue with a partial assessment.", ts }]; return n.length > 800 ? n.slice(-800) : n; });
        } else if (ev === "discovery_decision_resolved") {
          setDiscoveryDecision(null);
          setScanState("running");
        } else if (ev === "evidence") {
          setEvidence(msg.snapshot);
          if (msg.snapshot?.coverage) setCoverage(msg.snapshot.coverage);
        } else if (ev === "approval_needed") {
          setApproval(msg); setScanState("paused");
          setLogs(p => { const n = [...p, { type: "agent", message: `Approval needed for ${msg.tool}`, ts }]; return n.length > 800 ? n.slice(-800) : n; });
        } else if (ev === "exploit_decision_needed") {
          setExploitDecision(msg);
          setScanState("paused");
          setLogs(p => { const n = [...p, { type: "agent", message: `Exploitation decision needed for ${(msg.findings || []).length} mapped finding(s)`, ts }]; return n.length > 800 ? n.slice(-800) : n; });
        } else if (ev === "exploit_decision_resolved") {
          setExploitDecision(null);
          setScanState("running");
        } else if (ev === "scan_resumed") {
          setCurrentPhase(msg.phase || "exploit");
          setExploitDecision(null);
          setScanState("running");
        } else if (ev === "phase_change") {
          setCurrentPhase(msg.phase);
          setLogs(p => { const n = [...p, { type: "agent", message: `Phase → ${msg.phase}`, ts }]; return n.length > 800 ? n.slice(-800) : n; });
        } else if (ev === "report") {
          setReport(msg.markdown);
        } else if (ev === "error") {
          setLogs(p => { const n = [...p, { type: "error", message: msg.message, ts }]; return n.length > 800 ? n.slice(-800) : n; });
          setScanState(current => current === "starting" ? "error" : current);
        } else if (ev === "loot") {
          setLoot(p => { const n = [...p, msg]; return n.length > 50 ? n.slice(-50) : n; });
          setLogs(p => { const n = [...p, { type: "finding", message: `LOOT collected: ${msg.type} on ${msg.host || msg.service || '?'}`, ts }]; return n.length > 800 ? n.slice(-800) : n; });
        } else if (ev === "exploitation_approved") {
          setExploitDecision(null);
          setScanState("running");
          setExploitationApproved(p => p.some(item => item.id === msg.id)
            ? p
            : [...p, { id: msg.id, title: msg.title, tools: msg.tools || [] }]);
          setLogs(p => { const n = [...p, { type: "agent", message: `EXPLOITATION APPROVED: ${msg.title}`, ts }]; return n.length > 800 ? n.slice(-800) : n; });
        }
      } catch (err) { console.error("WS parse error:", err); }
    };

    ws.current = socket;
  }, []);

  const send = useCallback((data) => {
    if (ws.current?.readyState !== WebSocket.OPEN) return false;
    ws.current.send(JSON.stringify(data));
    return true;
  }, []);

  // Strict separation helper: must be called by user before any real exploitation
  const approveFindingForExploitation = useCallback((finding) => {
    if (!finding?.id) return;
    send({ action: "approve_exploitation", finding_id: finding.id });
  }, [send]);

  const skipExploitation = useCallback(() => {
    send({ action: "skip_exploitation" });
  }, [send]);

  useEffect(() => {
    isMounted.current = true;
    connect();
    return () => {
      isMounted.current = false;
      clearTimeout(wsCleanup.current);
      if (ws.current) { ws.current.onclose = null; ws.current.close(); }
    };
  }, [connect]);

  const newScan = useCallback(async () => {
    if (["starting", "running", "paused", "disconnected"].includes(scanState)) {
      try {
        const response = await apiFetch(`/api/scan/${scanId.current}/stop`, { method: "POST" });
        if (!response.ok && response.status !== 404) throw new Error(`HTTP ${response.status}`);
      } catch {
        if (!send({ action: "stop" })) {
          setLogs(p => [...p, { type: "error", message: "Could not stop the previous scan. Reconnect before starting another one.", ts: new Date().toLocaleTimeString() }]);
          return false;
        }
      }
    }
    if (ws.current) { ws.current.onclose = null; ws.current.close(); }
    scanId.current = makeScanId();
    try { sessionStorage.setItem("aegis.scan-id", scanId.current); } catch { /* Optional. */ }
    setLogs([]); setFindings([]); setReport(""); setToolOutput([]); setLoot([]);
    setExploitationApproved([]);
    setExploitDecision(null); setDiscoveryDecision(null); setCoverage(null); setEvidence(null);
    setLastTool(null); setApproval(null); setScanState("idle"); setCurrentPhase("");
    connect();
    return true;
  }, [connect, scanState, send]);

  return { connected, logs, findings, scanState, currentPhase, lastTool, approval, report, toolOutput, loot, exploitationApproved, exploitDecision, discoveryDecision, coverage, evidence, approveFindingForExploitation, skipExploitation, send, setScanState, setApproval, newScan };
}

function StatusDot({ color, pulse }) {
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: color, boxShadow: pulse ? `0 0 8px ${color}` : "none", animation: pulse ? "pulse 2s infinite" : "none" }} />;
}

function SeverityBadge({ severity }) {
  const c = sev_colors[severity] || theme.info;
  return <span style={{ display: "inline-block", padding: "2px 10px", borderRadius: 4, background: `${c}22`, color: c, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, border: `1px solid ${c}44` }}>{severity}</span>;
}

function Terminal({ lines }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines]);
  return (
    <div ref={ref} style={{ background: theme.terminal, padding: 12, fontFamily: "ui-monospace,SFMono-Regular,Menlo,Monaco,monospace", fontSize: 12, lineHeight: 1.6, color: theme.green, height: "100%", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
      {lines.map((l, i) => (
        <div key={i} style={{ color: typeof l === "string" ? theme.green : getLogColor(l.type) }}>
          {typeof l === "string" ? l : <><span style={{ color: theme.textDim }}>[{l.ts}]</span> {l.message}</>}
        </div>
      ))}
      <span style={{ animation: "blink 1s infinite" }}>▌</span>
    </div>
  );
}

const inputStyle = { width: "100%", padding: "10px 14px", background: "#0a0e17", border: "1px solid #1e293b", borderRadius: 6, color: "#e2e8f0", fontSize: 14, outline: "none" };
function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: "block", fontSize: 12, color: "#64748b", marginBottom: 6, fontWeight: 600 }}>{label}</label>
      {children}
    </div>
  );
}
function pillBtn(color) {
  return { padding: "4px 12px", background: `${color}22`, color, border: `1px solid ${color}44`, borderRadius: 4, fontSize: 11, fontWeight: 600, cursor: "pointer" };
}

function EvidenceTrail({ snapshot, coverage, decision, onRetry, onContinue, onRefresh, onOpenReport }) {
  const currentCoverage = coverage || snapshot?.coverage;
  const runs = snapshot?.tool_runs || [];
  const rangeText = ranges => (ranges || []).map(item => item.start === item.end ? `${item.start}` : `${item.start}–${item.end}`).join(", ") || "none";
  const stageLabels = {
    tcp_observation: "TCP observed",
    tcp_observed: "TCP observed",
    protocol_confirmed: "Protocol confirmed",
    evidence_backed_finding: "Evidence-backed finding",
    cve_candidate: "CVE candidate",
    active_confirmation: "Active validation confirmed",
  };
  const limited = currentCoverage?.status === "partial" || currentCoverage?.status === "pending";

  return (
    <div style={{ height: "100%", overflowY: "auto", padding: 18, background: theme.surface, fontSize: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700 }}>Evidence trail</div>
          <div style={{ color: theme.textDim, marginTop: 3 }}>Scanner coverage → TCP observation → protocol verification → finding or active confirmation. Raw response bodies and exact secrets are not included here.</div>
        </div>
        <button onClick={onRefresh} style={pillBtn(theme.accent)}>Refresh</button>
      </div>

      <div style={{ padding: 12, border: `1px solid ${limited ? theme.high : theme.border}`, borderRadius: 6, background: limited ? `${theme.high}12` : theme.bg, marginBottom: 14 }}>
        <div style={{ fontWeight: 700, color: limited ? theme.high : theme.text, marginBottom: 6 }}>TCP discovery coverage: {(currentCoverage?.status || "not started").replaceAll("_", " ").toUpperCase()}</div>
        {(currentCoverage?.hosts || []).map(item => (
          <div key={item.host} style={{ padding: "8px 0", borderTop: `1px solid ${theme.border}`, lineHeight: 1.5 }}>
            <b>{item.host}</b> · {item.method} · {item.completed_port_count.toLocaleString()} / {item.requested_port_count.toLocaleString()} planned TCP ports in completed scanner passes
            <div style={{ color: theme.textDim }}>Observed accepting ports: {(item.observed_ports || []).join(", ") || "none"}</div>
            {!!item.incomplete_ranges?.length && <div style={{ color: theme.high }}>Unfinished ranges: {rangeText(item.incomplete_ranges)}</div>}
            {item.note && <div style={{ color: theme.textDim }}>{item.note}</div>}
          </div>
        ))}
        {!currentCoverage?.hosts?.length && <div style={{ color: theme.textDim }}>No per-host discovery result yet.</div>}
      </div>

      {decision && (
        <div role="alert" style={{ padding: 12, border: `1px solid ${theme.high}`, borderRadius: 6, background: `${theme.high}18`, marginBottom: 14 }}>
          <div style={{ fontWeight: 700, color: theme.high, marginBottom: 5 }}>Discovery needs a decision</div>
          <div style={{ marginBottom: 9 }}>The scan is paused before service checks. Retry only the unfinished windows, or continue investigating observed ports with a PARTIAL final outcome.</div>
          <div style={{ color: theme.textDim, marginBottom: 9 }}>A brief UI reload can reattach; closing the app or waiting over one minute requires a fresh scan. Previous port observations are never reused as current coverage after a backend restart.</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {decision.can_retry && <button onClick={onRetry} style={pillBtn(theme.accent)}>Retry unfinished windows</button>}
            <button onClick={onContinue} style={pillBtn(theme.high)}>Continue with partial coverage</button>
          </div>
        </div>
      )}

      <div style={{ marginBottom: 14, padding: 12, border: `1px solid ${theme.border}`, borderRadius: 6, background: theme.bg }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Service observations ({snapshot?.services?.length || 0})</div>
        {!snapshot?.services?.length && <div style={{ color: theme.textDim }}>No TCP listener has been observed yet. This is not a negative result while discovery remains incomplete.</div>}
        {(snapshot?.services || []).slice(0, 200).map(item => (
          <div key={`${item.host}:${item.port}`} style={{ borderTop: `1px solid ${theme.border}`, padding: "7px 0", lineHeight: 1.5 }}>
            <b>{item.host}:{item.port}/tcp</b> · {item.label} · <span style={{ color: item.stage === "protocol_confirmed" ? theme.green : theme.high }}>{stageLabels[item.stage] || item.stage}</span>
            <div style={{ color: theme.textDim }}>{item.verification} · source run{item.source_runs.length === 1 ? "" : "s"}: {item.source_runs.map(index => `#${index + 1}`).join(", ") || "not linked"}</div>
          </div>
        ))}
        {(snapshot?.services?.length || 0) > 200 && <div style={{ color: theme.high }}>Showing 200 services here; the full service table is in the report.</div>}
      </div>

      <div style={{ marginBottom: 14, padding: 12, border: `1px solid ${theme.border}`, borderRadius: 6, background: theme.bg }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Findings and proof state ({snapshot?.findings?.length || 0})</div>
        {!snapshot?.findings?.length && <div style={{ color: theme.textDim }}>No evidence-backed finding has been recorded.</div>}
        {(snapshot?.findings || []).slice(0, 200).map(item => (
          <div key={item.id} style={{ borderTop: `1px solid ${theme.border}`, padding: "7px 0", lineHeight: 1.5 }}>
            <b>{item.title}</b> · <span style={{ color: item.stage === "active_confirmation" ? theme.green : theme.accent }}>{stageLabels[item.stage] || item.stage}</span>
            <div style={{ color: theme.textDim }}>{item.severity.toUpperCase()} · {item.target || snapshot.target} · {item.tool} · source run{item.source_runs.length === 1 ? "" : "s"}: {item.source_runs.map(index => `#${index + 1}`).join(", ") || "not linked"}</div>
          </div>
        ))}
        {(snapshot?.findings?.length || 0) > 200 && <div style={{ color: theme.high }}>Showing 200 findings here; the full finding list is in the report.</div>}
        {!!snapshot?.findings?.length && <button onClick={onOpenReport} style={{ ...pillBtn(theme.accent), marginTop: 9 }}>Open report with redacted evidence</button>}
      </div>

      <details style={{ padding: 12, border: `1px solid ${theme.border}`, borderRadius: 6, background: theme.bg }}>
        <summary style={{ cursor: "pointer", fontWeight: 700 }}>Tool-run provenance ({runs.length})</summary>
        {runs.map(item => (
          <div key={item.index} style={{ borderTop: `1px solid ${theme.border}`, padding: "6px 0", color: theme.textDim }}>
            #{item.index + 1} {item.tool} · {item.phase} · {item.result} · {item.duration.toFixed(1)}s{item.observed_ports.length ? ` · observed ports ${item.observed_ports.join(", ")}` : ""}
          </div>
        ))}
      </details>
    </div>
  );
}

function NetworkAssessment({ onOpenApplicationResearch }) {
  const agent = useAgent();
  const {
    loot,
    exploitationApproved,
    exploitDecision,
    discoveryDecision,
    approveFindingForExploitation,
    skipExploitation,
  } = agent; // Phase 2: strict separation + loot
  const actionableFindings = agent.findings.filter(f =>
    (f.permitted_tools || []).length > 0
    && !exploitationApproved.some(item => item.id === f.id)
  );
  const exploitConfirmations = agent.findings.filter(f => f.phase === "exploit");
  const [target, setTarget] = useState("");
  const [lmUrl, setLmUrl] = useState("http://localhost:1234");
  const [model, setModel] = useState("");
  const [models, setModels] = useState([]);
  const [modelsLoading, setModelsLoading] = useState(true);
  const [modelsError, setModelsError] = useState("");
  const [modelsRefresh, setModelsRefresh] = useState(0);
  const [mode, setMode] = useState("supervised");
  const [phases, setPhases] = useState(["recon", "web", "network", "osint", "exploit"]);
  const [scope, setScope] = useState("");
  const [activeTab, setActiveTab] = useState("terminal");
  const [chatMsg, setChatMsg] = useState("");
  const [showConfig, setShowConfig] = useState(true);
  const [envStatus, setEnvStatus] = useState(null);
  const [useAi, setUseAi] = useState(true);  // false = preset / no-LLM mode
  const [installLogs, setInstallLogs] = useState([]);  // captured output from brew installs for visibility
  const [installingTools, setInstallingTools] = useState([]);
  const [installingAll, setInstallingAll] = useState(false);
  const [recoveryPlan, setRecoveryPlan] = useState(null);
  const [recoveryPrepared, setRecoveryPrepared] = useState(false);
  const [confirmedRecoveryConfig, setConfirmedRecoveryConfig] = useState("");
  const recoveryConfig = JSON.stringify({ target, scope, mode, phases, useAi, model: useAi ? model : "" });
  const recoveryAuthorized = !recoveryPrepared || confirmedRecoveryConfig === recoveryConfig;

  useEffect(() => {
    const controller = new AbortController();
    apiFetch("/api/scan/recovery", { signal: controller.signal })
      .then(async response => response.ok ? response.json() : { interrupted: [] })
      .then(data => setRecoveryPlan((data.interrupted || [])[0] || null))
      .catch(error => { if (error.name !== "AbortError") setRecoveryPlan(null); });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (exploitDecision) setActiveTab("exploitation");
  }, [exploitDecision]);

  useEffect(() => {
    if (discoveryDecision) {
      setActiveTab("evidence");
      agent.send({ action: "evidence" });
    }
  }, [discoveryDecision]);

  useEffect(() => {
    const controller = new AbortController();
    setModelsLoading(true);
    setModelsError("");
    apiFetch(`/api/models?lm_url=${encodeURIComponent(lmUrl)}`, { signal: controller.signal })
      .then(async response => {
        const data = await response.json();
        if (!response.ok || data.error) throw new Error(data.error || `HTTP ${response.status}`);
        return data;
      })
      .then(data => {
        const available = (data.data || []).filter(item => item?.id);
        const ids = available.map(item => item.id);
        setModels(available);
        const safeModels = available.filter(item => !/(abliterated|uncensored|unfiltered)/i.test(`${item.id} ${item.display_name || ""}`));
        const preferred =
          safeModels.find(item => item.id.toLowerCase().includes("qwen3.5-9b"))?.id ||
          safeModels.find(item => item.id.toLowerCase().includes("gpt-oss-20b"))?.id ||
          safeModels.find(item => item.trained_for_tool_use)?.id ||
          safeModels[0]?.id ||
          ids[0] ||
          "";
        setModel(current => current && ids.includes(current) ? current : preferred);
      })
      .catch(error => {
        if (error.name === "AbortError") return;
        setModels([]);
        setModel("");
        setModelsError(error.message || "Local LLM provider is unavailable");
      })
      .finally(() => {
        if (!controller.signal.aborted) setModelsLoading(false);
      });

    // Fetch environment status (tools + LM Studio reachability + wordlists)
    // This helps the desktop app show friendly messages when things are missing.
    apiFetch(`/api/environment?lm_url=${encodeURIComponent(lmUrl)}`, { signal: controller.signal })
      .then(r => r.json())
      .then(setEnvStatus)
      .catch(error => { if (error.name !== "AbortError") setEnvStatus(null); });
    return () => controller.abort();
  }, [lmUrl, modelsRefresh]);

  useEffect(() => {
    if (["complete", "partial", "inconclusive"].includes(agent.scanState)) {
      agent.send({ action: "report" });
      setActiveTab(current => current === "evidence" ? current : "report");
    }
  }, [agent.scanState]);

  useEffect(() => {
    if (!["idle", "starting"].includes(agent.scanState)) setShowConfig(false);
  }, [agent.scanState]);

  useEffect(() => {
    if (["running", "paused", "complete", "partial", "inconclusive"].includes(agent.scanState)) {
      setRecoveryPlan(null);
    }
  }, [agent.scanState]);

  const startScan = () => {
    if (!target || !agent.connected || phases.length === 0 || (useAi && !model) || agent.scanState === "starting" || !recoveryAuthorized) return;
    const sent = agent.send({
      action: "start_scan",
      target,
      scope,
      mode,
      phases,
      lm_studio_url: lmUrl,
      model,
      llm_enabled: useAi
    });
    if (sent) agent.setScanState("starting");
  };

  const togglePhase = (p) => setPhases(prev => prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]);
  const sendChat = () => { if (!chatMsg.trim()) return; agent.send({ action: "message", message: chatMsg }); setChatMsg(""); };

  const refreshEnvironment = async () => {
    try {
      const response = await apiFetch(`/api/environment?lm_url=${encodeURIComponent(lmUrl)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || data.error || `HTTP ${response.status}`);
      setEnvStatus(data);
      return data;
    } catch (error) {
      setInstallLogs(prev => [...prev, `[diagnostics] Refresh failed: ${error.message || error}`]);
      return null;
    }
  };

  const installOneTool = async (toolName, refreshAfter = true) => {
    const guidance = envStatus?.install_guidance?.[toolName] || {};
    if (guidance.automatic === false) {
      const manual = guidance.manual_command
        ? `\nManual installation:\n${guidance.manual_command}`
        : "";
      setInstallLogs(prev => [
        ...prev,
        `[${toolName}] MANUAL SETUP REQUIRED\n${guidance.note || "AEGIS cannot safely install this tool automatically."}${manual}`,
      ]);
      return false;
    }
    setInstallingTools(prev => prev.includes(toolName) ? prev : [...prev, toolName]);
    setInstallLogs(prev => [...prev, `[${toolName}] Starting automatic setup…`]);
    let success = false;
    try {
      const response = await apiFetch(`/api/install-tool?name=${encodeURIComponent(toolName)}`, { method: "POST" });
      let data;
      try {
        data = await response.json();
      } catch {
        data = { error: `Installer returned HTTP ${response.status} without a JSON response.` };
      }
      success = response.ok && data.success === true;
      const manualCommand = data.manual_command || guidance.manual_command;
      const details = data.output || data.error || (success ? "Tool passed setup." : "Installer did not report a reason.");
      const manual = !success && manualCommand ? `\nManual installation:\n${manualCommand}` : "";
      setInstallLogs(prev => [
        ...prev,
        `[${toolName}] ${success ? "SUCCESS" : "FAILED"}${data.command ? ` (${data.command})` : ""}\n${details}${manual}`,
      ]);
    } catch (error) {
      const manual = guidance.manual_command ? `\nManual installation:\n${guidance.manual_command}` : "";
      setInstallLogs(prev => [...prev, `[${toolName}] FAILED\n${error.message || error}${manual}`]);
    } finally {
      setInstallingTools(prev => prev.filter(name => name !== toolName));
      if (refreshAfter) await refreshEnvironment();
    }
    return success;
  };

  const installAllMissingTools = async () => {
    const seenInstallCommands = new Set();
    const allMissing = envStatus?.missing_tools || [];
    const missing = allMissing.filter(toolName => {
      if (envStatus?.install_guidance?.[toolName]?.automatic === false) return false;
      const key = envStatus?.install_guidance?.[toolName]?.manual_command || toolName;
      if (seenInstallCommands.has(key)) return false;
      seenInstallCommands.add(key);
      return true;
    });
    const manualOnly = allMissing.filter(
      toolName => envStatus?.install_guidance?.[toolName]?.automatic === false
    );
    if (!allMissing.length || installingAll) return;
    setInstallingAll(true);
    try {
      for (const toolName of missing) {
        await installOneTool(toolName, false);
      }
      for (const toolName of manualOnly) {
        await installOneTool(toolName, false);
      }
      await refreshEnvironment();
    } finally {
      setInstallingAll(false);
    }
  };

  const downloadReport = () => {
    if (!agent.report) return;
    const blob = new Blob([agent.report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-report-${(target || "scan").replace(/[^a-z0-9.-]/gi, "_")}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const critC = agent.findings.filter(f => f.severity === "critical").length;
  const highC = agent.findings.filter(f => f.severity === "high").length;
  const medC = agent.findings.filter(f => f.severity === "medium").length;
  const latestStartError = [...agent.logs].reverse().find(item => item.type === "error")?.message;

  return (
    <div style={{ background: theme.bg, color: theme.text, height: "100vh", fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif", display: "flex", flexDirection: "column" }}>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: ${theme.bg}; }
        ::-webkit-scrollbar-thumb { background: ${theme.border}; border-radius: 3px; }
        @keyframes pulse { 0%,100%{opacity:1}50%{opacity:0.5} }
        @keyframes blink { 0%,100%{opacity:1}50%{opacity:0} }
        @keyframes slideIn { from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)} }
        input, textarea, select { font-family: inherit; }
        select option { background: ${theme.bg}; color: ${theme.text}; }
        button { cursor: pointer; font-family: inherit; }
      `}</style>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 24px", borderBottom: `1px solid ${theme.border}`, background: "linear-gradient(180deg,#111827 0%,#0a0e17 100%)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={theme.accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2l7 4v6c0 5-3.5 9-7 10-3.5-1-7-5-7-10V6l7-4z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          <div style={{ fontSize: 22, fontWeight: 700 }}>AEGIS</div>
          <span style={{ color: theme.textDim, fontSize: 12 }}>AI Pentest Agent</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 12 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <StatusDot color={agent.connected ? theme.green : theme.critical} pulse={agent.connected} />
            {agent.connected ? "Connected" : "Disconnected"}
          </span>
          {!showConfig && agent.currentPhase && <span style={{ display: "flex", alignItems: "center", gap: 6 }}><StatusDot color={theme.accent} pulse /> Phase: <b>{agent.currentPhase}</b></span>}
          {!showConfig && <span style={{ display: "flex", gap: 8 }}>
            {critC > 0 && <span style={{ color: theme.critical, fontWeight: 700 }}>🔴 {critC}</span>}
            {highC > 0 && <span style={{ color: theme.high, fontWeight: 700 }}>🟠 {highC}</span>}
            {medC > 0 && <span style={{ color: theme.medium, fontWeight: 700 }}>🟡 {medC}</span>}
          </span>}
        </div>
      </div>

      {/* Config */}
      {showConfig && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto", display: "flex", alignItems: "flex-start", justifyContent: "center", padding: "20px 0" }}>
          <div style={{ width: 560, padding: 32, background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 12, animation: "slideIn 0.3s ease" }}>
            <div role="tablist" aria-label="Start menu" style={{ display: "flex", gap: 4, margin: "-16px -16px 22px", padding: 4, background: theme.bg, borderRadius: 8 }}>
              <button
                role="tab"
                aria-selected="true"
                type="button"
                style={{ flex: 1, padding: "8px 12px", background: theme.accentGlow, color: theme.accent, border: `1px solid ${theme.accent}`, borderRadius: 6, fontWeight: 700 }}
              >
                ⚡ New Engagement
              </button>
              <button
                role="tab"
                aria-selected="false"
                type="button"
                onClick={() => { setActiveTab("diagnostics"); setShowConfig(false); }}
                style={{ flex: 1, padding: "8px 12px", background: "transparent", color: theme.textDim, border: `1px solid ${theme.border}`, borderRadius: 6, fontWeight: 700 }}
              >
                🧰 Diagnostics & Tools
              </button>
              <button
                role="tab"
                aria-selected="false"
                type="button"
                onClick={onOpenApplicationResearch}
                style={{ flex: 1, padding: "8px 12px", background: "transparent", color: theme.textDim, border: `1px solid ${theme.border}`, borderRadius: 6, fontWeight: 700 }}
              >
                ◫ Application Research
              </button>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 24 }}><span style={{ color: theme.accent }}>⚡</span> New Engagement</h2>

            {recoveryPlan && <div role="status" style={{ padding: 12, marginBottom: 16, border: `1px solid ${theme.high}`, borderRadius: 6, background: `${theme.high}12`, fontSize: 12, lineHeight: 1.5 }}>
              <b>Previous scan was interrupted</b>
              <div>{recoveryPlan.target} · last recorded TCP coverage: {recoveryPlan.coverage.toUpperCase()} ({recoveryPlan.completed_ports.toLocaleString()} / {recoveryPlan.requested_ports.toLocaleString()} planned ports in completed scanner passes).</div>
              <div style={{ color: theme.textDim, marginTop: 4 }}>This is historical metadata only. No port results, findings, approvals, or credentials were restored. A new scan starts in supervised recon-only mode, requires fresh scope authorization, and reruns discovery.</div>
              <div style={{ display: "flex", gap: 8, marginTop: 9 }}>
                <button type="button" onClick={() => { setTarget(recoveryPlan.target); setScope(""); setMode("supervised"); setPhases(["recon"]); setUseAi(false); setRecoveryPrepared(true); setConfirmedRecoveryConfig(""); }} style={pillBtn(theme.accent)}>Prepare fresh scan</button>
                <button type="button" onClick={async () => { const response = await apiFetch(`/api/scan/recovery/${recoveryPlan.scan_id}`, { method: "DELETE" }); if (response.ok) { setRecoveryPlan(null); setRecoveryPrepared(false); } }} style={pillBtn(theme.textDim)}>Dismiss notice</button>
              </div>
            </div>}

            <Field label="TARGET *">
              <input value={target} onChange={e => setTarget(e.target.value)}
                placeholder="192.168.1.100, example.com, my network, the router..."
                style={inputStyle} />
            </Field>

            <Field label="LOCAL LLM SERVER URL (LOOPBACK ONLY)">
              <input value={lmUrl} onChange={e => setLmUrl(e.target.value)} placeholder="http://localhost:1234" style={inputStyle} />
            </Field>

            <Field label={`MODEL ${models.length > 0 ? `(${models.length} available)` : ""}`}>
              <div style={{ display: "flex", gap: 8 }}>
                <select
                  value={model}
                  onChange={e => setModel(e.target.value)}
                  disabled={modelsLoading || models.length === 0}
                  style={{ ...inputStyle, WebkitAppearance: "auto", appearance: "auto", flex: 1, opacity: modelsLoading || models.length === 0 ? 0.65 : 1 }}
                >
                  {modelsLoading && <option value="">Loading models from local provider…</option>}
                  {!modelsLoading && models.length === 0 && <option value="">No LLM models available</option>}
                  {models.map(item => (
                    <option key={item.id} value={item.id}>
                      {item.loaded ? "● " : ""}{item.display_name || item.id}{item.display_name && item.display_name !== item.id ? ` — ${item.id}` : ""}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => setModelsRefresh(value => value + 1)}
                  disabled={modelsLoading}
                  style={{ ...pillBtn(theme.accent), padding: "8px 12px", opacity: modelsLoading ? 0.6 : 1 }}
                >
                  Refresh
                </button>
              </div>
              {modelsError && <div style={{ fontSize: 11, color: theme.critical, marginTop: 6 }}>Local provider: {modelsError}</div>}
              <div style={{ fontSize: 11, color: theme.textDim, marginTop: 6, lineHeight: 1.4 }}>
                LM Studio loaded models are marked ●. Generic OpenAI-compatible providers manage their own model lifecycle.
              </div>
            </Field>

            <Field label="SCOPE NOTES / TCP PORTS">
              <textarea value={scope} onChange={e => setScope(e.target.value)} rows={2}
                placeholder="e.g. 443  •  all ports  •  Exclude 10.0.0.5  •  investigate CVE-2025-40833"
                style={{ ...inputStyle, resize: "vertical" }} />
              <div style={{ fontSize: 11, color: theme.textDim, marginTop: 6, lineHeight: 1.4 }}>
                Ports are checked exactly with Nmap. Any CVE IDs entered here become mandatory official-record lookups with product/version correlation; denial-of-service triggers are not sent automatically.
              </div>
              <div style={{ fontSize: 11, color: theme.textDim, marginTop: 4, lineHeight: 1.4 }}>
                Product fingerprinting covers hypervisors, BMC/server controllers, network appliances, and common server applications. Identification and CVE correlation are deterministic and also run with AI mode disabled.
              </div>
              <div style={{ fontSize: 11, color: scope.trim() ? theme.accent : theme.textDim, marginTop: 4, lineHeight: 1.4 }}>
                Submitted scope: {scope.trim() || "automatic port discovery"}
              </div>
            </Field>

            <Field label="AGENT MODE">
              <div style={{ display: "flex", gap: 8 }}>
                {[{ id: "autonomous", label: "🤖 Autonomous", desc: "Auto investigation + exploits" }, { id: "supervised", label: "👁️ Supervised", desc: "Approve exploits" }, { id: "manual", label: "🔒 Manual", desc: "Approve every tool" }].map(m => (
                  <button key={m.id} onClick={() => setMode(m.id)} style={{ flex: 1, padding: "10px 8px", background: mode === m.id ? theme.accentGlow : theme.bg, border: `1px solid ${mode === m.id ? theme.accent : theme.border}`, borderRadius: 6, color: mode === m.id ? theme.accent : theme.textDim, fontSize: 13, fontWeight: 600, textAlign: "center" }}>
                    {m.label}<br /><span style={{ fontSize: 10, fontWeight: 400 }}>{m.desc}</span>
                  </button>
                ))}
              </div>
            </Field>

            <Field label="AI BRAIN">
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button
                  onClick={() => setUseAi(true)}
                  style={{ flex: 1, padding: "8px", background: useAi ? theme.accentGlow : theme.bg, border: `1px solid ${useAi ? theme.accent : theme.border}`, borderRadius: 6, color: useAi ? theme.accent : theme.textDim, fontSize: 12, fontWeight: 600 }}
                >
                  🧠 AI Mode (needs local LLM)
                </button>
                <button
                  onClick={() => setUseAi(false)}
                  style={{ flex: 1, padding: "8px", background: !useAi ? theme.accentGlow : theme.bg, border: `1px solid ${!useAi ? theme.accent : theme.border}`, borderRadius: 6, color: !useAi ? theme.accent : theme.textDim, fontSize: 12, fontWeight: 600 }}
                >
                  🛠️ Preset Tools Only (no LLM)
                </button>
              </div>
              <div style={{ fontSize: 11, color: theme.textDim, marginTop: 4 }}>
                {!useAi && "Safe preset recon/tools will run automatically without calling the LLM."}
              </div>
            </Field>

            <Field label="PHASES">
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {["recon", "web", "network", "osint", "exploit"].map(p => (
                  <button key={p} onClick={() => togglePhase(p)} style={{ padding: "6px 14px", background: phases.includes(p) ? theme.accentGlow : theme.bg, border: `1px solid ${phases.includes(p) ? theme.accent : theme.border}`, borderRadius: 6, color: phases.includes(p) ? theme.accent : theme.textDim, fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>{p}</button>
                ))}
              </div>
            </Field>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: "#64748b", marginBottom: 4 }}>QUICK PRESETS (faster scans)</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button onClick={() => { setScope("light quick scan internal device"); setPhases(["recon", "network"]); setUseAi(false); }} style={{ padding: "4px 8px", fontSize: 11, background: "#1e293b", border: "1px solid #334155", borderRadius: 4, color: "#94a3b8" }}>Internal Device (fast, no LLM)</button>
                <button onClick={() => { setScope("only web ports 80,443"); setPhases(["recon", "web"]); setUseAi(true); }} style={{ padding: "4px 8px", fontSize: 11, background: "#1e293b", border: "1px solid #334155", borderRadius: 4, color: "#94a3b8" }}>Web App Focus</button>
                <button onClick={() => { setPhases(["recon", "web", "network", "osint", "exploit"]); setUseAi(true); }} style={{ padding: "4px 8px", fontSize: 11, background: "#1e293b", border: "1px solid #334155", borderRadius: 4, color: "#94a3b8" }}>Full Phases</button>
              </div>
            </div>

            {envStatus && !envStatus.lm_studio?.reachable && (
              <div style={{ background: "#3b1f1f", color: "#fca5a5", padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 12 }}>
                ⚠️ Local LLM provider not reachable at {lmUrl}. Start the provider and make the selected model available first.
              </div>
            )}
            {envStatus && envStatus.missing_tools?.length > 5 && (
              <div style={{ background: "#3b2f1f", color: "#fcd34d", padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 12 }}>
                Many tools missing ({envStatus.missing_tools.length}). Most scans will be limited. Open Diagnostics and click "Install / setup all missing tools".
              </div>
            )}
            {agent.scanState === "error" && latestStartError && (
              <div style={{ background: "#3b1f1f", color: "#fca5a5", padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 12 }}>
                Could not start scan: {latestStartError}
              </div>
            )}
            {recoveryPrepared && <label style={{ display: "flex", alignItems: "flex-start", gap: 8, color: theme.high, fontSize: 12, lineHeight: 1.5, marginTop: 10 }}>
              <input type="checkbox" checked={recoveryAuthorized} onChange={event => setConfirmedRecoveryConfig(event.target.checked ? recoveryConfig : "")} />
              I reauthorize this target, scope, and phase selection for a fresh scan. Blank scope means automatic full-range discovery; no previous observations will be reused.
            </label>}
            <button
              onClick={startScan}
              disabled={!target || !agent.connected || phases.length === 0 || (useAi && !model) || agent.scanState === "starting" || !recoveryAuthorized}
              style={{
                width: "100%", padding: "12px 24px", marginTop: 8,
                background: target && agent.connected && phases.length > 0 && (!useAi || model) && agent.scanState !== "starting" && recoveryAuthorized ? theme.accent : theme.border,
                color: target && agent.connected && phases.length > 0 && (!useAi || model) && agent.scanState !== "starting" && recoveryAuthorized ? "#fff" : theme.textDim,
                border: "none", borderRadius: 8, fontSize: 14, fontWeight: 700,
              }}
            >
              {agent.scanState === "starting" ? "Loading selected model…" : agent.connected ? "⚡ LAUNCH SCAN" : "Waiting for local backend…"}
            </button>
          </div>
        </div>
      )}

      {/* Dashboard */}
      {!showConfig && (
        <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 340px", overflow: "hidden" }}>
          {/* Left */}
          <div style={{ display: "flex", flexDirection: "column", borderRight: `1px solid ${theme.border}`, overflow: "hidden" }}>
            <div style={{ display: "flex", borderBottom: `1px solid ${theme.border}`, background: theme.surfaceAlt, flexShrink: 0, alignItems: "flex-end", height: 38 }}>
              {["terminal", "output", "evidence", "exploitation", "diagnostics", "report"].map(tab => {
                const isActive = activeTab === tab;
                return (
                  <button key={tab} onClick={() => { setActiveTab(tab); if (tab === "evidence") agent.send({ action: "evidence" }); }} style={{
                    padding: "8px 16px",
                    paddingBottom: isActive ? 6 : 8,
                    background: "transparent",
                    border: "none",
                    borderBottom: isActive ? `3px solid ${theme.accent}` : "3px solid transparent",
                    color: isActive ? theme.text : theme.textDim,
                    fontSize: 13,
                    fontWeight: 600,
                    height: 38,
                    display: "flex",
                    alignItems: "center",
                    boxSizing: "border-box"
                  }}>
                    {tab === "exploitation" ? "💥 EXPLOITATION (gated)" : tab.charAt(0).toUpperCase() + tab.slice(1)}
                  </button>
                );
              })}
              <div style={{ marginLeft: "auto", display: "flex", gap: 8, padding: "6px 12px", alignItems: "center" }}>
                {["running", "paused"].includes(agent.scanState) && <button onClick={() => agent.send({ action: "stop" })} style={pillBtn(theme.critical)}>■ STOP</button>}
                <button onClick={() => { agent.send({ action: "report" }); setActiveTab("report"); }} style={pillBtn(theme.accent)}>📄 REPORT</button>
                {agent.report && <button onClick={downloadReport} style={pillBtn(theme.green)}>⬇️ DL .md</button>}
                <button onClick={async () => { if (await agent.newScan()) { setRecoveryPrepared(false); setConfirmedRecoveryConfig(""); setShowConfig(true); } }} style={pillBtn(theme.green)}>+ NEW</button>
              </div>
            </div>

            <div style={{ flex: 1, overflow: "hidden" }}>
              {activeTab === "terminal" && <Terminal lines={agent.logs} />}
              {activeTab === "output" && (
                <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
                  {agent.lastTool && (
                    <div style={{ padding: "8px 16px", background: theme.accentGlow, borderBottom: `1px solid ${theme.border}`, fontSize: 12, flexShrink: 0 }}>
                      {agent.lastTool.done ? "✓" : "⏳"} <b>{agent.lastTool.tool}</b> — {agent.lastTool.reasoning}
                    </div>
                  )}
                  <div style={{ flex: 1, overflow: "hidden" }}><Terminal lines={agent.toolOutput} /></div>
                </div>
              )}
              {activeTab === "evidence" && (
                <EvidenceTrail
                  snapshot={agent.evidence}
                  coverage={agent.coverage}
                  decision={discoveryDecision}
                  onRetry={() => agent.send({ action: "retry_discovery" })}
                  onContinue={() => agent.send({ action: "continue_partial" })}
                  onRefresh={() => agent.send({ action: "evidence" })}
                  onOpenReport={() => { agent.send({ action: "report" }); setActiveTab("report"); }}
                />
              )}
              {activeTab === "diagnostics" && (
                <div style={{ padding: 20, height: "100%", overflow: "auto", fontSize: 13 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                    <b>Environment & Diagnostics</b>
                    <button onClick={refreshEnvironment} style={{ ...pillBtn(theme.accent), fontSize: 11 }}>Refresh</button>
                  </div>

                  {!envStatus && <div>Loading environment status...</div>}

                  {envStatus && (
                    <>
                      <div style={{ marginBottom: 16, padding: 12, background: theme.bg, borderRadius: 6, border: `1px solid ${theme.border}` }}>
                        <div style={{ color: envStatus.lm_studio?.reachable ? theme.green : theme.critical, fontWeight: 600 }}>
                          Local LLM provider: {envStatus.lm_studio?.reachable ? "Reachable ✓" : "Not reachable ✗"}
                        </div>
                        {envStatus.lm_studio?.error && <div style={{ color: theme.critical, fontSize: 12 }}>{envStatus.lm_studio.error}</div>}
                        {envStatus.lm_studio?.models?.length > 0 && <div style={{ fontSize: 12, color: theme.textDim }}>Models: {envStatus.lm_studio.models.slice(0,3).join(", ")}{envStatus.lm_studio.models.length > 3 ? "..." : ""}</div>}
                        <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                          <button onClick={() => apiFetch("/api/lm/start-server", {method:"POST"}).then(()=> alert("LM server start requested. Check logs."))} style={pillBtn(theme.accent)}>Start LM Server (lms)</button>
                          <button onClick={() => apiFetch("/api/lm/launch-app", {method:"POST"})} style={pillBtn(theme.accent)}>Launch LM Studio App</button>
                        </div>
                      </div>

                      <div style={{ marginBottom: 16 }}>
                        <div style={{ fontWeight: 600, marginBottom: 6 }}>Tools ({(envStatus.missing_tools || []).length} missing)</div>
                        {(envStatus.missing_tools || []).length > 0 && (
                          <div style={{ fontSize: 12, color: theme.critical, marginBottom: 6 }}>
                            Missing: {(envStatus.missing_tools || []).join(", ")}
                          </div>
                        )}
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))", gap: 6 }}>
                          {Object.entries(envStatus.tools || {}).map(([name, avail]) => {
                            const installing = installingTools.includes(name);
                            const automatic = envStatus.install_guidance?.[name]?.automatic !== false;
                            return (
                            <button
                              key={name}
                              type="button"
                              disabled={avail || installing || installingAll}
                              onClick={() => installOneTool(name)}
                              title={avail ? `${name} is available` : automatic ? `Install or repair ${name}` : `Show setup instructions for ${name}`}
                              style={{
                                padding: "5px 8px",
                                background: theme.bg,
                                color: theme.text,
                                borderRadius: 4,
                                fontSize: 11,
                                display: "flex",
                                justifyContent: "space-between",
                                border: `1px solid ${avail ? theme.border : theme.critical}`,
                                cursor: avail || installing || installingAll ? "default" : "pointer",
                                opacity: installing || installingAll ? 0.7 : 1,
                              }}
                            >
                              <span>{name}</span>
                              <span style={{ color: avail ? theme.green : installing ? theme.accent : theme.critical }}>{avail ? "✓" : installing ? "…" : automatic ? "Install" : "Instructions"}</span>
                            </button>
                          )})}
                        </div>
                        {(envStatus.missing_tools || []).length > 0 && (
                          <div style={{ marginTop: 8 }}>
                            <button
                              onClick={installAllMissingTools}
                              disabled={installingAll || installingTools.length > 0}
                              style={{ ...pillBtn(theme.green), opacity: installingAll ? 0.7 : 1 }}
                            >
                              {installingAll ? "Installing missing tools…" : "Install / setup all missing tools"}
                            </button>
                            <div style={{ fontSize: 11, color: theme.textDim, marginTop: 4 }}>Click any red tool to install just that tool. Setup output appears immediately below; failed automatic installs include a manual command.</div>
                            <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
                              {(envStatus.missing_tools || []).map(name => {
                                const guidance = envStatus.install_guidance?.[name];
                                if (!guidance) return null;
                                return (
                                  <div key={name} style={{ padding: 8, background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 4, fontSize: 11 }}>
                                    <div><b>{name}</b> — {guidance.automatic ? "automatic setup supported" : "manual setup required"}</div>
                                    {guidance.manual_command && <code style={{ display: "block", marginTop: 4, color: theme.accent, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{guidance.manual_command}</code>}
                                    {guidance.note && <div style={{ marginTop: 3, color: theme.textDim }}>{guidance.note}</div>}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                        {installLogs.length > 0 && (
                          <pre style={{ fontSize: 10, background: theme.bg, padding: 8, marginTop: 8, maxHeight: 240, overflow: 'auto', whiteSpace: 'pre-wrap', border: `1px solid ${theme.border}` }}>
                            {installLogs.join('\n\n')}
                          </pre>
                        )}
                      </div>

                      <div>
                        <div style={{ fontWeight: 600, marginBottom: 6 }}>Wordlists (auto-download on first use if missing)</div>
                        {Object.entries(envStatus.wordlists || {}).map(([f, present]) => (
                          <div key={f} style={{ fontSize: 12 }}>{f}: {present ? "✓ present" : "will fetch automatically"}</div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
              {activeTab === "exploitation" && (
                <div style={{ padding: 16, height: "100%", minHeight: 0, overflowY: "auto", overscrollBehavior: "contain", boxSizing: "border-box", background: theme.surface, border: `1px solid ${theme.critical}`, borderRadius: 6, fontSize: 13 }}>
                  <div style={{ marginBottom: 8, fontWeight: 700, color: theme.critical, fontSize: 15 }}>💥 EXPLOITATION CONSOLE — NOTHING RUNS WITHOUT YOUR EXPLICIT ACCEPTANCE</div>
                  <div style={{ marginBottom: 12, padding: 8, background: "#2a1a1a", borderRadius: 4, fontSize: 12 }}>
                    {mode === "autonomous" ? (
                      <><b>Autonomous execution:</b> Investigation happens first. AEGIS then automatically runs every available action mapped to a real finding, without approval dialogs. Scope and tool safety limits still apply.</>
                    ) : (
                      <><b>Strict Separation:</b> Investigation happens first. Approve a mapped finding, then AEGIS will offer its exploit when the scan reaches this phase. The tool still cannot run until you accept the separate per-action confirmation.</>
                    )}
                  </div>

                  {exploitDecision && (
                    <div style={{ marginBottom: 12, padding: 10, background: `${theme.high}18`, border: `1px solid ${theme.high}`, borderRadius: 4 }}>
                      <div style={{ fontWeight: 700, color: theme.high, marginBottom: 5 }}>Operator decision required</div>
                      <div style={{ fontSize: 12, marginBottom: 9 }}>
                        The scan is paused because evidence-backed actions are available. Approve any finding below, or explicitly finish the assessment without exploitation.
                      </div>
                      <button
                        onClick={skipExploitation}
                        style={{ ...pillBtn(theme.textDim), padding: "6px 12px" }}
                      >
                        FINISH WITHOUT EXPLOITATION
                      </button>
                    </div>
                  )}

                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>Available Gated Actions ({actionableFindings.length}):</div>
                    {actionableFindings.length === 0 ? (
                      <span style={{ color: theme.textDim }}>No evidence-backed exploit or confirmation action is currently available.</span>
                    ) : actionableFindings.map(finding => (
                      <div key={finding.id} style={{ padding: 8, background: "#2a1a1a", border: `1px solid ${theme.critical}55`, borderRadius: 4, marginBottom: 6 }}>
                        <div style={{ fontWeight: 600 }}>{finding.title}</div>
                        <div style={{ fontSize: 11, color: theme.textDim, margin: "3px 0 6px" }}>
                          Tools: {(finding.permitted_tools || []).join(", ")}
                        </div>
                        <button
                          onClick={() => approveFindingForExploitation(finding)}
                          style={{ ...pillBtn(theme.critical), color: "white" }}
                        >
                          ⚠️ APPROVE MAPPED ACTIONS
                        </button>
                      </div>
                    ))}
                  </div>

                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>Approved for Exploitation ({exploitationApproved.length}):</div>
                    {exploitationApproved.length === 0 ? <span style={{ color: theme.textDim }}>None yet — approve from the Findings list in Investigation view.</span> :
                      exploitationApproved.map(item => (
                        <div key={item.id} style={{ fontSize: 12, background: "#1f2a1f", padding: "4px 6px", borderRadius: 3, marginBottom: 3 }}>
                          ✓ {item.title}
                          {item.tools.length > 0 && <span style={{ color: theme.textDim }}> — {item.tools.join(", ")}</span>}
                        </div>
                      ))}
                  </div>

                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>Confirmed by Active Validation ({exploitConfirmations.length}):</div>
                    {exploitConfirmations.length === 0 ? (
                      <span style={{ color: theme.textDim }}>No exploit-phase tool has confirmed a vulnerability yet.</span>
                    ) : exploitConfirmations.map(finding => (
                      <div key={finding.id} style={{ fontSize: 12, background: "#231b12", padding: "5px 7px", borderRadius: 3, marginBottom: 4 }}>
                        <b>{finding.title}</b>
                        {finding.target && <div style={{ color: theme.textDim }}>{finding.target}</div>}
                      </div>
                    ))}
                  </div>

                  <div style={{ marginBottom: 8, fontWeight: 600, color: theme.accent }}>🔐 Credentials / Access Obtained</div>
                  {loot.length === 0 ? <div style={{ color: theme.textDim }}>None. Successful vulnerability validation appears above; it does not imply that credentials, a session, a shell, or files were obtained.</div> :
                    loot.map((l, i) => (
                      <div key={i} style={{ padding: "6px 8px", background: "#0f1623", marginBottom: 4, borderRadius: 4, fontFamily: "monospace", fontSize: 12 }}>
                        <b>{l.type}</b> {l.service ? `[${l.service}]` : ""} on {l.host || "?"}
                        {l.username && l.password && <> : <span style={{color: theme.green}}>{l.username}:{l.password}</span></>}
                        {l.details && <div style={{color: theme.textDim}}>{l.details}</div>}
                        <div style={{fontSize:10, color: theme.textDim}}>from {l.source}</div>
                      </div>
                    ))
                  }

                  <div style={{ marginTop: 12, fontSize: 11, color: theme.textDim, borderTop: `1px solid ${theme.border}`, paddingTop: 8 }}>
                    AEGIS pauses here when mapped actions exist. Approving a finding resumes this phase and presents the separate per-action confirmation; approving after an older completed scan reopens only this phase. Every exploit remains scope-checked and logged.
                    <div style={{ marginTop: 5 }}>After completion, ask naturally about findings or extracted credentials for a brief local-LLM answer grounded in captured evidence. Ask “show all raw extracted credentials and evidence” only when you want the full exact export. Raw evidence remains local and is never copied into routine reports.</div>
                  </div>
                </div>
              )}
              {activeTab === "report" && (
                <div style={{ padding: 24, fontFamily: "ui-monospace,SFMono-Regular,Menlo,Monaco,monospace", fontSize: 13, lineHeight: 1.8, whiteSpace: "pre-wrap", height: "100%", overflow: "auto", position: "relative" }}>
                  <div style={{ position: "sticky", top: 0, background: theme.surfaceAlt, padding: "4px 8px", marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span>Report</span>
                    {agent.report && <button onClick={downloadReport} style={{ ...pillBtn(theme.accent), fontSize: 11 }}>Download .md</button>}
                  </div>
                  {agent.report || "Click REPORT to generate."}
                </div>
              )}
            </div>

            <div style={{ padding: "8px 12px", borderTop: `1px solid ${theme.border}`, display: "flex", gap: 8, flexShrink: 0 }}>
              <input value={chatMsg} onChange={e => setChatMsg(e.target.value)}
                onKeyDown={e => e.key === "Enter" && sendChat()}
                placeholder="Send a message to the agent... (type 'stop' to halt)"
                style={{ flex: 1, padding: "8px 12px", background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 6, color: theme.text, fontSize: 13, outline: "none" }} />
              <button onClick={sendChat} style={{ padding: "8px 16px", background: theme.accent, color: "#fff", border: "none", borderRadius: 6, fontSize: 13, fontWeight: 600 }}>Send</button>
            </div>
          </div>

          {/* Right Sidebar */}
          <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {agent.approval && (
              <div style={{ padding: 16, background: `${theme.high}11`, borderBottom: `1px solid ${theme.high}44`, animation: "slideIn 0.3s ease", flexShrink: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: theme.high, marginBottom: 8 }}>⚠️ APPROVAL REQUIRED</div>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{agent.approval.tool}</div>
                <div style={{ fontSize: 11, color: theme.textDim, marginBottom: 12 }}>{agent.approval.reasoning}</div>
                <div style={{ fontSize: 10, color: theme.textDim, marginBottom: 12, wordBreak: "break-all" }}>
                  {JSON.stringify(Object.fromEntries(Object.entries(agent.approval.params || {}).filter(([key]) => key !== "password")))}
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button onClick={() => { agent.send({ action: "approve" }); agent.setApproval(null); agent.setScanState("running"); }} style={{ flex: 1, padding: 8, background: theme.green, color: "#fff", border: "none", borderRadius: 4, fontSize: 12, fontWeight: 700 }}>✓ APPROVE</button>
                  <button onClick={() => { agent.send({ action: "reject" }); agent.setApproval(null); agent.setScanState("running"); }} style={{ flex: 1, padding: 8, background: theme.critical, color: "#fff", border: "none", borderRadius: 4, fontSize: 12, fontWeight: 700 }}>✗ REJECT</button>
                </div>
              </div>
            )}

            <div style={{ padding: 16, borderBottom: `1px solid ${theme.border}`, flexShrink: 0 }}>
              <div style={{ fontSize: 12, color: theme.textDim, fontWeight: 600, marginBottom: 8, letterSpacing: 1, textTransform: "uppercase" }}>📊 Scan Stats</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {[
                  { l: "Status", v: agent.scanState.toUpperCase(), c: agent.scanState === "running" ? theme.green : agent.scanState === "paused" ? theme.high : agent.scanState === "complete" ? theme.accent : ["partial", "inconclusive"].includes(agent.scanState) ? theme.high : theme.textDim },
                  { l: "Phase", v: agent.currentPhase || "—", c: theme.accent },
                  { l: "Findings", v: agent.findings.length, c: agent.findings.length > 0 ? theme.high : theme.textDim },
                  { l: "Logs", v: agent.logs.length, c: theme.textDim },
                ].map(s => (
                  <div key={s.l} style={{ padding: "8px 10px", background: theme.bg, borderRadius: 6, border: `1px solid ${theme.border}` }}>
                    <div style={{ fontSize: 10, color: theme.textDim, fontWeight: 600 }}>{s.l}</div>
                    <div style={{ fontSize: 16, fontWeight: 700, color: s.c }}>{s.v}</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ flex: 1, overflow: "auto" }}>
              <div style={{ padding: "10px 16px", borderBottom: `1px solid ${theme.border}`, background: theme.surfaceAlt }}>
                <span style={{ color: theme.textDim, fontSize: 12, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase" }}>🎯 Findings</span>
              </div>
              <div style={{ padding: 8 }}>
                {agent.findings.length === 0 && <div style={{ padding: 24, textAlign: "center", color: ["inconclusive", "partial"].includes(agent.scanState) ? theme.high : theme.textDim, fontSize: 13 }}>{agent.scanState === "inconclusive" ? "Assessment incomplete — see Report for the network-path diagnosis." : agent.scanState === "partial" ? "No findings in completed checks; TCP discovery was incomplete. See Evidence and Report." : "No findings yet..."}</div>}
                {agent.findings.map((f, i) => {
                  const isApproved = exploitationApproved.some(item => item.id === f.id);
                  const canApprove = (f.permitted_tools || []).length > 0 && !isApproved;
                  return (
                    <div key={i} style={{ padding: 12, marginBottom: 6, background: theme.bg, borderRadius: 6, border: `1px solid ${theme.border}`, borderLeft: `3px solid ${sev_colors[f.severity] || theme.info}`, animation: "slideIn 0.3s ease" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                        <SeverityBadge severity={f.severity} />
                        <span style={{ fontSize: 10, color: theme.textDim }}>{f.phase}</span>
                        {isApproved && <span style={{ fontSize: 10, background: theme.high, color: "#000", padding: "1px 6px", borderRadius: 3, fontWeight: 700 }}>EXPLOITATION APPROVED</span>}
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{f.title}</div>
                      {f.target && <div style={{ fontSize: 10, color: theme.accent, marginBottom: 4 }}>Host: {f.target}</div>}
                      <div style={{ fontSize: 11, color: theme.textDim, lineHeight: 1.5 }}>{(f.description || "").substring(0, 120)}{(f.description || "").length > 120 ? "..." : ""}</div>
                      {canApprove && (
                        <button
                          onClick={() => approveFindingForExploitation(f)}
                          style={{ marginTop: 8, padding: "4px 10px", fontSize: 11, background: theme.critical, color: "white", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}
                        >
                          ⚠️ APPROVE FOR EXPLOITATION (requires explicit acceptance)
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [workspace, setWorkspace] = useState("network");
  if (workspace === "application") {
    return (
      <ApplicationResearch
        apiFetch={apiFetch}
        theme={theme}
        onBack={() => setWorkspace("network")}
      />
    );
  }
  return <NetworkAssessment onOpenApplicationResearch={() => setWorkspace("application")} />;
}
