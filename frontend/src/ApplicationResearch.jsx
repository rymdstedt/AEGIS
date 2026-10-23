import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let amount = bytes / 1024;
  let unit = units[0];
  for (let index = 1; index < units.length && amount >= 1024; index += 1) {
    amount /= 1024;
    unit = units[index];
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${unit}`;
}

function downloadJson(value, fileName) {
  const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

async function consumeChatStream(response, onEvent) {
  if (!response.ok) {
    let detail = `Local model request failed (HTTP ${response.status})`;
    try { detail = (await response.json()).detail || detail; } catch { /* non-JSON error */ }
    throw new Error(detail);
  }
  if (!response.body) throw new Error("The local backend did not return a response stream");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  let completed = null;
  const processLine = (line) => {
    if (!line.trim()) return;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error("The local backend returned an invalid progress event"); }
    onEvent(event);
    if (event.type === "error") throw new Error(event.message || "The local model request failed");
    if (event.type === "complete") completed = event;
  };
  while (true) {
    const { value, done } = await reader.read();
    buffered += decoder.decode(value || new Uint8Array(), { stream: !done });
    const lines = buffered.split("\n");
    buffered = lines.pop() || "";
    lines.forEach(processLine);
    if (done) break;
  }
  if (buffered.trim()) processLine(buffered);
  if (!completed?.answer) throw new Error("The local model stream ended without an answer");
  return completed;
}

function SeverityBadge({ severity, theme }) {
  const colors = {
    critical: theme.critical,
    high: theme.high,
    medium: theme.medium,
    low: theme.low,
    info: theme.info,
  };
  const color = colors[severity] || theme.info;
  return (
    <span style={{ padding: "2px 8px", borderRadius: 4, color, background: `${color}22`, border: `1px solid ${color}55`, fontSize: 10, fontWeight: 800, letterSpacing: 0.7, textTransform: "uppercase" }}>
      {severity}
    </span>
  );
}

function SmallStat({ label, value, color, theme }) {
  return (
    <div style={{ padding: "10px 12px", background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 7 }}>
      <div style={{ color: theme.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.8 }}>{label}</div>
      <div style={{ color: color || theme.text, fontSize: 17, fontWeight: 750, marginTop: 3 }}>{value}</div>
    </div>
  );
}

function EvidencePager({ title, items, theme, renderItem, searchText, getKey, pageSize = 10 }) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [items, query]);
  const records = Array.isArray(items) ? items : [];
  const needle = query.trim().toLocaleLowerCase();
  const filtered = needle
    ? records.filter(item => String(searchText(item) || "").toLocaleLowerCase().includes(needle))
    : records;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visible = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  return (
    <div style={{ marginTop: 10, paddingTop: 9, borderTop: `1px solid ${theme.border}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, color: theme.textDim, fontSize: 10, marginBottom: 6 }}>
        <b style={{ color: theme.text }}>{title}</b>
        <span>{filtered.length === records.length ? `${records.length} total` : `${filtered.length} matching / ${records.length} total`}</span>
      </div>
      {records.length > 0 && (
        <input
          aria-label={`Search ${title.toLowerCase()}`}
          value={query}
          onChange={event => setQuery(event.target.value)}
          placeholder={`Search ${title.toLowerCase()}…`}
          style={{ width: "100%", padding: "6px 8px", background: theme.bg, color: theme.text, border: `1px solid ${theme.border}`, borderRadius: 4, fontSize: 10 }}
        />
      )}
      {filtered.length === 0 && <div style={{ color: theme.textDim, fontSize: 9, marginTop: 6 }}>{records.length ? "No matching records." : "No records."}</div>}
      {visible.map((item, index) => (
        <div key={getKey(item, currentPage * pageSize + index)}>{renderItem(item)}</div>
      ))}
      {pageCount > 1 && (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 8, color: theme.textDim, fontSize: 9 }}>
          <button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)} style={{ padding: "4px 7px", color: theme.text, background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 4, opacity: currentPage === 0 ? 0.45 : 1 }}>Previous</button>
          <span>Page {currentPage + 1} of {pageCount}</span>
          <button type="button" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)} style={{ padding: "4px 7px", color: theme.text, background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 4, opacity: currentPage + 1 >= pageCount ? 0.45 : 1 }}>Next</button>
        </div>
      )}
    </div>
  );
}

export default function ApplicationResearch({ apiFetch, theme, onBack }) {
  const [projects, setProjects] = useState([]);
  const [project, setProject] = useState(null);
  const [loading, setLoading] = useState(true);
  const [importing, setImporting] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisJob, setAnalysisJob] = useState(null);
  const [cancellingAnalysis, setCancellingAnalysis] = useState(false);
  const [analysisProfile, setAnalysisProfile] = useState("quick");
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [deletingProject, setDeletingProject] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revealedEvidence, setRevealedEvidence] = useState({});
  const [revealingId, setRevealingId] = useState("");
  const [exportingPrivate, setExportingPrivate] = useState(false);
  const [exportingRedacted, setExportingRedacted] = useState(false);
  const [lmUrl, setLmUrl] = useState("http://localhost:1234");
  const [models, setModels] = useState([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [modelsLoading, setModelsLoading] = useState(false);
  const [modelsError, setModelsError] = useState("");
  const [chatQuestion, setChatQuestion] = useState("");
  const [chatMessages, setChatMessages] = useState([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [chatElapsedSeconds, setChatElapsedSeconds] = useState(0);
  const [chatStage, setChatStage] = useState("");
  const [includePrivateInChat, setIncludePrivateInChat] = useState(false);
  const [ciscoAccessToken, setCiscoAccessToken] = useState("");
  const [ciscoVersion, setCiscoVersion] = useState("");
  const [advisoryLoading, setAdvisoryLoading] = useState(false);
  const [advisoryError, setAdvisoryError] = useState("");
  const [sbomDownloading, setSbomDownloading] = useState(false);
  const chatEndRef = useRef(null);
  const chatInputRef = useRef(null);
  const chatProjectRef = useRef(project?.id);
  const chatEpochRef = useRef(0);
  const desktopPickerAvailable = typeof window.aegisDesktop?.selectArtifact === "function";
  const privateEvidenceAvailable = typeof window.aegisDesktop?.revealApplicationEvidence === "function";
  const projectDeleteAvailable = typeof window.aegisDesktop?.deleteApplicationProject === "function";
  const privateExportAvailable = typeof window.aegisDesktop?.exportApplicationEvidence === "function";
  const privateChatAvailable = typeof window.aegisDesktop?.chatApplicationWithPrivateEvidence === "function";

  const refreshProjects = useCallback(async () => {
    const response = await apiFetch("/api/application/projects");
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Could not load projects (HTTP ${response.status})`);
    setProjects(data.projects || []);
    return data.projects || [];
  }, [apiFetch]);

  const loadProject = useCallback(async (projectId) => {
    setError("");
    const response = await apiFetch(`/api/application/projects/${encodeURIComponent(projectId)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Could not load project (HTTP ${response.status})`);
    setProject(data);
    return data;
  }, [apiFetch]);

  const loadFindingsPage = async (offset) => {
    if (!project?.id || findingsLoading) return;
    const projectId = project.id;
    setFindingsLoading(true);
    setRevealedEvidence({});
    try {
      const response = await apiFetch(`/api/application/projects/${encodeURIComponent(projectId)}/findings?offset=${offset}&limit=100`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Could not load findings (HTTP ${response.status})`);
      if (data.analysis_job_id !== project.summary?.analysis_job_id) throw new Error("Analysis changed while loading findings; reload the project.");
      setProject(current => current?.id === projectId ? {
        ...current,
        findings: data.findings,
        findings_total: data.total,
        findings_page: { offset: data.offset, limit: data.limit, has_more: data.has_more, analysis_job_id: data.analysis_job_id },
      } : current);
    } catch (problem) {
      setError(problem.message || String(problem));
    } finally {
      setFindingsLoading(false);
    }
  };

  const refreshModels = useCallback(async (providerUrl = "http://localhost:1234") => {
    setModelsLoading(true);
    setModelsError("");
    try {
      const response = await apiFetch(`/api/models?lm_url=${encodeURIComponent(providerUrl)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Could not load models (HTTP ${response.status})`);
      const items = data.data || [];
      setModels(items);
      setSelectedModel(current => {
        if (items.some(item => item.id === current)) return current;
        const loaded = items.find(item => item.loaded);
        return loaded?.id || items[0]?.id || "";
      });
      if (data.error) setModelsError(data.error);
    } catch (problem) {
      setModels([]);
      setModelsError(problem.message || String(problem));
    } finally {
      setModelsLoading(false);
    }
  }, [apiFetch]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    refreshProjects()
      .then(items => {
        if (cancelled || items.length === 0) return null;
        return loadProject(items[0].id);
      })
      .catch(problem => { if (!cancelled) setError(problem.message || String(problem)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [loadProject, refreshProjects]);

  useEffect(() => {
    refreshModels("http://localhost:1234");
  }, [refreshModels]);

  useLayoutEffect(() => {
    chatProjectRef.current = project?.id;
    chatEpochRef.current += 1;
    setRevealedEvidence({});
    setChatMessages([]);
    setChatQuestion("");
    setChatLoading(false);
    setChatStage("");
    setIncludePrivateInChat(false);
    setCiscoAccessToken("");
    setCiscoVersion("");
    setAdvisoryError("");
    setNotice("");
  }, [project?.id]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ block: "nearest" });
  }, [chatMessages, chatLoading]);

  useEffect(() => {
    if (!chatLoading) {
      setChatElapsedSeconds(0);
      return undefined;
    }
    const started = Date.now();
    const timer = setInterval(() => {
      setChatElapsedSeconds(Math.floor((Date.now() - started) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [chatLoading]);

  useEffect(() => {
    if (!analyzing || !project?.id) return undefined;
    let disposed = false;
    const projectId = project.id;
    const refresh = async () => {
      try {
        const response = await apiFetch(`/api/application/projects/${encodeURIComponent(projectId)}/analysis-job`);
        if (!response.ok) return;
        const data = await response.json();
        if (!disposed) setAnalysisJob(data.job || null);
      } catch { /* progress is advisory; the main analyze response reports failure */ }
    };
    refresh();
    const timer = setInterval(refresh, 700);
    return () => { disposed = true; clearInterval(timer); };
  }, [analyzing, project?.id, apiFetch]);

  const analyzeProject = async (projectId, profile = "quick") => {
    setAnalyzing(true);
    setAnalysisJob(null);
    setCancellingAnalysis(false);
    setAnalysisProfile(profile);
    setError("");
    setNotice("");
    setRevealedEvidence({});
    try {
      const response = await apiFetch(`/api/application/projects/${encodeURIComponent(projectId)}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Analysis failed (HTTP ${response.status})`);
      setProject(data);
      await refreshProjects();
    } catch (problem) {
      setError(problem.message || String(problem));
      try { await loadProject(projectId); } catch { /* keep the primary error */ }
    } finally {
      setAnalyzing(false);
      setCancellingAnalysis(false);
    }
  };

  const cancelAnalysis = async () => {
    if (!analyzing || !project?.id || cancellingAnalysis) return;
    setCancellingAnalysis(true);
    try {
      const response = await apiFetch(`/api/application/projects/${encodeURIComponent(project.id)}/analysis-job/cancel`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Cancellation failed (HTTP ${response.status})`);
      setAnalysisJob(data.job || null);
      setNotice("Cancellation requested. The current bounded check will stop before its result is saved.");
    } catch (problem) {
      setError(problem.message || String(problem));
      setCancellingAnalysis(false);
    }
  };

  const selectArtifact = async (kind) => {
    if (!desktopPickerAvailable || importing || analyzing || deletingProject) return;
    setImporting(true);
    setError("");
    try {
      const result = await window.aegisDesktop.selectArtifact(kind);
      if (result?.cancelled) return;
      if (!result?.project?.id) throw new Error("The desktop importer returned no project");
      setProject(result.project);
      await refreshProjects();
      await analyzeProject(result.project.id, "quick");
    } catch (problem) {
      setError(problem.message || String(problem));
    } finally {
      setImporting(false);
    }
  };

  const chooseProject = async (projectId) => {
    setLoading(true);
    try {
      await loadProject(projectId);
    } catch (problem) {
      setError(problem.message || String(problem));
    } finally {
      setLoading(false);
    }
  };

  const revealEvidence = async (findingId) => {
    if (!privateEvidenceAvailable || !project?.id || revealingId) return;
    if (revealedEvidence[findingId]) {
      setRevealedEvidence(current => {
        const next = { ...current };
        delete next[findingId];
        return next;
      });
      return;
    }
    setRevealingId(findingId);
    setError("");
    try {
      const result = await window.aegisDesktop.revealApplicationEvidence(project.id, findingId);
      if (result?.cancelled) return;
      if (!result?.evidence?.raw_evidence) throw new Error("No exact evidence was returned");
      setRevealedEvidence(current => ({
        ...current,
        [findingId]: result.evidence.raw_evidence,
      }));
    } catch (problem) {
      setError(problem.message || String(problem));
    } finally {
      setRevealingId("");
    }
  };

  const exportPrivateEvidence = async () => {
    if (!privateExportAvailable || !project?.id || exportingPrivate) return;
    setExportingPrivate(true);
    setError("");
    setNotice("");
    try {
      const result = await window.aegisDesktop.exportApplicationEvidence(project.id);
      if (!result?.cancelled) setNotice(`Private evidence saved as ${result.fileName}.`);
    } catch (problem) {
      setError(problem.message || String(problem));
    } finally {
      setExportingPrivate(false);
    }
  };

  const exportRedactedProject = async () => {
    if (!project?.id || exportingRedacted || analyzing) return;
    setExportingRedacted(true);
    setError("");
    try {
      if (typeof window.aegisDesktop?.exportApplicationRedacted === "function") {
        const result = await window.aegisDesktop.exportApplicationRedacted(project.id);
        if (!result?.cancelled) setNotice(`Exported ${result.count} redacted findings as ${result.fileName}. Exact values were not included.`);
        return;
      }
      const allFindings = [];
      const expectedTotal = project.findings_total ?? project.findings?.length ?? 0;
      const expectedJob = project.summary?.analysis_job_id;
      for (let offset = 0; offset < expectedTotal; offset += 500) {
        const response = await apiFetch(`/api/application/projects/${encodeURIComponent(project.id)}/findings?offset=${offset}&limit=500`);
        const page = await response.json();
        if (!response.ok) throw new Error(page.detail || `Finding export failed (HTTP ${response.status})`);
        if (page.total !== expectedTotal || page.analysis_job_id !== expectedJob || !page.findings?.length) throw new Error("Findings changed during export; retry after analysis finishes");
        allFindings.push(...page.findings);
      }
      const safeName = project.name.replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 80) || "application";
      downloadJson({ ...project, findings: allFindings, findings_total: expectedTotal, findings_page: null }, `AEGIS-${safeName}-redacted-findings.json`);
      setNotice(`Exported ${expectedTotal} redacted findings. Exact values were not included.`);
    } catch (problem) {
      setError(problem.message || String(problem));
    } finally {
      setExportingRedacted(false);
    }
  };

  const downloadSbom = async () => {
    if (!project?.id || sbomDownloading) return;
    setSbomDownloading(true);
    setError("");
    try {
      const response = await apiFetch(`/api/application/projects/${encodeURIComponent(project.id)}/sbom`);
      if (!response.ok) {
        let detail = `SBOM download failed (HTTP ${response.status})`;
        try { detail = (await response.json()).detail || detail; } catch { /* non-JSON error */ }
        throw new Error(detail);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const safeName = project.name.replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 80) || "application";
      anchor.href = url;
      anchor.download = `AEGIS-${safeName}-sbom.cdx.json`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (problem) {
      setError(problem.message || String(problem));
    } finally {
      setSbomDownloading(false);
    }
  };

  const deleteProject = async () => {
    if (!project?.id || !projectDeleteAvailable || deletingProject) return;
    const projectId = project.id;
    setDeletingProject(true);
    setError("");
    setNotice("");
    try {
      const result = await window.aegisDesktop.deleteApplicationProject(projectId);
      if (result?.cancelled) return;
      setProject(null);
      setRevealedEvidence({});
      setChatMessages([]);
      const remaining = await refreshProjects();
      if (remaining.length > 0) await loadProject(remaining[0].id);
      setNotice(result?.response?.cleanup_pending
        ? "Project record removed. Cleanup of its private copied files is still pending."
        : "Project and its AEGIS-owned copied data were removed. The original import was not changed.");
    } catch (problem) {
      setError(problem.message || String(problem));
      try { await loadProject(projectId); } catch { /* deletion may already be committed */ }
    } finally {
      setDeletingProject(false);
    }
  };

  const askLocalModel = async () => {
    const question = chatQuestion.trim();
    if (!project?.id || !question || !selectedModel || chatLoading) return;
    const requestProjectId = project.id;
    const requestEpoch = chatEpochRef.current;
    const requestIsCurrent = () => (
      chatProjectRef.current === requestProjectId && chatEpochRef.current === requestEpoch
    );
    const includePrivate = includePrivateInChat;
    const history = chatMessages
      .filter(message => ["user", "assistant"].includes(message.role))
      .filter(message => includePrivate || !message.private)
      .slice(-8)
      .map(message => ({
        role: message.role,
        content: String(message.content || "").slice(0, 1200),
      }))
      .filter(message => message.content.trim());
    const userMessage = { role: "user", content: question, private: includePrivate };
    setChatMessages(current => requestIsCurrent() ? [...current, userMessage] : current);
    setChatQuestion("");
    setChatLoading(true);
    setChatStage("Preparing the selected local model");
    setError("");
    const assistantId = `local-answer-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    let streamedAnswer = "";
    const handleStreamEvent = (event) => {
      if (!requestIsCurrent()) return;
      if (event?.type === "progress") {
        if (event.stage === "model") setChatStage("Ensuring only the selected model is loaded");
        else if (event.stage === "prompt") {
          const percent = Number.isFinite(Number(event.progress)) ? ` ${Math.round(Number(event.progress) * 100)}%` : "";
          setChatStage(`Reading the project evidence${percent}`);
        } else if (event.stage === "generating") setChatStage("Generating answer · partial text appears above");
      }
      if (event?.type === "delta" && event.content) {
        streamedAnswer += event.content;
        setChatMessages(current => {
          if (!requestIsCurrent()) return current;
          const index = current.findIndex(message => message.id === assistantId);
          const nextMessage = { id: assistantId, role: "assistant", content: streamedAnswer, private: includePrivate };
          if (index < 0) return [...current, nextMessage];
          const next = [...current];
          next[index] = nextMessage;
          return next;
        });
      }
    };
    try {
      let data;
      if (includePrivate) {
        if (!privateChatAvailable) throw new Error("Private-evidence chat requires the AEGIS desktop app");
        const result = await window.aegisDesktop.chatApplicationWithPrivateEvidence({
          projectId: project.id,
          question,
          lmUrl,
          model: selectedModel,
          history,
        }, handleStreamEvent);
        if (!requestIsCurrent()) return;
        if (result?.cancelled) {
          setChatMessages(current => requestIsCurrent() ? [...current, { role: "assistant", content: "Exact-evidence sharing was cancelled; no prompt was sent." }] : current);
          return;
        }
        data = result?.response;
      } else {
        const response = await apiFetch(`/api/application/projects/${encodeURIComponent(project.id)}/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question, lm_url: lmUrl, model: selectedModel, include_private: false, stream: true, history }),
        });
        data = await consumeChatStream(response, handleStreamEvent);
      }
      if (!requestIsCurrent()) return;
      if (!data?.answer) throw new Error("The local model returned no answer");
      streamedAnswer = data.answer;
      setChatMessages(current => {
        if (!requestIsCurrent()) return current;
        const index = current.findIndex(message => message.id === assistantId);
        const finalMessage = {
          id: assistantId,
          role: "assistant",
          content: data.answer,
          private: Boolean(data.included_private_evidence),
          truncated: Boolean(data.truncated),
          notice: data.notice || "",
        };
        if (index < 0) return [...current, finalMessage];
        const next = [...current];
        next[index] = finalMessage;
        return next;
      });
    } catch (problem) {
      if (!requestIsCurrent()) return;
      const message = problem.message || String(problem);
      setChatMessages(current => {
        if (!requestIsCurrent()) return current;
        const index = current.findIndex(item => item.id === assistantId);
        if (index < 0 || !streamedAnswer.trim()) {
          return [...current, { role: "error", content: message }];
        }
        const next = [...current];
        next[index] = {
          ...next[index],
          content: streamedAnswer,
          truncated: true,
          notice: `Generation stopped before a final response: ${message}`,
        };
        return next;
      });
      setChatQuestion(current => requestIsCurrent() ? (current || question) : current);
    } finally {
      if (requestIsCurrent()) {
        setChatLoading(current => requestIsCurrent() ? false : current);
        setChatStage(current => requestIsCurrent() ? "" : current);
      }
    }
  };

  const lookupCiscoAdvisories = async () => {
    const versions = project?.summary?.firmware?.versions || [];
    const version = ciscoVersion || versions[0] || "";
    if (!project?.id || !version || ciscoAccessToken.trim().length < 20 || advisoryLoading) return;
    setAdvisoryLoading(true);
    setAdvisoryError("");
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(`/api/application/projects/${encodeURIComponent(project.id)}/cisco-advisories`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ access_token: ciscoAccessToken.trim(), version }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Cisco advisory lookup failed (HTTP ${response.status})`);
      setProject(data);
      await refreshProjects();
      const count = data.summary?.firmware?.advisory_lookup?.advisory_count ?? 0;
      setNotice(`Cisco PSIRT lookup completed for ${version}: ${count} advisory record${count === 1 ? "" : "s"}.`);
    } catch (problem) {
      setAdvisoryError(problem.message || String(problem));
    } finally {
      setCiscoAccessToken("");
      setAdvisoryLoading(false);
    }
  };

  const findings = project?.findings || [];
  const inventory = project?.summary?.inventory || {};
  const counts = project?.summary?.finding_counts || {};
  const firmware = project?.summary?.firmware || null;
  const supplyChain = project?.summary?.supply_chain || null;
  const deepSource = project?.summary?.deep_source || null;
  const evidenceGraph = project?.summary?.evidence_graph || null;
  const intakeLimits = project?.intake?.limits || {};
  const hasTraversalMetrics = inventory.analyzed_text_bytes !== undefined
    && project?.summary?.rule_evaluations !== undefined;
  const busy = importing || analyzing || deletingProject || advisoryLoading;

  return (
    <div style={{ background: theme.bg, color: theme.text, height: "100vh", fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif", display: "flex", flexDirection: "column" }}>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 7px; height: 7px; }
        ::-webkit-scrollbar-track { background: ${theme.bg}; }
        ::-webkit-scrollbar-thumb { background: ${theme.border}; border-radius: 4px; }
        button { cursor: pointer; font-family: inherit; }
        @keyframes aegis-spin { to { transform: rotate(360deg); } }
      `}</style>

      <header style={{ height: 58, padding: "0 22px", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: `1px solid ${theme.border}`, background: "linear-gradient(180deg,#111827 0%,#0a0e17 100%)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={onBack} aria-label="Back to live assessment" style={{ width: 32, height: 32, borderRadius: 6, border: `1px solid ${theme.border}`, background: theme.surface, color: theme.text, fontSize: 17 }}>←</button>
          <div style={{ fontSize: 21, fontWeight: 800 }}>AEGIS</div>
          <div style={{ width: 1, height: 22, background: theme.border }} />
          <div>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Application Research</div>
            <div style={{ fontSize: 10, color: theme.textDim }}>Local artifact analysis</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, color: theme.green, fontSize: 12 }}>
          <span style={{ width: 8, height: 8, background: theme.green, borderRadius: "50%", boxShadow: `0 0 8px ${theme.green}` }} />
          Read-only analysis
        </div>
      </header>

      <div style={{ padding: "12px 18px", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, background: theme.surface, borderBottom: `1px solid ${theme.border}` }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14 }}>Inspect source, packages, firmware, archives, and native binaries</div>
          <div style={{ color: theme.textDim, fontSize: 11, marginTop: 3 }}>AEGIS copies the selection into private storage. It does not launch, boot, mount, or run code from the artifact.</div>
        </div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          <button disabled={!desktopPickerAvailable || busy} onClick={() => selectArtifact("file")} style={{ padding: "9px 14px", border: `1px solid ${theme.accent}`, borderRadius: 6, background: theme.accentGlow, color: theme.accent, fontWeight: 700, opacity: !desktopPickerAvailable || busy ? 0.5 : 1 }}>
            {importing ? "Importing…" : "+ Import file"}
          </button>
          <button disabled={!desktopPickerAvailable || busy} onClick={() => selectArtifact("directory")} style={{ padding: "9px 14px", border: `1px solid ${theme.accent}`, borderRadius: 6, background: theme.accent, color: "white", fontWeight: 700, opacity: !desktopPickerAvailable || busy ? 0.5 : 1 }}>
            + Import source folder
          </button>
        </div>
      </div>

      {!desktopPickerAvailable && (
        <div style={{ padding: "8px 18px", background: "#3b2f1f", color: "#fcd34d", fontSize: 12, borderBottom: "1px solid #5c4721" }}>
          Native artifact selection is available in the AEGIS desktop app. The browser development preview intentionally cannot read arbitrary local paths.
        </div>
      )}
      {error && (
        <div role="alert" style={{ padding: "9px 18px", background: "#3b1f1f", color: "#fca5a5", fontSize: 12, borderBottom: "1px solid #713232" }}>{error}</div>
      )}
      {notice && (
        <div role="status" style={{ padding: "9px 18px", background: `${theme.green}18`, color: theme.green, fontSize: 12, borderBottom: `1px solid ${theme.green}55` }}>{notice}</div>
      )}

      <main style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "280px minmax(0, 1fr)" }}>
        <aside style={{ minHeight: 0, overflowY: "auto", borderRight: `1px solid ${theme.border}`, background: theme.surface }}>
          <div style={{ padding: "12px 14px", position: "sticky", top: 0, zIndex: 1, background: theme.surfaceAlt, borderBottom: `1px solid ${theme.border}`, color: theme.textDim, fontSize: 10, fontWeight: 800, letterSpacing: 1, textTransform: "uppercase" }}>
            Projects ({projects.length})
          </div>
          {projects.length === 0 && !loading && (
            <div style={{ padding: 20, color: theme.textDim, fontSize: 12, lineHeight: 1.6 }}>No application projects yet. Import a file or source folder to create one.</div>
          )}
          {projects.map(item => {
            const active = project?.id === item.id;
            return (
              <button key={item.id} onClick={() => chooseProject(item.id)} style={{ width: "100%", padding: "12px 14px", textAlign: "left", border: "none", borderBottom: `1px solid ${theme.border}`, borderLeft: `3px solid ${active ? theme.accent : "transparent"}`, background: active ? theme.accentGlow : "transparent", color: theme.text }}>
                <div style={{ fontSize: 13, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.name}</div>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, color: theme.textDim, fontSize: 10, marginTop: 5 }}>
                  <span>{item.artifact_kind.replaceAll("_", " ")}</span>
                  <span style={{ color: item.status === "complete" ? theme.green : item.status === "error" ? theme.critical : theme.accent }}>{item.status}</span>
                </div>
              </button>
            );
          })}
        </aside>

        <section style={{ minWidth: 0, minHeight: 0, overflowY: "auto", padding: 20 }}>
          {loading && !project && <div style={{ color: theme.textDim }}>Loading projects…</div>}
          {!project && !loading && (
            <div style={{ height: "100%", display: "grid", placeItems: "center" }}>
              <div style={{ maxWidth: 520, textAlign: "center", color: theme.textDim }}>
                <div style={{ fontSize: 46, marginBottom: 12 }}>◫</div>
                <div style={{ color: theme.text, fontSize: 18, fontWeight: 750, marginBottom: 8 }}>Start with an application artifact</div>
                <div style={{ fontSize: 13, lineHeight: 1.7 }}>Choose a repository folder, ZIP/TAR bundle, Cisco IOS or IOS XE image, APK, IPA, JAR, EXE, DLL, DMG, PKG, or individual source file. Quick triage inventories one logical project and reports deterministic static evidence without loading the whole project into memory.</div>
              </div>
            </div>
          )}

          {project && (
            <>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, marginBottom: 16 }}>
                <div style={{ minWidth: 0 }}>
                  <h1 style={{ fontSize: 22, overflowWrap: "anywhere" }}>{project.name}</h1>
                  <div style={{ color: theme.textDim, fontSize: 11, marginTop: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
                    <span>{project.artifact_kind.replaceAll("_", " ")}</span>
                    <span>{formatBytes(project.size_bytes)}</span>
                    <span title={project.sha256}>SHA-256 {project.sha256.slice(0, 16)}…</span>
                    <span>{project.source_type}</span>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 7, flexWrap: "wrap", justifyContent: "flex-end" }}>
                  <button disabled={exportingRedacted || analyzing} onClick={exportRedactedProject} style={{ padding: "9px 11px", flexShrink: 0, border: `1px solid ${theme.border}`, borderRadius: 6, background: theme.surface, color: theme.text, fontWeight: 700, opacity: exportingRedacted || analyzing ? 0.5 : 1 }}>
                    {exportingRedacted ? "Exporting…" : "Export redacted JSON"}
                  </button>
                  <button disabled={!privateExportAvailable || exportingPrivate || findings.length === 0} onClick={exportPrivateEvidence} style={{ padding: "9px 11px", flexShrink: 0, border: `1px solid ${theme.high}`, borderRadius: 6, background: `${theme.high}16`, color: theme.high, fontWeight: 700, opacity: !privateExportAvailable || exportingPrivate || findings.length === 0 ? 0.5 : 1 }}>
                    {exportingPrivate ? "Exporting…" : "Export exact evidence…"}
                  </button>
                  <button disabled={busy} onClick={() => analyzeProject(project.id)} style={{ padding: "9px 14px", flexShrink: 0, border: `1px solid ${theme.green}`, borderRadius: 6, background: `${theme.green}18`, color: theme.green, fontWeight: 750, opacity: busy ? 0.55 : 1 }}>
                    {analyzing && analysisProfile === "quick" ? "Analyzing…" : project.status === "complete" ? "Run quick triage again" : "Run quick triage"}
                  </button>
                  <button disabled={busy} onClick={() => analyzeProject(project.id, "supply_chain")} style={{ padding: "9px 14px", flexShrink: 0, border: `1px solid ${theme.accent}`, borderRadius: 6, background: theme.accentGlow, color: theme.accent, fontWeight: 750, opacity: busy ? 0.55 : 1 }}>
                    {analyzing && analysisProfile === "supply_chain" ? "Checking dependencies…" : supplyChain ? "Run supply-chain analysis again" : "Analyze dependencies + SBOM"}
                  </button>
                  <button disabled={busy} onClick={() => analyzeProject(project.id, "deep_source")} style={{ padding: "9px 14px", flexShrink: 0, border: `1px solid ${theme.high}`, borderRadius: 6, background: `${theme.high}16`, color: theme.high, fontWeight: 750, opacity: busy ? 0.55 : 1 }}>
                    {analyzing && analysisProfile === "deep_source" ? "Tracing source paths…" : deepSource ? "Run deep source analysis again" : "Deep source analysis"}
                  </button>
                  {firmware && (
                    <button disabled={busy} onClick={() => analyzeProject(project.id, "deep_firmware")} style={{ padding: "9px 14px", flexShrink: 0, border: `1px solid ${theme.accent}`, borderRadius: 6, background: theme.accentGlow, color: theme.accent, fontWeight: 750, opacity: busy ? 0.55 : 1 }}>
                      {analyzing && analysisProfile === "deep_firmware" ? "Deep scanning…" : firmware.deep_analysis ? "Run deep firmware analysis again" : "Run deep firmware analysis"}
                    </button>
                  )}
                  <button disabled={!projectDeleteAvailable || busy} onClick={deleteProject} style={{ padding: "9px 11px", flexShrink: 0, border: `1px solid ${theme.critical}`, borderRadius: 6, background: `${theme.critical}12`, color: theme.critical, fontWeight: 700, opacity: !projectDeleteAvailable || busy ? 0.5 : 1 }}>
                    {deletingProject ? "Removing…" : "Remove project…"}
                  </button>
                </div>
              </div>

              <div style={{ padding: "9px 12px", marginBottom: 14, border: `1px solid ${theme.green}55`, background: `${theme.green}0d`, borderRadius: 6, color: theme.green, fontSize: 11 }}>
                ✓ Artifact execution: never &nbsp;•&nbsp; Original selection: not modified &nbsp;•&nbsp; Reports: redacted by default &nbsp;•&nbsp; Exact evidence: explicit confirmation only
              </div>

              {analyzing && (
                <div role="status" style={{ padding: 16, marginBottom: 14, border: `1px solid ${theme.accent}`, background: theme.accentGlow, borderRadius: 7, display: "flex", gap: 10, alignItems: "center", color: theme.accent, fontSize: 12 }}>
                  <span style={{ width: 15, height: 15, flexShrink: 0, border: `2px solid ${theme.accent}44`, borderTopColor: theme.accent, borderRadius: "50%", animation: "aegis-spin 0.8s linear infinite" }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div>{analysisJob?.progress?.phase === "deep_source" ? "Deep source analysis…" : analysisJob?.progress?.phase === "supply_chain" ? "Supply-chain analysis…" : "Scanning source files…"}</div>
                    <div style={{ marginTop: 4, fontSize: 10, color: theme.textDim, overflowWrap: "anywhere" }}>
                      {analysisJob?.progress?.files_visited ?? 0} files visited · {formatBytes(analysisJob?.progress?.text_bytes_inspected)} text inspected
                      {analysisJob?.progress?.current_file ? ` · ${analysisJob.progress.current_file}` : ""}
                    </div>
                  </div>
                  <button type="button" disabled={cancellingAnalysis} onClick={cancelAnalysis} style={{ padding: "7px 10px", border: `1px solid ${theme.critical}`, borderRadius: 5, background: theme.surface, color: theme.critical, opacity: cancellingAnalysis ? 0.5 : 1 }}>
                    {cancellingAnalysis ? "Stopping…" : "Cancel analysis"}
                  </button>
                </div>
              )}

              <div style={{ display: "grid", gridTemplateColumns: "repeat(6, minmax(0, 1fr))", gap: 8, marginBottom: 16 }}>
                <SmallStat label="Files" value={inventory.files ?? "—"} theme={theme} />
                <SmallStat label="Analyzed text" value={inventory.analyzed_text_files ?? "—"} theme={theme} />
                <SmallStat label="Critical" value={counts.critical ?? 0} color={theme.critical} theme={theme} />
                <SmallStat label="High" value={counts.high ?? 0} color={theme.high} theme={theme} />
                <SmallStat label="Medium" value={counts.medium ?? 0} color={theme.medium} theme={theme} />
                <SmallStat label="Other" value={(counts.low || 0) + (counts.info || 0)} color={theme.low} theme={theme} />
              </div>

              {project.status === "complete" && (
                <div style={{ padding: "10px 12px", marginBottom: 14, border: `1px solid ${theme.border}`, background: theme.surface, borderRadius: 6, color: theme.textDim, fontSize: 10, lineHeight: 1.55 }}>
                  {hasTraversalMetrics ? (
                    <>
                      <b style={{ color: theme.text }}>Traversal completed:</b> {inventory.files ?? 0} file{inventory.files === 1 ? "" : "s"} inventoried; {inventory.analyzed_text_files ?? 0} readable text file{inventory.analyzed_text_files === 1 ? "" : "s"} ({formatBytes(inventory.analyzed_text_bytes)}) inspected with {Number(project.summary.rule_evaluations).toLocaleString()} bounded pattern evaluations. {Number(inventory.binary_or_unreadable_candidates || 0) + Number(inventory.inventory_only_non_text_files || 0)} binary, metadata, or unreadable file{Number(inventory.binary_or_unreadable_candidates || 0) + Number(inventory.inventory_only_non_text_files || 0) === 1 ? " was" : "s were"} inventoried without text matching. Large text files are streamed; {inventory.segmented_long_lines || 0} unusually long line{inventory.segmented_long_lines === 1 ? " was" : "s were"} segmented.
                      <div style={{ marginTop: 4 }}>A small fixture can complete in milliseconds because quick triage reads files and performs in-memory matching. {deepSource ? "Deep source analysis also ran its explicitly reported analyzers and coverage below." : "Run Deep source analysis for taint paths, private secret scanning, and dependency-to-code correlation."} Dynamic execution is still a separate gated stage.</div>
                    </>
                  ) : (
                    <><b style={{ color: theme.text }}>Traversal metrics unavailable:</b> this project was analyzed by an older build. Run quick triage again to measure bytes inspected, pattern evaluations, binary-only files, and skipped files.</>
                  )}
                </div>
              )}

              {(project.summary?.findings_truncated || project.summary?.coverage_incomplete) && (
                <div role="status" style={{ padding: "10px 12px", marginBottom: 14, border: `1px solid ${theme.high}`, background: `${theme.high}18`, borderRadius: 6, color: theme.high, fontSize: 11, lineHeight: 1.5 }}>
                  {project.summary.per_rule_file_omission_count > 0 ? "Finding results are incomplete. " : "Pattern coverage may be incomplete. "}{project.summary.per_rule_file_omission_count > 0 && `At least ${project.summary.findings_omitted_lower_bound} additional match(es) were omitted after the ${project.summary.max_findings_per_rule_file}-per-rule-per-file cap. `}{inventory.segmented_long_lines > 0 && `${inventory.segmented_long_lines} unusually long line(s) were streamed in segments; patterns spanning more than ${project.summary.pattern_overlap_bytes} bytes across a boundary may be missed. `}{inventory.changed_during_scan_files > 0 && `${inventory.changed_during_scan_files} file(s) changed size during inspection; rescan a stable snapshot.`}
                </div>
              )}

              <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 2fr) minmax(250px, 1fr)", gap: 14, alignItems: "start" }}>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <h2 style={{ fontSize: 15 }}>Application findings</h2>
                    <span style={{ color: theme.textDim, fontSize: 11 }}>{(project.findings_total ?? findings.length).toLocaleString()} total · showing {findings.length}</span>
                  </div>
                  {project.status === "imported" && <div style={{ padding: 16, color: theme.textDim, border: `1px solid ${theme.border}`, borderRadius: 7 }}>The artifact is safely imported and awaiting static analysis.</div>}
                  {project.status === "complete" && findings.length === 0 && <div style={{ padding: 16, color: theme.textDim, border: `1px solid ${theme.border}`, borderRadius: 7 }}>No enabled analyzer produced an evidence-backed finding. This is not a clean bill of health; review Current limits for analysis stages that have not run.</div>}
                  {findings.length > 0 && <div>
                    {findings.map(finding => <article key={finding.id} style={{ padding: 13, marginBottom: 8, background: theme.surface, border: `1px solid ${theme.border}`, borderLeft: `3px solid ${finding.severity === "high" ? theme.high : finding.severity === "medium" ? theme.medium : theme.low}`, borderRadius: 7 }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 7 }}>
                        <SeverityBadge severity={finding.severity} theme={theme} />
                        <span style={{ color: theme.textDim, fontSize: 10 }}>{finding.confidence} confidence · {(finding.status || "static_evidence").replaceAll("_", " ")}</span>
                      </div>
                      <div style={{ fontWeight: 750, fontSize: 13 }}>{finding.title}</div>
                      <div style={{ color: theme.accent, fontFamily: "ui-monospace,SFMono-Regular,Menlo,monospace", fontSize: 10, marginTop: 5, overflowWrap: "anywhere" }}>{finding.file_path}{finding.line ? `:${finding.line}` : ""}</div>
                      <div style={{ color: theme.textDim, fontSize: 11, lineHeight: 1.55, marginTop: 7 }}>{finding.description}</div>
                      <pre style={{ marginTop: 8, padding: 8, whiteSpace: "pre-wrap", overflowWrap: "anywhere", background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 4, color: theme.text, fontSize: 10 }}>{finding.evidence}</pre>
                      {finding.has_private_evidence && (
                        <div style={{ marginTop: 8 }}>
                          <button disabled={!privateEvidenceAvailable || Boolean(revealingId)} onClick={() => revealEvidence(finding.id)} style={{ padding: "6px 9px", borderRadius: 5, border: `1px solid ${theme.high}88`, background: `${theme.high}12`, color: theme.high, fontSize: 10, fontWeight: 750, opacity: !privateEvidenceAvailable || revealingId ? 0.5 : 1 }}>
                            {revealingId === finding.id ? "Waiting for confirmation…" : revealedEvidence[finding.id] ? "Hide exact evidence" : "Reveal exact evidence…"}
                          </button>
                          {revealedEvidence[finding.id] && (
                            <div style={{ marginTop: 8, padding: 9, border: `1px solid ${theme.high}88`, background: `${theme.high}0d`, borderRadius: 5 }}>
                              <div style={{ color: theme.high, fontSize: 9, fontWeight: 800, letterSpacing: 0.7, marginBottom: 6 }}>SENSITIVE · LOCAL PRIVATE EVIDENCE</div>
                              <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", color: theme.text, fontSize: 10, userSelect: "text" }}>{revealedEvidence[finding.id]}</pre>
                            </div>
                          )}
                        </div>
                      )}
                      <div style={{ fontSize: 11, marginTop: 8 }}><b>Fix:</b> <span style={{ color: theme.textDim }}>{finding.remediation}</span></div>
                    </article>)}
                    {(project.findings_total ?? findings.length) > 100 && (
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginTop: 10, color: theme.textDim, fontSize: 10 }}>
                        <button type="button" disabled={findingsLoading || !project.findings_page?.offset} onClick={() => loadFindingsPage(Math.max(0, (project.findings_page?.offset || 0) - 100))} style={{ padding: "7px 10px", border: `1px solid ${theme.border}`, borderRadius: 5, background: theme.surface, color: theme.text, opacity: findingsLoading || !project.findings_page?.offset ? 0.5 : 1 }}>Previous 100</button>
                        <span>{(project.findings_page?.offset || 0) + 1}–{(project.findings_page?.offset || 0) + findings.length} of {project.findings_total}{findingsLoading ? " · Loading…" : ""}</span>
                        <button type="button" disabled={findingsLoading || !project.findings_page?.has_more} onClick={() => loadFindingsPage((project.findings_page?.offset || 0) + 100)} style={{ padding: "7px 10px", border: `1px solid ${theme.border}`, borderRadius: 5, background: theme.surface, color: theme.text, opacity: findingsLoading || !project.findings_page?.has_more ? 0.5 : 1 }}>Next 100</button>
                      </div>
                    )}
                  </div>}
                </div>

                <div style={{ display: "grid", gap: 10 }}>
                  {supplyChain && (
                    <div style={{ padding: 13, background: theme.surface, border: `1px solid ${theme.accent}66`, borderRadius: 7 }}>
                      <h2 style={{ fontSize: 13, marginBottom: 9 }}>Supply-chain analysis</h2>
                      <div style={{ color: theme.textDim, fontSize: 10, lineHeight: 1.65 }}>
                        <div>Status: <b style={{ color: supplyChain.status === "complete" ? theme.green : theme.medium }}>{supplyChain.status}</b></div>
                        <div>Components inventoried: {supplyChain.component_count ?? 0}</div>
                        <div>Affected dependency records: {supplyChain.vulnerability_count ?? 0}</div>
                        <div>Known-exploited matches: {supplyChain.risk_enrichment?.kev_matches ?? 0}</div>
                        <div>EPSS scores retrieved: {supplyChain.risk_enrichment?.epss_matches ?? 0}</div>
                        <div>Imported code executed: no</div>
                      </div>
                      {supplyChain.error && <div style={{ color: theme.medium, fontSize: 9, lineHeight: 1.45, marginTop: 7 }}>{supplyChain.error}</div>}
                      {supplyChain.install_guidance && <div style={{ color: theme.medium, fontSize: 9, lineHeight: 1.45, marginTop: 7 }}>{supplyChain.install_guidance}</div>}
                      {(supplyChain.risk_enrichment?.warnings || []).map(item => <div key={item} style={{ color: theme.medium, fontSize: 8, lineHeight: 1.4, marginTop: 4 }}>{item}</div>)}
                      {supplyChain.sbom?.available && (
                        <button disabled={sbomDownloading} onClick={downloadSbom} style={{ width: "100%", padding: "7px 9px", marginTop: 9, border: `1px solid ${theme.accent}`, borderRadius: 5, background: theme.accentGlow, color: theme.accent, fontWeight: 750, opacity: sbomDownloading ? 0.5 : 1 }}>
                          {sbomDownloading ? "Downloading…" : "Download CycloneDX 1.6 SBOM"}
                        </button>
                      )}
                      <EvidencePager title="Components" items={supplyChain.components || []} theme={theme}
                        getKey={(component, index) => component.component_id || index}
                        searchText={component => `${component.name} ${component.version} ${component.ecosystem} ${component.source}`}
                        renderItem={component => (
                          <div style={{ marginTop: 5, color: theme.textDim, fontSize: 9, overflowWrap: "anywhere" }}>
                            <b style={{ color: theme.text }}>{component.name} {component.version}</b> · {component.ecosystem} · {component.source}
                          </div>
                        )}
                      />
                    </div>
                  )}

                  {deepSource && (
                    <div style={{ padding: 13, background: theme.surface, border: `1px solid ${theme.high}66`, borderRadius: 7 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 9 }}>
                        <h2 style={{ fontSize: 13 }}>Deep source + reachability</h2>
                        <span style={{ padding: "2px 6px", borderRadius: 4, color: deepSource.status === "complete" ? theme.green : theme.medium, background: deepSource.status === "complete" ? `${theme.green}18` : `${theme.medium}18`, border: `1px solid ${deepSource.status === "complete" ? theme.green : theme.medium}55`, fontSize: 9, fontWeight: 800 }}>{String(deepSource.status || "unknown").toUpperCase()}</span>
                      </div>
                      <div style={{ color: theme.textDim, fontSize: 10, lineHeight: 1.65 }}>
                        <div>Semgrep: <b style={{ color: deepSource.analyzers?.semgrep?.status === "complete" ? theme.green : theme.medium }}>{deepSource.analyzers?.semgrep?.status || "not run"}</b> · {deepSource.analyzers?.semgrep?.finding_count ?? 0} finding{deepSource.analyzers?.semgrep?.finding_count === 1 ? "" : "s"}</div>
                        <div>Gitleaks: <b style={{ color: deepSource.analyzers?.gitleaks?.status === "complete" ? theme.green : theme.medium }}>{deepSource.analyzers?.gitleaks?.status || "not run"}</b> · {deepSource.analyzers?.gitleaks?.detections_total ?? 0} detection{deepSource.analyzers?.gitleaks?.detections_total === 1 ? "" : "s"} ({deepSource.analyzers?.gitleaks?.deduplicated_count ?? 0} merged with built-in evidence)</div>
                        <div>Static input-to-sink paths: {deepSource.reachability_path_count ?? 0}</div>
                        <div>Dependency references in code: {deepSource.component_reference_count ?? 0}</div>
                        <div>Reference coverage: {deepSource.component_reference_coverage?.files ?? 0} source file{deepSource.component_reference_coverage?.files === 1 ? "" : "s"} · {formatBytes(deepSource.component_reference_coverage?.bytes)}</div>
                        <div>Affected only: {deepSource.vulnerability_states?.affected_dependency_only ?? 0} · referenced: {deepSource.vulnerability_states?.referenced_by_code ?? 0} · affected component receives input: {deepSource.vulnerability_states?.affected_component_reachable_from_input ?? 0} · CVE-specific static sink candidates: {deepSource.vulnerability_states?.cve_specific_sink_path_observed ?? 0}</div>
                        <div>Imported code/build scripts executed: <b style={{ color: theme.green }}>no</b></div>
                      </div>
                      {deepSource.error && <div style={{ color: theme.medium, fontSize: 9, lineHeight: 1.45, marginTop: 7 }}>{deepSource.error}</div>}
                      {Object.values(deepSource.analyzers || {}).map(analyzer => analyzer.install_guidance && (
                        <div key={analyzer.analyzer} style={{ marginTop: 6, padding: 7, border: `1px dashed ${theme.medium}88`, borderRadius: 4, color: theme.medium, fontSize: 9, lineHeight: 1.45 }}>{analyzer.install_guidance} Open Diagnostics to install it or see the platform-specific manual command.</div>
                      ))}
                      <EvidencePager title="Static input-to-sink paths" items={deepSource.reachability || []} theme={theme}
                        getKey={(path, index) => path.finding_id || index}
                        searchText={path => `${path.rule_id} ${path.source} ${path.sink} ${path.file_path} ${path.line} ${path.component_hint}`}
                        renderItem={path => (
                          <div style={{ marginTop: 7, padding: 8, background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 5 }}>
                            <div style={{ color: theme.high, fontSize: 9, fontWeight: 750 }}>{path.source} → {path.sink}</div>
                            <div style={{ color: theme.accent, fontFamily: "ui-monospace,SFMono-Regular,Menlo,monospace", fontSize: 8, marginTop: 3, overflowWrap: "anywhere" }}>{path.file_path}{path.line ? `:${path.line}` : ""}</div>
                            <div style={{ color: theme.textDim, fontSize: 8, lineHeight: 1.4, marginTop: 3 }}>Static taint path; runtime execution and exploitation are not demonstrated.</div>
                          </div>
                        )}
                      />
                      <EvidencePager title="CVE correlations" items={deepSource.vulnerability_reachability || []} theme={theme}
                        getKey={(item, index) => `${item.vulnerability_id}-${item.component_id}-${index}`}
                        searchText={item => `${item.vulnerability_id} ${item.component} ${item.version} ${item.state} ${(item.references || []).map(reference => reference.file_path).join(" ")}`}
                        renderItem={item => (
                          <div style={{ marginTop: 7, padding: 7, background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 4, color: theme.textDim, fontSize: 9, overflowWrap: "anywhere" }}>
                            <b style={{ color: item.cve_specific_sink_path_observed ? theme.high : item.state === "affected_component_reachable_from_input" ? theme.high : item.state === "referenced_by_code" ? theme.medium : theme.text }}>{item.vulnerability_id}</b> · {item.component} {item.version}
                            <div style={{ marginTop: 3 }}>{String(item.state || "affected_dependency_only").replaceAll("_", " ")}{item.cve_specific_sink_path_observed ? " · static sink candidate only; configuration and runtime unverified" : item.state === "affected_component_reachable_from_input" ? " · CVE-specific trigger not confirmed" : ""}</div>
                            {(item.references || []).slice(0, 2).map(reference => <div key={`${reference.file_path}-${reference.line}`} style={{ color: theme.accent, marginTop: 3 }}>{reference.file_path}{reference.line ? `:${reference.line}` : ""}</div>)}
                            <button type="button" onClick={() => { setChatQuestion(`Explain the evidence and unverified preconditions for ${item.vulnerability_id} in ${item.component}.`); chatInputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" }); chatInputRef.current?.focus(); }} style={{ marginTop: 5, padding: "3px 6px", border: `1px solid ${theme.border}`, borderRadius: 4, background: theme.surface, color: theme.accent, fontSize: 9 }}>Ask local model about this</button>
                          </div>
                        )}
                      />
                    </div>
                  )}

                  {evidenceGraph && (
                    <div style={{ padding: 13, background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 7 }}>
                      <h2 style={{ fontSize: 13, marginBottom: 7 }}>Evidence graph</h2>
                      <div style={{ color: theme.textDim, fontSize: 10, lineHeight: 1.6 }}>
                        {evidenceGraph.stats?.nodes ?? 0} nodes · {evidenceGraph.stats?.edges ?? 0} relationships
                        <div style={{ marginTop: 3 }}>{Object.entries(evidenceGraph.stats?.kinds || {}).map(([kind, count]) => `${kind} ${count}`).join(" · ")}</div>
                      </div>
                    </div>
                  )}

                  {firmware && (
                    <div style={{ padding: 13, background: theme.surface, border: `1px solid ${theme.accent}66`, borderRadius: 7 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 8 }}>
                        <h2 style={{ fontSize: 13 }}>Firmware inventory</h2>
                        <span style={{ padding: "2px 6px", borderRadius: 4, color: theme.green, background: `${theme.green}18`, border: `1px solid ${theme.green}55`, fontSize: 9, fontWeight: 800 }}>READ ONLY</span>
                      </div>
                      <div style={{ color: theme.textDim, fontSize: 10, lineHeight: 1.65 }}>
                        <div>Vendor hint: <b style={{ color: theme.text }}>{firmware.vendor || "Unknown"}</b></div>
                        <div>Platform family: <b style={{ color: theme.text }}>{firmware.platform_family || "Unknown"}</b></div>
                        <div>Assessment: {(firmware.assessment_scope || "metadata triage").replaceAll("_", " ")}</div>
                        <div>Version hints: <b style={{ color: theme.text }}>{(firmware.versions || []).join(", ") || "None recovered"}</b></div>
                        <div>Candidate files: {firmware.candidate_files ?? 0}{firmware.candidates_truncated ? ` (+${firmware.candidates_truncated} omitted)` : ""}</div>
                        <div>Binary signature coverage: {firmware.binary_scan_coverage || "unknown"}</div>
                        <div>Authenticity: <span style={{ color: theme.medium }}>not verified offline</span></div>
                        <div>Cisco advisory lookup: <span style={{ color: theme.medium }}>{firmware.advisory_lookup_performed ? "completed" : "not run"}</span></div>
                        <div>Cryptographic signature verification: <span style={{ color: theme.medium }}>{firmware.signature_verification_performed ? "completed" : "not run"}</span></div>
                        <div>Embedded formats: {(firmware.embedded_formats || []).join(", ") || "No built-in signature matched"}</div>
                        {(firmware.package_references || []).length > 0 && <div>Install-mode packages referenced: {firmware.package_references.length}</div>}
                        {(firmware.missing_package_references || []).length > 0 && <div style={{ color: theme.medium }}>Referenced packages absent from snapshot: {firmware.missing_package_references.length}</div>}
                      </div>
                      <EvidencePager title="Firmware images" items={firmware.images || []} theme={theme}
                        getKey={(image, index) => image.path || index}
                        searchText={image => `${image.path} ${image.artifact_kind} ${(image.vendor_markers || []).join(" ")} ${(image.embedded_formats || []).map(format => format.name).join(" ")}`}
                        renderItem={image => (
                          <div style={{ marginTop: 9, padding: 8, background: theme.bg, border: `1px solid ${theme.border}`, borderRadius: 5 }}>
                            <div style={{ color: theme.accent, fontFamily: "ui-monospace,SFMono-Regular,Menlo,monospace", fontSize: 9, overflowWrap: "anywhere" }}>{image.path}</div>
                            <div style={{ color: theme.textDim, fontSize: 9, lineHeight: 1.5, marginTop: 4 }}>
                              {image.artifact_kind?.replaceAll("_", " ")} · {formatBytes(image.size_bytes)} · entropy {image.sample_entropy_bits_per_byte ?? "—"} bits/byte · {image.scan_complete ? "fully scanned" : `${formatBytes(image.scan_bytes)} sampled`}
                            </div>
                            {image.sha256 && <div style={{ color: theme.textDim, fontFamily: "ui-monospace,SFMono-Regular,Menlo,monospace", fontSize: 8, overflowWrap: "anywhere", marginTop: 3 }}>SHA-256 {image.sha256}</div>}
                            {(image.vendor_markers || []).length > 0 && <div style={{ color: theme.textDim, fontSize: 9, marginTop: 3 }}>Markers: {image.vendor_markers.join(", ")}</div>}
                            {(image.embedded_formats || []).map(format => (
                              <div key={format.name} style={{ color: theme.textDim, fontSize: 9, marginTop: 3 }}>
                                {format.name}: {(format.offsets || []).map(offset => `0x${Number(offset).toString(16)}`).join(", ") || "offset unavailable"}
                              </div>
                            ))}
                          </div>
                        )}
                      />
                      <EvidencePager title="Missing firmware packages" items={firmware.missing_package_references || []} theme={theme}
                        getKey={(reference, index) => `${reference}-${index}`}
                        searchText={reference => reference}
                        renderItem={reference => <div style={{ color: theme.medium, fontFamily: "ui-monospace,SFMono-Regular,Menlo,monospace", fontSize: 8, overflowWrap: "anywhere", marginTop: 3 }}>Missing from imported snapshot: {reference}</div>}
                      />
                      {firmware.deep_analysis ? (
                        <div style={{ marginTop: 10, paddingTop: 9, borderTop: `1px solid ${theme.border}` }}>
                          <div style={{ color: theme.text, fontSize: 10, fontWeight: 800, marginBottom: 6 }}>DEEP STATIC PASS</div>
                          <div style={{ color: theme.textDim, fontSize: 9, lineHeight: 1.55 }}>
                            <div>Images scanned: {firmware.deep_analysis.images_scanned ?? 0}</div>
                            <div>Bytes covered: {formatBytes(firmware.deep_analysis.bytes_covered)}</div>
                            <div>Indicator rules checked: {firmware.deep_analysis.indicator_rules_checked ?? 0}</div>
                            <div>Security indicators: {firmware.deep_analysis.security_indicators ?? 0}</div>
                            <div>Component versions: {(firmware.deep_analysis.components || []).length}{firmware.deep_analysis.components_truncated ? "+" : ""}</div>
                            <div>Embedded ELF objects parsed: {(firmware.deep_analysis.elf_objects || []).length}{firmware.deep_analysis.elf_objects_truncated ? "+" : ""}</div>
                          </div>
                          <EvidencePager title="Firmware components" items={firmware.deep_analysis.components || []} theme={theme}
                            getKey={(component, index) => `${component.name}-${component.version}-${component.path}-${index}`}
                            searchText={component => `${component.name} ${component.version} ${component.path}`}
                            renderItem={component => <div style={{ marginTop: 4, fontSize: 9, color: theme.textDim }}><b style={{ color: theme.text }}>{component.name} {component.version}</b> · {component.path}@0x{Number(component.offset).toString(16)}</div>}
                          />
                          <EvidencePager title="Embedded ELF objects" items={firmware.deep_analysis.elf_objects || []} theme={theme}
                            getKey={(elf, index) => `${elf.path}-${elf.offset}-${index}`}
                            searchText={elf => `${elf.path} ${elf.machine} ${elf.bits} ${elf.type} ${elf.interpreter}`}
                            renderItem={elf => (
                              <div style={{ marginTop: 5, padding: 6, border: `1px solid ${theme.border}`, borderRadius: 4, color: theme.textDim, fontSize: 8, lineHeight: 1.45 }}>
                                <b style={{ color: theme.text }}>{elf.machine} {elf.bits}-bit {elf.type}</b> · {elf.endianness}-endian · stack {elf.stack_executable === true ? "executable" : elf.stack_executable === false ? "non-executable" : "unknown"} · {elf.position_independent ? "PIE/shared" : "not PIE"}
                                {elf.interpreter && <div style={{ overflowWrap: "anywhere" }}>Interpreter: {elf.interpreter}</div>}
                              </div>
                            )}
                          />
                          <div style={{ marginTop: 7, color: theme.textDim, fontSize: 8 }}>
                            Extractors: {Object.entries(firmware.deep_analysis.extractors || {}).map(([name, value]) => `${name} ${value.available ? "available" : "missing"}`).join(" · ") || "not checked"}
                          </div>
                        </div>
                      ) : (
                        <div style={{ marginTop: 10, padding: 8, border: `1px dashed ${theme.accent}88`, borderRadius: 5, color: theme.textDim, fontSize: 9, lineHeight: 1.45 }}>
                          Run Deep Firmware Analysis to inspect uncompressed configuration secrets, identify component versions, and parse embedded ELF hardening metadata.
                        </div>
                      )}
                      {firmware.vendor === "Cisco" && (firmware.versions || []).length > 0 && (
                        <div style={{ marginTop: 10, paddingTop: 9, borderTop: `1px solid ${theme.border}` }}>
                          <div style={{ color: theme.text, fontSize: 10, fontWeight: 800, marginBottom: 5 }}>CISCO PSIRT VERSION CORRELATION</div>
                          <div style={{ color: theme.textDim, fontSize: 8, lineHeight: 1.45, marginBottom: 7 }}>
                            Uses Cisco&apos;s version-specific advisory API. Paste a current Cisco API access token; AEGIS sends it only to <b style={{ color: theme.text }}>apix.cisco.com</b>, never writes it to project storage, and clears this field after the request.
                            {" "}<a href="https://developer.cisco.com/docs/psirt/authentication/" target="_blank" rel="noreferrer" style={{ color: theme.accent }}>Cisco token setup ↗</a>
                          </div>
                          <select value={ciscoVersion || firmware.versions[0] || ""} onChange={event => setCiscoVersion(event.target.value)} disabled={advisoryLoading} aria-label="Detected Cisco firmware version" style={{ width: "100%", padding: "6px 7px", marginBottom: 5, borderRadius: 4, border: `1px solid ${theme.border}`, background: theme.bg, color: theme.text, fontSize: 9 }}>
                            {(firmware.versions || []).map(version => <option key={version} value={version}>{version}</option>)}
                          </select>
                          <input type="password" autoComplete="off" spellCheck={false} value={ciscoAccessToken} onChange={event => setCiscoAccessToken(event.target.value)} disabled={advisoryLoading} placeholder="Cisco API access token (not stored)" aria-label="Cisco API access token" style={{ width: "100%", padding: "6px 7px", marginBottom: 5, borderRadius: 4, border: `1px solid ${theme.border}`, background: theme.bg, color: theme.text, fontSize: 9 }} />
                          <button disabled={busy || ciscoAccessToken.trim().length < 20} onClick={lookupCiscoAdvisories} style={{ width: "100%", padding: "7px 9px", border: `1px solid ${theme.accent}`, borderRadius: 4, background: theme.accentGlow, color: theme.accent, fontWeight: 750, fontSize: 9, opacity: busy || ciscoAccessToken.trim().length < 20 ? 0.5 : 1 }}>
                            {advisoryLoading ? "Querying Cisco PSIRT…" : "Check detected version against Cisco PSIRT"}
                          </button>
                          {advisoryError && <div style={{ color: theme.medium, fontSize: 8, lineHeight: 1.4, marginTop: 6 }}>{advisoryError}</div>}
                          {firmware.advisory_lookup && (
                            <div style={{ marginTop: 8 }}>
                              <div style={{ color: theme.textDim, fontSize: 8, lineHeight: 1.5 }}>
                                Version <b style={{ color: theme.text }}>{firmware.advisory_lookup.version}</b> · {firmware.advisory_lookup.advisory_count ?? 0} stored result{firmware.advisory_lookup.advisory_count === 1 ? "" : "s"}{firmware.advisory_lookup.truncated ? " (response truncated)" : ""}
                              </div>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 4, margin: "5px 0" }}>
                                {Object.entries(firmware.advisory_lookup.severity_counts || {}).map(([severity, count]) => count > 0 && (
                                  <span key={severity} style={{ padding: "2px 5px", borderRadius: 3, border: `1px solid ${severity === "critical" ? theme.critical : severity === "high" ? theme.high : severity === "medium" ? theme.medium : theme.low}55`, color: severity === "critical" ? theme.critical : severity === "high" ? theme.high : severity === "medium" ? theme.medium : theme.low, fontSize: 8, textTransform: "uppercase" }}>{severity} {count}</span>
                                ))}
                              </div>
                              <div style={{ maxHeight: 360, overflowY: "auto", display: "grid", gap: 5 }}>
                                {(firmware.advisory_lookup.advisories || []).map(advisory => (
                                  <div key={advisory.advisory_id} style={{ padding: 7, border: `1px solid ${theme.border}`, borderRadius: 4, background: theme.bg }}>
                                    <div style={{ color: theme.text, fontSize: 9, fontWeight: 750, lineHeight: 1.35 }}>{advisory.title}</div>
                                    <div style={{ color: theme.textDim, fontSize: 8, marginTop: 3 }}>{advisory.advisory_id} · {advisory.severity || "unknown"}{advisory.cvss_base_score != null ? ` · CVSS ${advisory.cvss_base_score}` : ""}</div>
                                    {(advisory.cves || []).length > 0 && <div style={{ color: theme.textDim, fontSize: 8, marginTop: 3, overflowWrap: "anywhere" }}>CVEs: {advisory.cves.join(", ")}</div>}
                                    {(advisory.first_fixed || []).length > 0 && <div style={{ color: theme.green, fontSize: 8, marginTop: 3, overflowWrap: "anywhere" }}>First fixed: {advisory.first_fixed.join(", ")}</div>}
                                    {advisory.publication_url && <a href={advisory.publication_url} target="_blank" rel="noreferrer" style={{ display: "inline-block", marginTop: 4, color: theme.accent, fontSize: 8 }}>Open Cisco advisory ↗</a>}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                      <div style={{ color: theme.textDim, fontSize: 9, lineHeight: 1.45, marginTop: 9 }}>
                        This identifies local image structure and version clues; it does not prove a firmware image is genuine, trusted, or vulnerability-free. Proprietary or encrypted regions require a separate isolated extractor for deeper review.
                      </div>
                    </div>
                  )}

                  <div style={{ padding: 13, background: theme.surface, border: `1px solid ${theme.accent}66`, borderRadius: 7 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                      <h2 style={{ fontSize: 13 }}>Local LLM analyst</h2>
                      <button disabled={modelsLoading} onClick={() => refreshModels(lmUrl)} style={{ border: "none", background: "transparent", color: theme.accent, fontSize: 10, fontWeight: 700 }}>{modelsLoading ? "Loading…" : "Refresh models"}</button>
                    </div>
                    <div style={{ color: theme.textDim, fontSize: 10, lineHeight: 1.45, marginBottom: 8 }}>Grounded in this project only. It cannot execute files or change findings.</div>
                    <input value={lmUrl} onChange={event => setLmUrl(event.target.value)} aria-label="LM Studio URL" style={{ width: "100%", padding: "7px 8px", marginBottom: 6, borderRadius: 5, border: `1px solid ${theme.border}`, background: theme.bg, color: theme.text, fontSize: 10 }} />
                    <select value={selectedModel} onChange={event => setSelectedModel(event.target.value)} aria-label="Local model" style={{ width: "100%", padding: "7px 8px", marginBottom: 7, borderRadius: 5, border: `1px solid ${theme.border}`, background: theme.bg, color: theme.text, fontSize: 10 }}>
                      <option value="">{modelsLoading ? "Loading installed models…" : "Select an installed model"}</option>
                      {models.map(model => <option key={model.id} value={model.id}>{model.display_name}{model.loaded ? " · loaded" : ""}</option>)}
                    </select>
                    {modelsError && <div style={{ color: theme.medium, fontSize: 9, lineHeight: 1.4, marginBottom: 7 }}>{modelsError}</div>}
                    {chatMessages.length > 0 && (
                      <div style={{ maxHeight: 260, overflowY: "auto", display: "grid", gap: 6, padding: 7, marginBottom: 7, border: `1px solid ${theme.border}`, borderRadius: 5, background: theme.bg }}>
                        {chatMessages.map((message, index) => (
                          <div key={`${message.role}-${index}`} style={{ padding: 7, borderRadius: 5, background: message.role === "user" ? theme.accentGlow : message.role === "error" ? "#3b1f1f" : theme.surfaceAlt, color: message.role === "error" ? "#fca5a5" : theme.text, fontSize: 10, lineHeight: 1.5, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                            <div style={{ color: message.role === "user" ? theme.accent : message.private ? theme.high : theme.green, fontSize: 8, fontWeight: 800, marginBottom: 3 }}>{message.role === "user" ? "YOU" : message.role === "error" ? "ERROR" : message.private ? `LOCAL LLM · EXACT EVIDENCE INCLUDED${message.truncated ? " · PARTIAL" : ""}` : `LOCAL LLM · REDACTED RECORD${message.truncated ? " · PARTIAL" : ""}`}</div>
                            {message.content}
                            {message.notice && <div style={{ color: theme.medium, fontSize: 8, lineHeight: 1.4, marginTop: 6 }}>{message.notice}</div>}
                          </div>
                        ))}
                        <div ref={chatEndRef} />
                      </div>
                    )}
                    <textarea ref={chatInputRef} value={chatQuestion} onChange={event => setChatQuestion(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); askLocalModel(); } }} placeholder="Ask for a brief summary, explain a finding, or identify extracted values…" rows={3} style={{ width: "100%", resize: "vertical", padding: 8, borderRadius: 5, border: `1px solid ${theme.border}`, background: theme.bg, color: theme.text, fontSize: 10, lineHeight: 1.4 }} />
                    <label style={{ display: "flex", alignItems: "flex-start", gap: 6, color: theme.textDim, fontSize: 9, lineHeight: 1.35, margin: "7px 0" }}>
                      <input type="checkbox" checked={includePrivateInChat} disabled={!privateChatAvailable} onChange={event => setIncludePrivateInChat(event.target.checked)} />
                      Include exact extracted values for this question (desktop confirmation required)
                    </label>
                    <div style={{ color: theme.textDim, fontSize: 8, lineHeight: 1.4, margin: "-2px 0 7px" }}>Enable this when asking for credentials, flags, tokens, account names, or other exact values. Otherwise the model receives only the redacted record.</div>
                    {chatLoading && (
                      <div style={{ padding: "7px 8px", marginBottom: 7, borderRadius: 5, background: theme.accentGlow, color: theme.accent, fontSize: 9, lineHeight: 1.4 }}>
                        {chatStage || "Generating locally"} · {chatElapsedSeconds}s. The first answer after a model switch can take longer.
                      </div>
                    )}
                    <button disabled={!chatQuestion.trim() || !selectedModel || chatLoading} onClick={askLocalModel} style={{ width: "100%", padding: "8px 10px", border: `1px solid ${theme.accent}`, borderRadius: 5, background: theme.accentGlow, color: theme.accent, fontWeight: 750, opacity: !chatQuestion.trim() || !selectedModel || chatLoading ? 0.5 : 1 }}>
                      {chatLoading ? `Asking local model… ${chatElapsedSeconds}s` : "Ask about this project"}
                    </button>
                  </div>

                  <div style={{ padding: 13, background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 7 }}>
                    <h2 style={{ fontSize: 13, marginBottom: 9 }}>Artifact inventory</h2>
                    <div style={{ fontSize: 11, color: theme.textDim, lineHeight: 1.7 }}>
                      <div>Snapshot size: {inventory.bytes !== undefined ? formatBytes(inventory.bytes) : "Not analyzed"}</div>
                      <div>Analysis profile: {project.summary?.analysis_profile?.replaceAll("_", " ") || "Not analyzed"}</div>
                      <div>Analysis time: {project.summary?.duration_seconds !== undefined ? `${project.summary.duration_seconds} s` : "—"}</div>
                      <div>Rules checked: {project.summary?.rules_checked ?? "—"}</div>
                      <div>Bounded pattern evaluations: {project.summary?.rule_evaluations?.toLocaleString?.() ?? "—"}</div>
                      <div>Text bytes inspected: {inventory.analyzed_text_bytes !== undefined ? formatBytes(inventory.analyzed_text_bytes) : "—"}</div>
                      <div>Binary/metadata inventory only: {inventory.binary_or_unreadable_candidates !== undefined ? Number(inventory.binary_or_unreadable_candidates || 0) + Number(inventory.inventory_only_non_text_files || 0) : "—"}</div>
                      <div>Source scanning: {project.summary?.streamed_text_segment_bytes ? `${formatBytes(project.summary.streamed_text_segment_bytes)} bounded segments` : "Legacy 1 MiB read ceiling"}</div>
                      <div>Large text candidates skipped: {inventory.skipped_large_text_candidates ?? "—"}</div>
                      <div>Long lines segmented: {inventory.segmented_long_lines ?? "—"}</div>
                      <div>Files changed during scan: {inventory.changed_during_scan_files ?? "—"}</div>
                      <div>Finding matches omitted (lower bound): {project.summary?.findings_omitted_lower_bound ?? "—"}</div>
                      <div>Import warnings: {(project.intake?.warnings || []).length + (project.intake?.truncated_warnings || 0)}</div>
                      <div>Extracted files: {project.intake?.extracted_files || 0}</div>
                      <div>Input size ceiling: {intakeLimits.max_directory_bytes || intakeLimits.max_single_file_bytes ? formatBytes(project.source_type === "directory" ? intakeLimits.max_directory_bytes : intakeLimits.max_single_file_bytes) : "—"}</div>
                      {project.source_type === "directory" && <div>Project file ceiling: {intakeLimits.max_directory_files?.toLocaleString?.() || "—"}</div>}
                      {project.intake?.extracted_files > 0 && <div>Archive expanded ceiling: {formatBytes(intakeLimits.max_archive_uncompressed_bytes)}</div>}
                    </div>
                    <EvidencePager title="Languages" items={inventory.languages || []} theme={theme}
                      getKey={(language, index) => `${language.name}-${index}`}
                      searchText={language => language.name}
                      renderItem={language => <div style={{ marginTop: 3, fontSize: 10, color: theme.textDim }}>{language.name} · {language.files} file{language.files === 1 ? "" : "s"}</div>}
                    />
                    <EvidencePager title="Manifests" items={inventory.manifests || []} theme={theme}
                      getKey={(manifest, index) => `${manifest}-${index}`}
                      searchText={manifest => manifest}
                      renderItem={manifest => <div style={{ fontFamily: "monospace", fontSize: 9, color: theme.accent, overflowWrap: "anywhere", marginBottom: 3 }}>{manifest}</div>}
                    />
                  </div>

                  {(project.intake?.warnings || []).length > 0 && (
                    <div style={{ padding: 13, background: "#3b2f1f55", border: "1px solid #5c4721", borderRadius: 7 }}>
                      <h2 style={{ fontSize: 13, color: "#fcd34d", marginBottom: 8 }}>Intake exclusions</h2>
                      <EvidencePager title="Import warnings" items={project.intake.warnings || []} theme={theme}
                        getKey={(warning, index) => `${warning.entry}-${index}`}
                        searchText={warning => `${warning.entry} ${warning.reason}`}
                        renderItem={warning => <div style={{ fontSize: 10, color: theme.textDim, marginBottom: 5, overflowWrap: "anywhere" }}><b style={{ color: theme.text }}>{warning.entry}</b> — {warning.reason}</div>}
                      />
                      {(project.intake.truncated_warnings || 0) > 0 && <div style={{ fontSize: 9, color: theme.medium, marginTop: 6 }}>{project.intake.truncated_warnings} additional import warning{project.intake.truncated_warnings === 1 ? " was" : "s were"} not retained by the importer.</div>}
                    </div>
                  )}

                  {(project.summary?.limitations || []).length > 0 && (
                    <div style={{ padding: 13, background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 7 }}>
                      <h2 style={{ fontSize: 13, marginBottom: 8 }}>Current limits</h2>
                      {project.summary.limitations.map(item => <div key={item} style={{ color: theme.textDim, fontSize: 10, lineHeight: 1.5, marginBottom: 6 }}>• {item}</div>)}
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </section>
      </main>
    </div>
  );
}
