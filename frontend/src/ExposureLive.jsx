import { useState } from "react";

function ObservationList({ items, theme }) {
  if (!items.length) return <p style={{ color: theme.textDim, fontSize: 12 }}>No service observations returned.</p>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", minWidth: 630, borderCollapse: "collapse", fontSize: 12 }}>
        <thead><tr style={{ textAlign: "left", color: theme.textDim }}>
          {["Address", "Host", "Service", "Title / product", "Review group", "Observed"].map(label => <th key={label} style={{ padding: 8 }}>{label}</th>)}
        </tr></thead>
        <tbody>{items.map((item, index) => <tr key={`${item.ip}-${item.port}-${index}`} style={{ borderTop: `1px solid ${theme.border}` }}>
          <td style={{ padding: 8, whiteSpace: "nowrap" }}>{item.ip}</td>
          <td style={{ padding: 8, overflowWrap: "anywhere" }}>{item.host || "—"}</td>
          <td style={{ padding: 8, whiteSpace: "nowrap" }}>{item.port ?? "—"} {item.protocol}</td>
          <td style={{ padding: 8, overflowWrap: "anywhere" }}>{item.title || item.product || "Unidentified"}{item.version && ` ${item.version}`}</td>
          <td style={{ padding: 8 }}>{item.review_group}<div style={{ color: theme.textDim, fontSize: 10 }}>{item.review_basis}</div></td>
          <td style={{ padding: 8, whiteSpace: "nowrap" }}>{item.scan_time || "Not provided"}</td>
        </tr>)}</tbody>
      </table>
    </div>
  );
}

export default function ExposureLive({ apiFetch, theme, onBack, onImport }) {
  const [mode, setMode] = useState("owned");
  const [targets, setTargets] = useState("");
  const [query, setQuery] = useState("");
  const [censysPat, setCensysPat] = useState("");
  const [netlasKey, setNetlasKey] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const field = { width: "100%", boxSizing: "border-box", background: theme.bg, color: theme.text, border: `1px solid ${theme.border}`, borderRadius: 7, padding: "10px 12px", fontSize: 13, fontFamily: "inherit" };
  const button = { background: theme.accent, color: "white", border: 0, borderRadius: 7, padding: "10px 16px", fontWeight: 700, fontFamily: "inherit", cursor: loading ? "wait" : "pointer" };
  const label = { display: "grid", gap: 7, fontSize: 13, fontWeight: 700 };
  const hint = { color: theme.textDim, fontSize: 11, fontWeight: 400, lineHeight: 1.5 };

  const submit = async () => {
    if (loading) return;
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const endpoint = mode === "owned" ? "/api/exposure/owned/check" : "/api/exposure/world/search";
      const payload = mode === "owned"
        ? { targets, censys_pat: censysPat || null, netlas_key: netlasKey || null }
        : { query, netlas_key: netlasKey };
      const response = await apiFetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The provider lookup failed.");
      setResult(data);
    } catch (cause) {
      setError(cause.message || "The provider lookup failed.");
    } finally {
      setLoading(false);
    }
  };

  const selected = mode === "owned" ? targets.trim() : query.trim();
  return (
    <div style={{ minHeight: "100vh", background: theme.bg, color: theme.text, padding: "20px clamp(12px, 4vw, 40px)", boxSizing: "border-box", fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <button type="button" onClick={onBack} style={{ ...button, background: theme.surfaceAlt, border: `1px solid ${theme.border}`, marginBottom: 18 }}>← Back to start</button>
        <h1 style={{ fontSize: 24, margin: "0 0 8px" }}>Exposure Inventory</h1>
        <p style={{ color: theme.textDim, lineHeight: 1.5 }}>Check published observations from credible indexes. AEGIS never connects to devices found in these views. An exposure, a reported CVE, a CVE exploited somewhere, and a compromised device are different findings.</p>
        <div role="tablist" aria-label="Exposure source" style={{ display: "flex", flexWrap: "wrap", gap: 8, margin: "18px 0" }}>
          {["owned", "world"].map(value => <button key={value} type="button" role="tab" aria-selected={mode === value} onClick={() => { setMode(value); setResult(null); setError(""); }} style={{ ...button, background: mode === value ? theme.accent : theme.surfaceAlt, border: `1px solid ${theme.border}` }}>{value === "owned" ? "My assets" : "Worldwide index"}</button>)}
          <button type="button" onClick={onImport} style={{ ...button, background: theme.surfaceAlt, border: `1px solid ${theme.border}` }}>Import Censys file</button>
        </div>
        <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 10, padding: 20, display: "grid", gap: 16 }}>
          {mode === "owned" ? <>
            <label style={label}>Public IPs, small CIDRs, or domains you control
              <textarea value={targets} onChange={event => { setTargets(event.target.value); setResult(null); }} disabled={loading} aria-label="Owned public assets" placeholder="Enter your public IPs or domains, one per line" rows={3} style={{ ...field, resize: "vertical" }} />
              <span style={hint}>Up to five public targets as a Netlas guest, or 16 with a Netlas key. CIDRs may contain up to 16 addresses. Domains are checked without DNS or direct contact.</span>
            </label>
            <label style={label}>Censys Personal Access Token <span style={hint}>(optional)</span>
              <input type="password" autoComplete="off" aria-label="Censys Personal Access Token" value={censysPat} onChange={event => setCensysPat(event.target.value)} disabled={loading} style={field} />
              <span style={hint}>Free supports exact lookups. One IP can use one credit; one domain checks web ports 80 and 443 and can use two. This check is capped at ten Censys lookups.</span>
            </label>
          </> : <>
            <label style={label}>Netlas search query
              <input aria-label="Netlas search query" value={query} onChange={event => { setQuery(event.target.value); setResult(null); }} disabled={loading} placeholder={'http.title:"StoreView" or prot7:modbus'} style={field} />
              <span style={hint}>A worldwide passive search returns only the first 20 service observations. Search by a specific title or protocol. These assets may belong to others.</span>
            </label>
          </>}
          <label style={label}>Netlas API key <span style={hint}>(optional)</span>
            <input type="password" autoComplete="off" aria-label="Netlas API key" value={netlasKey} onChange={event => setNetlasKey(event.target.value)} disabled={loading} style={field} />
            <span style={hint}>Netlas allows a small number of guest lookups. A free Community key raises the available limits for personal, noncommercial use. Its free tier has no CVE data.</span>
          </label>
          <div><button type="button" onClick={submit} disabled={!selected || loading} style={{ ...button, opacity: !selected || loading ? 0.55 : 1 }}>{loading ? "Checking indexes…" : mode === "owned" ? "Check indexed exposure" : "Search worldwide index"}</button></div>
          <span style={hint}>Entered assets or queries are sent to the selected providers. Keys are used for this request only and are not saved. This workflow makes no active scan or login attempt.</span>
          {error && <div role="alert" style={{ color: theme.critical }}>{error}</div>}
        </div>

        {result?.mode === "owned" && <section style={{ marginTop: 20 }}>
          <p role="status" style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>{result.interpretation} Checked {new Date(result.checked_at).toLocaleString()}. {result.targets_total} targets, {result.cve_candidates_total} source-reported CVE candidates, {result.kev_status === "complete" ? `${result.kev_matches_total} CISA KEV matches` : `KEV status: ${result.kev_status}`}.</p>
          {result.records.map((record, index) => <article key={`${record.target}-${record.source}-${index}`} style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 8, padding: 16, marginBottom: 12 }}>
            <div style={{ fontWeight: 700 }}>{record.target}{record.web_port ? `:${record.web_port}` : ""} · {record.source}</div>
            <div style={{ color: record.status === "unavailable" ? theme.critical : theme.textDim, fontSize: 12, margin: "5px 0 10px" }}>{record.status.replaceAll("_", " ")} · {record.note}</div>
            {record.cve_candidates.length > 0 && <p style={{ fontSize: 12, lineHeight: 1.5 }}><strong>Host-level CVE suggestions:</strong> {record.cve_candidates.join(", ")}. {record.kev_matches.length > 0 && <strong>CISA KEV lists {record.kev_matches.join(", ")}. </strong>}This does not prove the host is vulnerable or compromised.</p>}
            <ObservationList items={record.observations} theme={theme} />
          </article>)}
          <p style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>For stronger evidence of malware or malicious traffic on networks you own, <a href="https://www.shadowserver.org/what-we-do/network-reporting/get-reports/" target="_blank" rel="noreferrer" style={{ color: theme.accent }}>Shadowserver offers vetted network-owner reports</a>. These reports are separate from this exposure check.</p>
        </section>}

        {result?.mode === "world" && <section style={{ marginTop: 20 }}>
          <p role="status" style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>{result.interpretation} Checked {new Date(result.checked_at).toLocaleString()}.</p>
          <p style={{ color: result.status === "unavailable" ? theme.critical : theme.textDim, fontSize: 12 }}>{result.source}: {result.status.replaceAll("_", " ")}. {result.note}</p>
          <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 8, padding: 10 }}><ObservationList items={result.observations} theme={theme} /></div>
          <p style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>The free Netlas tier has no CVE data. Product identity, support status, patch state, vulnerability, and compromise require separate evidence.</p>
        </section>}
      </div>
    </div>
  );
}
