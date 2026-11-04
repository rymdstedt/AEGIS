import { useEffect, useState } from "react";
import HomeButton from "./HomeButton";

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

function VulnerabilityList({ record, theme }) {
  const rows = record.vulnerabilities || [];
  if (record.cve_data_status === "not_applicable") return null;
  if (!rows.length) {
    const message = record.cve_data_status === "not_provided"
      ? "This provider did not include CVE data in the response. That can be plan- or record-dependent and is not evidence that the host has no vulnerabilities."
      : "The provider returned its CVE field without candidates. That is not a patch or vulnerability assessment.";
    return <div style={{ margin: "10px 0", padding: 10, border: `1px dashed ${theme.border}`, borderRadius: 6, color: theme.textDim, fontSize: 11, lineHeight: 1.5 }}>{message}</div>;
  }
  return (
    <div style={{ margin: "12px 0" }}>
      <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 7 }}>Source-reported CVE candidates</div>
      <div style={{ overflowX: "auto", border: `1px solid ${theme.border}`, borderRadius: 7 }}>
        <table style={{ width: "100%", minWidth: 720, borderCollapse: "collapse", fontSize: 11 }}>
          <thead><tr style={{ textAlign: "left", color: theme.textDim, background: theme.surfaceAlt }}>
            {["CVE", "Service", "Severity", "Passive evidence", "CISA KEV"].map(label => <th key={label} style={{ padding: 8 }}>{label}</th>)}
          </tr></thead>
          <tbody>{rows.map((item, index) => <tr key={`${item.id}-${item.service_port}-${index}`} style={{ borderTop: `1px solid ${theme.border}` }}>
            <td style={{ padding: 8, whiteSpace: "nowrap" }}><a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}`} target="_blank" rel="noreferrer" style={{ color: theme.accent }}>{item.id}</a></td>
            <td style={{ padding: 8, whiteSpace: "nowrap" }}>{item.service_port ? `${item.service_port} ${item.service_protocol || ""}` : "Host-level only"}</td>
            <td style={{ padding: 8, whiteSpace: "nowrap" }}>{item.severity || "Not supplied"}{item.cvss_score !== null && item.cvss_score !== undefined ? <div style={{ color: theme.textDim }}>CVSS {item.cvss_version || ""} {item.cvss_score}</div> : null}</td>
            <td style={{ padding: 8, lineHeight: 1.45 }}>{item.basis}<div style={{ color: theme.textDim, fontSize: 10, marginTop: 3 }}>{item.source}</div></td>
            <td style={{ padding: 8, color: item.cisa_kev ? theme.critical : theme.textDim, fontWeight: item.cisa_kev ? 700 : 400 }}>{item.cisa_kev === true ? "Listed" : item.cisa_kev === false ? "Not listed" : "Not checked"}</td>
          </tr>)}</tbody>
        </table>
      </div>
      <div style={{ color: theme.textDim, fontSize: 10, lineHeight: 1.5, marginTop: 6 }}>These are passive source associations. A CVE match—even a CISA KEV match—does not confirm that this host is vulnerable, exploitable, or compromised.</div>
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
  const credentialApiAvailable = typeof window.aegisDesktop?.loadExposureCredentials === "function";
  const [credentialStorage, setCredentialStorage] = useState({
    loading: credentialApiAvailable, available: false, protection: "",
  });
  const [rememberCredentials, setRememberCredentials] = useState(true);
  const [credentialMessage, setCredentialMessage] = useState("");
  const field = { width: "100%", boxSizing: "border-box", background: theme.bg, color: theme.text, border: `1px solid ${theme.border}`, borderRadius: 7, padding: "10px 12px", fontSize: 13, fontFamily: "inherit" };
  const button = { background: theme.accent, color: "white", border: 0, borderRadius: 7, padding: "10px 16px", fontWeight: 700, fontFamily: "inherit", cursor: loading ? "wait" : "pointer" };
  const label = { display: "grid", gap: 7, fontSize: 13, fontWeight: 700 };
  const hint = { color: theme.textDim, fontSize: 11, fontWeight: 400, lineHeight: 1.5 };

  useEffect(() => {
    let active = true;
    if (!credentialApiAvailable) {
      setCredentialStorage({ loading: false, available: false, protection: "" });
      return () => { active = false; };
    }
    window.aegisDesktop.loadExposureCredentials().then(status => {
      if (!active) return;
      setCredentialStorage({
        loading: false,
        available: Boolean(status.available),
        protection: status.protection || "protected storage",
      });
      if (status.credentials?.censys) setCensysPat(current => current || status.credentials.censys);
      if (status.credentials?.netlas) setNetlasKey(current => current || status.credentials.netlas);
      if (status.stored?.length) setCredentialMessage(`Loaded saved ${status.stored.join(" and ")} credentials.`);
      else if (!status.available) setCredentialMessage("Protected credential storage is unavailable on this device.");
    }).catch(() => {
      if (!active) return;
      setCredentialStorage({ loading: false, available: true, protection: "protected storage" });
      setCredentialMessage("Saved credentials could not be unlocked. You can forget them and save fresh keys.");
    });
    return () => { active = false; };
  }, [credentialApiAvailable]);

  const saveUsedCredentials = async (lookupResult) => {
    if (!rememberCredentials || !credentialStorage.available) return;
    const records = lookupResult?.records || [];
    const censysRejected = records.some(record => (
      record.source === "Censys Platform" && record.note?.includes("rejected the API token")
    ));
    const netlasRejected = lookupResult?.note?.includes("rejected the API token") || records.some(record => (
      record.source?.startsWith("Netlas") && record.note?.includes("rejected the API token")
    ));
    const updates = {};
    if (mode === "owned" && censysPat && !censysRejected) updates.censys = censysPat;
    if (netlasKey && !netlasRejected) updates.netlas = netlasKey;
    if (!Object.keys(updates).length) return;
    try {
      const status = await window.aegisDesktop.saveExposureCredentials(updates);
      setCredentialMessage(`Saved ${status.stored.join(" and ")} credentials using ${status.protection}.`);
    } catch {
      setCredentialMessage("The lookup completed, but AEGIS could not save the provider credentials securely.");
    }
  };

  const forgetCredentials = async () => {
    if (loading || typeof window.aegisDesktop?.clearExposureCredentials !== "function") return;
    try {
      await window.aegisDesktop.clearExposureCredentials();
      setCensysPat("");
      setNetlasKey("");
      setCredentialMessage("Saved provider credentials were removed from this device.");
    } catch {
      setCredentialMessage("AEGIS could not remove the saved provider credentials.");
    }
  };

  const submit = async (requestedStart = 0) => {
    if (loading) return;
    setError("");
    if (mode === "owned" || requestedStart === 0) setResult(null);
    setLoading(true);
    try {
      const endpoint = mode === "owned" ? "/api/exposure/owned/check" : "/api/exposure/world/search";
      const payload = mode === "owned"
        ? { targets, censys_pat: censysPat || null, netlas_key: netlasKey || null }
        : { query, netlas_key: netlasKey || null, start: requestedStart };
      const response = await apiFetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The provider lookup failed.");
      setResult(data);
      await saveUsedCredentials(data);
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
        <HomeButton onClick={onBack} theme={theme} style={{ marginBottom: 18 }} />
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
              <input type="password" autoComplete="new-password" aria-label="Censys Personal Access Token" value={censysPat} onChange={event => setCensysPat(event.target.value)} disabled={loading} style={field} />
              <span style={hint}>Exact IP lookups can return service-level CVE, CVSS, and KEV metadata when the Censys plan and host record include it. One domain checks web ports 80 and 443; every check is capped at ten Censys lookups.</span>
            </label>
          </> : <>
            <label style={label}>Netlas search query
              <input aria-label="Netlas search query" value={query} onChange={event => { setQuery(event.target.value); setResult(null); }} disabled={loading} placeholder={'http.title:"StoreView" or prot7:modbus'} style={field} />
              <span style={hint}>A worldwide passive search loads 20 indexed responses at a time. Use Previous and Next to browse more without downloading the whole result set. These assets may belong to others.</span>
            </label>
          </>}
          <label style={label}>Netlas API key <span style={hint}>(optional)</span>
            <input type="password" autoComplete="new-password" aria-label="Netlas API key" value={netlasKey} onChange={event => setNetlasKey(event.target.value)} disabled={loading} style={field} />
            <span style={hint}>Netlas allows limited guest lookups. A Community key increases provider limits, but its free tier does not include CVE data; AEGIS can still show CVEs reported by Censys or Shodan for owned IP lookups.</span>
          </label>

          <div style={{ padding: 12, border: `1px solid ${theme.border}`, borderRadius: 7, background: theme.bg, display: "grid", gap: 8 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: credentialStorage.available ? theme.text : theme.textDim }}>
              <input type="checkbox" checked={rememberCredentials && credentialStorage.available} disabled={!credentialStorage.available || credentialStorage.loading} onChange={event => setRememberCredentials(event.target.checked)} />
              Save provider keys securely on this device
            </label>
            <div style={hint}>
              {credentialStorage.loading
                ? "Checking protected credential storage…"
                : credentialStorage.available
                  ? `Keys are encrypted through ${credentialStorage.protection} and are never stored by the Python API.`
                  : "Protected saving is available in the packaged AEGIS desktop app, not the browser preview."}
            </div>
            {credentialStorage.available && <div><button type="button" onClick={forgetCredentials} disabled={loading} style={{ ...button, padding: "6px 10px", fontSize: 11, background: theme.surfaceAlt, border: `1px solid ${theme.border}` }}>Forget saved keys</button></div>}
            {credentialMessage && <div role="status" style={{ ...hint, color: credentialMessage.includes("could not") ? theme.high : theme.textDim }}>{credentialMessage}</div>}
          </div>

          <div><button type="button" onClick={() => submit(0)} disabled={!selected || loading} style={{ ...button, opacity: !selected || loading ? 0.55 : 1 }}>{loading ? "Checking indexes…" : mode === "owned" ? "Check indexed exposure" : "Search worldwide index"}</button></div>
          <span style={hint}>Entered assets or queries are sent only to the selected index providers. This workflow makes no active scan or login attempt against discovered systems.</span>
          {error && <div role="alert" style={{ color: theme.critical }}>{error}</div>}
        </div>

        {result?.mode === "owned" && <section style={{ marginTop: 20 }}>
          <p role="status" style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>{result.interpretation} Checked {new Date(result.checked_at).toLocaleString()}. {result.targets_total} targets, {result.cve_candidates_total} unique source-reported CVE candidates, {result.kev_status === "complete" ? `${result.kev_matches_total} CISA KEV matches` : `KEV status: ${result.kev_status}`}.</p>
          {result.cve_product_enrichment?.products_checked > 0 && <p style={{ color: theme.textDim, fontSize: 11, lineHeight: 1.5 }}>AEGIS checked {result.cve_product_enrichment.products_checked} provider-reported product{result.cve_product_enrichment.products_checked === 1 ? "" : "s"} against bounded CVE indexes and added {result.cve_product_enrichment.candidates_added} candidate{result.cve_product_enrichment.candidates_added === 1 ? "" : "s"}. Status: {result.cve_product_enrichment.status}.</p>}
          {result.records.map((record, index) => <article key={`${record.target}-${record.source}-${index}`} style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 8, padding: 16, marginBottom: 12 }}>
            <div style={{ fontWeight: 700 }}>{record.target}{record.web_port ? `:${record.web_port}` : ""} · {record.source}</div>
            <div style={{ color: record.status === "unavailable" ? theme.critical : theme.textDim, fontSize: 12, margin: "5px 0 10px" }}>{record.status.replaceAll("_", " ")} · {record.note}</div>
            <VulnerabilityList record={record} theme={theme} />
            <ObservationList items={record.observations} theme={theme} />
          </article>)}
          <p style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>For stronger evidence of malware or malicious traffic on networks you own, <a href="https://www.shadowserver.org/what-we-do/network-reporting/get-reports/" target="_blank" rel="noreferrer" style={{ color: theme.accent }}>Shadowserver offers vetted network-owner reports</a>. These reports are separate from this exposure check.</p>
        </section>}

        {result?.mode === "world" && <section style={{ marginTop: 20 }}>
          <p role="status" style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>{result.interpretation} Checked {new Date(result.checked_at).toLocaleString()}.</p>
          <p style={{ color: result.status === "unavailable" ? theme.critical : theme.textDim, fontSize: 12 }}>{result.source}: {result.status.replaceAll("_", " ")}. {result.note}</p>
          <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 8, padding: 10 }}><ObservationList items={result.observations} theme={theme} /></div>
          <div aria-label="Worldwide search pagination" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, marginTop: 12 }}>
            <button type="button" onClick={() => submit(result.start - result.page_size)} disabled={!result.has_previous || loading} style={{ ...button, background: theme.surfaceAlt, border: `1px solid ${theme.border}`, opacity: !result.has_previous || loading ? 0.45 : 1 }}>← Previous</button>
            <span style={{ color: theme.textDim, fontSize: 12 }}>Page {result.page}</span>
            <button type="button" onClick={() => submit(result.start + result.page_size)} disabled={!result.has_next || loading} style={{ ...button, background: theme.surfaceAlt, border: `1px solid ${theme.border}`, opacity: !result.has_next || loading ? 0.45 : 1 }}>Next →</button>
          </div>
          <p style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>Netlas pages are passive search leads. Product identity, support status, patch state, vulnerability, and compromise require separate evidence.</p>
        </section>}
      </div>
    </div>
  );
}
