import { useMemo, useState } from "react";

const MAX_FILE_BYTES = 2_000_000;
const GROUPS = ["All", "OT / control", "Management candidate", "Other service"];

function Stat({ label, value, theme }) {
  return (
    <div style={{ padding: 12, background: theme.surfaceAlt, border: `1px solid ${theme.border}`, borderRadius: 8 }}>
      <div style={{ color: theme.textDim, fontSize: 11 }}>{label}</div>
      <div style={{ color: theme.text, fontSize: 20, fontWeight: 700, marginTop: 3 }}>{value}</div>
    </div>
  );
}

export default function ExposureInventory({ apiFetch, theme, onBack }) {
  const [file, setFile] = useState(null);
  const [scope, setScope] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [group, setGroup] = useState("All");
  const visible = useMemo(() => (result?.observations || []).filter(
    item => group === "All" || item.review_group === group,
  ), [result, group]);

  const analyze = async () => {
    if (!file || !scope.trim() || loading) return;
    setError("");
    setResult(null);
    if (file.size > MAX_FILE_BYTES) {
      setError("Choose a Censys export smaller than 2 MB.");
      return;
    }
    setLoading(true);
    try {
      const response = await apiFetch("/api/exposure/censys/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file.name, content: await file.text(), scope }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The export could not be analyzed.");
      setResult(data);
      setGroup("All");
    } catch (cause) {
      setError(cause.message || "The export could not be analyzed.");
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    width: "100%", boxSizing: "border-box", background: theme.bg, color: theme.text,
    border: `1px solid ${theme.border}`, borderRadius: 7, padding: "10px 12px", fontSize: 13,
    fontFamily: "inherit",
  };
  const buttonStyle = {
    background: theme.accent, color: "white", border: 0, borderRadius: 7,
    padding: "10px 16px", fontWeight: 700, cursor: loading ? "wait" : "pointer", fontFamily: "inherit",
  };

  return (
    <div style={{ minHeight: "100vh", background: theme.bg, color: theme.text, padding: "20px clamp(12px, 4vw, 40px)", boxSizing: "border-box", fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <button type="button" onClick={onBack} style={{ ...buttonStyle, background: theme.surfaceAlt, border: `1px solid ${theme.border}`, marginBottom: 18 }}>← Back to start</button>
        <h1 style={{ fontSize: 24, margin: "0 0 8px" }}>Exposure Inventory</h1>
        <p style={{ color: theme.textDim, lineHeight: 1.5, margin: "0 0 20px" }}>
          Review internet-facing services from a Censys export for IP addresses you own. AEGIS reads the file locally and does not contact the listed devices or Censys.
        </p>

        <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 10, padding: 20, display: "grid", gap: 16 }}>
          <label style={{ display: "grid", gap: 7, fontSize: 13, fontWeight: 700 }}>
            Censys host export
            <input type="file" accept=".csv,.json,.jsonl,text/csv,application/json" aria-label="Censys host export" disabled={loading} onChange={event => { setFile(event.target.files?.[0] || null); setResult(null); setError(""); }} style={inputStyle} />
            <span style={{ color: theme.textDim, fontWeight: 400, fontSize: 11 }}>CSV, JSON, or JSONL; up to 2 MB and 5,000 host records. Include IP plus service ports, protocols, software, or HTTP page titles.</span>
          </label>
          <label style={{ display: "grid", gap: 7, fontSize: 13, fontWeight: 700 }}>
            Owned IP addresses or CIDR ranges
            <textarea value={scope} disabled={loading} onChange={event => { setScope(event.target.value); setResult(null); }} placeholder={"192.0.2.0/24\n2001:db8:1234::/64"} rows={3} aria-label="Owned IP addresses or CIDR ranges" style={{ ...inputStyle, resize: "vertical" }} />
            <span style={{ color: theme.textDim, fontWeight: 400, fontSize: 11 }}>One entry per line. Results outside these ranges are counted but never displayed.</span>
          </label>
          <div><button type="button" onClick={analyze} disabled={!file || !scope.trim() || loading} style={{ ...buttonStyle, opacity: !file || !scope.trim() || loading ? 0.55 : 1 }}>{loading ? "Analyzing…" : "Analyze export"}</button></div>
          {error && <div role="alert" style={{ color: theme.critical }}>{error}</div>}
        </div>

        {result && (
          <section style={{ marginTop: 20 }}>
            <div role="status" style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5, marginBottom: 12 }}>
              {result.interpretation} No DNS lookup, active scan, model request, or controller action was performed.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(145px, 1fr))", gap: 10 }}>
              <Stat label="Imported hosts" value={result.records_total} theme={theme} />
              <Stat label="Hosts in scope" value={result.records_in_scope} theme={theme} />
              <Stat label="Service observations" value={result.observations_total} theme={theme} />
              <Stat label="Suggested products" value={result.identified_total} theme={theme} />
              <Stat label="OT / control candidates" value={result.ot_total} theme={theme} />
            </div>
            <p style={{ color: theme.textDim, fontSize: 12 }}>
              {result.records_out_of_scope} out-of-scope records withheld; {result.records_invalid_ip} records had no valid IP.
              {result.observations_omitted > 0 && ` ${result.observations_omitted} service observations omitted by the 500-result display limit.`}
            </p>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, margin: "18px 0 10px", flexWrap: "wrap" }}>
              <h2 style={{ fontSize: 17, margin: 0 }}>Observed services</h2>
              <select aria-label="Filter observed services" value={group} onChange={event => setGroup(event.target.value)} style={{ ...inputStyle, width: "auto" }}>
                {GROUPS.map(value => <option key={value} value={value}>{value}</option>)}
              </select>
            </div>
            <div style={{ overflowX: "auto", background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: 8 }}>
              <table style={{ width: "100%", minWidth: 760, borderCollapse: "collapse", fontSize: 12 }}>
                <thead><tr style={{ textAlign: "left", color: theme.textDim, borderBottom: `1px solid ${theme.border}` }}>
                  {["Address", "Port / protocol", "Page title", "Suggested product", "Review group", "Observed", "Patch status"].map(label => <th key={label} style={{ padding: 10 }}>{label}</th>)}
                </tr></thead>
                <tbody>
                  {visible.map((item, index) => (
                    <tr key={`${item.ip}-${item.port}-${item.title}-${index}`} style={{ borderBottom: `1px solid ${theme.border}` }}>
                      <td style={{ padding: 10, whiteSpace: "nowrap" }}>{item.ip}</td>
                      <td style={{ padding: 10, whiteSpace: "nowrap" }}>{item.port ?? "—"} {item.protocol}</td>
                      <td style={{ padding: 10, maxWidth: 220, overflowWrap: "anywhere" }}>{item.title || "—"}</td>
                      <td style={{ padding: 10 }}>{item.product ? `${item.vendor ? `${item.vendor} ` : ""}${item.product}${item.version ? ` ${item.version}` : ""}` : "Unidentified"}<div style={{ color: theme.textDim, fontSize: 10 }}>{item.identity_source}</div></td>
                      <td style={{ padding: 10 }}>{item.review_group}<div style={{ color: theme.textDim, fontSize: 10 }}>{item.review_basis}</div></td>
                      <td style={{ padding: 10, whiteSpace: "nowrap" }}>{item.scan_time || "Not provided"}</td>
                      <td style={{ padding: 10 }}>Unknown</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {visible.length === 0 && <div style={{ color: theme.textDim, padding: 20 }}>No service observations in this view.</div>}
            </div>
            <p style={{ color: theme.textDim, fontSize: 12, lineHeight: 1.5 }}>
              An observed version is a lead for review. This inventory does not determine whether a device is end-of-life, patched, vulnerable, or compromised.
            </p>
          </section>
        )}
      </div>
    </div>
  );
}
