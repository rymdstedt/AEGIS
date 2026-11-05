import AegisLogo from "./AegisLogo";
import UiIcon from "./UiIcon";

const navigation = [
  { id: "assessment", label: "New assessment", shortLabel: "Assessment", icon: "assessment" },
  { id: "exposure", label: "Exposure", shortLabel: "Exposure", icon: "exposure" },
  { id: "application", label: "Application research", shortLabel: "Research", icon: "research" },
  { id: "diagnostics", label: "Diagnostics", shortLabel: "Diagnostics", icon: "diagnostics" },
];

const titles = {
  assessment: "New assessment",
  exposure: "Exposure inventory",
  application: "Application research",
  diagnostics: "Diagnostics",
};

export default function WorkspaceShell({ active, onNavigate, connected, phase, children }) {
  return (
    <div className="workspace-shell">
      <aside className="workspace-sidebar">
        <div className="workspace-brand">
          <AegisLogo size={38} />
          <div>
            <div className="workspace-brand-name">AEGIS</div>
            <div className="workspace-brand-caption">Hybrid Solutions</div>
          </div>
        </div>

        <nav className="workspace-nav" aria-label="AEGIS workspaces">
          <div className="workspace-nav-label">Workspace</div>
          {navigation.map(item => (
            <button
              key={item.id}
              type="button"
              className={`workspace-nav-item${active === item.id ? " is-active" : ""}`}
              aria-label={item.label}
              aria-current={active === item.id ? "page" : undefined}
              title={item.label}
              onClick={() => onNavigate(item.id)}
            >
              <UiIcon name={item.icon} />
              <span className="workspace-nav-long">{item.label}</span>
              <span className="workspace-nav-short">{item.shortLabel}</span>
            </button>
          ))}
        </nav>

        <div className="workspace-sidebar-status">
          <div className="workspace-status-row">
            <span className={`workspace-status-dot${connected ? " is-online" : ""}`} />
            <span>{connected ? "Backend connected" : "Backend offline"}</span>
          </div>
          <div className="workspace-status-detail">Local processing · private by design</div>
        </div>
      </aside>

      <section className="workspace-stage">
        <header className="workspace-commandbar">
          <div className="workspace-command-title">
            <span>AEGIS</span>
            <i aria-hidden="true" />
            <strong>{titles[active] || "Security workspace"}</strong>
          </div>
          <div className="workspace-command-status">
            {phase && <span className="workspace-phase">{phase}</span>}
            <span className={`workspace-connection${connected ? " is-online" : ""}`}>
              <span />{connected ? "Connected" : "Disconnected"}
            </span>
          </div>
        </header>
        <main className="workspace-content">{children}</main>
      </section>
    </div>
  );
}
