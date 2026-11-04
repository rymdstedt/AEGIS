import HomeButton from "./HomeButton";

export default function PageHeader({ title, subtitle, onBack, theme, badge, actions }) {
  return (
    <header className="aegis-page-header">
      <div className="aegis-page-header-main">
        <HomeButton onClick={onBack} theme={theme} compact />
        <div className="aegis-page-header-divider" aria-hidden="true" />
        <div className="aegis-page-identity">
          <div className="aegis-page-kicker">AEGIS <span aria-hidden="true">/</span> WORKSPACE</div>
          <div className="aegis-page-title">{title}</div>
          {subtitle && <div className="aegis-page-subtitle">{subtitle}</div>}
        </div>
      </div>
      {(badge || actions) && <div className="aegis-page-header-actions">{badge && <span className="aegis-page-badge">{badge}</span>}{actions}</div>}
    </header>
  );
}
