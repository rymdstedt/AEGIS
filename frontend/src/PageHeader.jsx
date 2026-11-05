export default function PageHeader({ title, subtitle, badge, actions }) {
  return (
    <header className="aegis-page-header">
      <div className="aegis-page-header-main">
        <div className="aegis-page-identity">
          <div className="aegis-page-title">{title}</div>
          {subtitle && <div className="aegis-page-subtitle">{subtitle}</div>}
        </div>
      </div>
      {(badge || actions) && <div className="aegis-page-header-actions">{badge && <span className="aegis-page-badge">{badge}</span>}{actions}</div>}
    </header>
  );
}
