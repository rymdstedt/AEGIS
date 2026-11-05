import UiIcon from "./UiIcon";

export default function NetworkGraphic() {
  return (
    <div className="network-graphic" aria-label="Assessment flow from client to target and evidence store">
      <svg className="network-graphic-lines" viewBox="0 0 760 180" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <pattern id="aegis-dot-grid" width="18" height="18" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="currentColor" />
          </pattern>
        </defs>
        <rect width="760" height="180" fill="url(#aegis-dot-grid)" />
        <path d="M72 94h238c44 0 49-28 92-28h188" />
        <path className="network-graphic-signal" d="M72 94h238c44 0 49-28 92-28h188" />
      </svg>
      <div className="network-node network-node-client"><UiIcon name="assessment" /><span>Assessment client</span></div>
      <div className="network-node network-node-target"><UiIcon name="status" /><span>Target</span></div>
      <div className="network-node network-node-evidence"><UiIcon name="exposure" /><span>Evidence store</span></div>
    </div>
  );
}
