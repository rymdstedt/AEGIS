export default function HomeButton({ onClick, theme, compact = false, style = {} }) {
  return (
    <button
      className="aegis-home-button"
      type="button"
      onClick={onClick}
      aria-label="AEGIS home"
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 7,
        minHeight: 38,
        padding: compact ? "8px 12px" : "9px 14px",
        borderRadius: 9,
        border: `1px solid ${theme.border}`,
        background: theme.surface,
        color: theme.text,
        fontSize: compact ? 11 : 12,
        fontWeight: 700,
        fontFamily: "inherit",
        cursor: "pointer",
        ...style,
      }}
    >
      <span aria-hidden="true" style={{ color: theme.accent, fontSize: 15, lineHeight: 1 }}>⌂</span>
      AEGIS home
    </button>
  );
}
