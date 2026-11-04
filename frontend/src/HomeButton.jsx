export default function HomeButton({ onClick, theme, compact = false, style = {} }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="AEGIS home"
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 7,
        minHeight: 34,
        padding: compact ? "7px 10px" : "8px 13px",
        borderRadius: 7,
        border: `1px solid ${theme.border}`,
        background: theme.surfaceAlt,
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
