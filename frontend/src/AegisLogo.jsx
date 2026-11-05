export default function AegisLogo({ size = 36, className = "" }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 512 512"
      role="img"
      aria-label="AEGIS"
    >
      <defs>
        <linearGradient id="aegis-logo-bg" x1="64" y1="32" x2="448" y2="480" gradientUnits="userSpaceOnUse">
          <stop stopColor="#111a2e" />
          <stop offset="1" stopColor="#060a12" />
        </linearGradient>
        <linearGradient id="aegis-logo-edge" x1="128" y1="96" x2="386" y2="414" gradientUnits="userSpaceOnUse">
          <stop stopColor="#56e6ff" />
          <stop offset="0.52" stopColor="#2a8dff" />
          <stop offset="1" stopColor="#a855f7" />
        </linearGradient>
      </defs>
      <rect width="512" height="512" rx="112" fill="url(#aegis-logo-bg)" />
      <path d="M256 72 407 128v116c0 91-58 163-151 200-93-37-151-109-151-200V128L256 72Z" fill="#0b1322" stroke="url(#aegis-logo-edge)" strokeWidth="20" strokeLinejoin="round" />
      <path d="M146 253c31-51 68-77 110-77s79 26 110 77c-31 51-68 77-110 77s-79-26-110-77Z" fill="none" stroke="#dffaff" strokeWidth="18" strokeLinejoin="round" />
      <circle cx="256" cy="253" r="42" fill="url(#aegis-logo-edge)" />
      <circle cx="256" cy="253" r="17" fill="#06101d" />
      <path d="M256 117v35M151 165l24 24M361 165l-24 24" stroke="#55dfff" strokeWidth="13" strokeLinecap="round" opacity=".88" />
    </svg>
  );
}
