const paths = {
  assessment: <><circle cx="12" cy="12" r="5" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></>,
  exposure: <><path d="m12 3 8 4.5-8 4.5-8-4.5L12 3Z" /><path d="m4 12 8 4.5 8-4.5M4 16.5 12 21l8-4.5" /></>,
  research: <><path d="M8 3 3 12l5 9M16 3l5 9-5 9M14 7l-4 10" /></>,
  diagnostics: <><path d="M2 13h4l2-7 4 13 3-9 2 3h5" /></>,
  status: <><rect x="3" y="5" width="18" height="5" rx="2" /><rect x="3" y="14" width="18" height="5" rx="2" /><path d="M7 8h.01M7 17h.01" /></>,
  model: <><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z" /><path d="m4.5 7.7 7.5 4.2 7.5-4.2M12 12v9" /></>,
  command: <><circle cx="11" cy="11" r="6" /><path d="m16 16 5 5" /></>,
  play: <path d="m8 5 11 7-11 7V5Z" />,
  file: <><path d="M6 2h8l4 4v16H6V2Z" /><path d="M14 2v5h5" /></>,
  folder: <><path d="M3 6h7l2 2h9v11H3V6Z" /></>,
  home: <><path d="m4 11 8-7 8 7" /><path d="M6 10v10h12V10M10 20v-6h4v6" /></>,
  shield: <><path d="M12 2 20 6v6c0 5-3.5 8.3-8 10-4.5-1.7-8-5-8-10V6l8-4Z" /><path d="m9 12 2 2 4-4" /></>,
};

export default function UiIcon({ name, size = 19, className = "" }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {paths[name] || paths.assessment}
    </svg>
  );
}
