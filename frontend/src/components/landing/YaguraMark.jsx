export default function YaguraMark({ size = 28, className = '' }) {
  return (
    <span
      className={`inline-flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
      aria-label="Yagura"
    >
      <svg
        width={Math.round(size * 0.78)}
        height={Math.round(size * 0.78)}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {/* Pagoda-style watchtower roof */}
        <path d="M3 7 L12 2 L21 7" />
        <path d="M5 7 L19 7" />
        {/* Tower body — trapezoid */}
        <path d="M6 7 L6 21 L18 21 L18 7" />
        {/* Window slits */}
        <path d="M9 11 L9 14" />
        <path d="M15 11 L15 14" />
        {/* Floor divider */}
        <path d="M6 16 L18 16" />
      </svg>
    </span>
  );
}
