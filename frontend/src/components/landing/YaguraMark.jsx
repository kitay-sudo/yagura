export default function YaguraMark({ size = 28, className = '' }) {
  return (
    <span
      className={`inline-flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
      aria-label="Yagura"
    >
      <svg
        width={Math.round(size * 0.82)}
        height={Math.round(size * 0.82)}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {/* Finial — vertical anchor at the top of the pagoda */}
        <line x1="12" y1="2" x2="12" y2="3.4" />
        {/* Upper tier: eaved roof with slight upturn — Japanese watchtower silhouette */}
        <path d="M5.2 6.2 Q 4.6 5.6 5.4 5 L 12 3.4 L 18.6 5 Q 19.4 5.6 18.8 6.2 Z" />
        {/* Lower tier: wider eaved roof */}
        <path d="M3.4 10.4 Q 2.6 9.8 3.6 9 L 12 7 L 20.4 9 Q 21.4 9.8 20.6 10.4 Z" />
        {/* Tower body — slight inward taper, like a real yagura */}
        <path d="M6 10.4 L 6.8 19.4 L 17.2 19.4 L 18 10.4" />
        {/* Arrow-slit windows */}
        <line x1="9.4" y1="13.4" x2="9.4" y2="16" />
        <line x1="14.6" y1="13.4" x2="14.6" y2="16" />
        {/* Stone foundation */}
        <line x1="5.4" y1="21.2" x2="18.6" y2="21.2" />
      </svg>
    </span>
  );
}
