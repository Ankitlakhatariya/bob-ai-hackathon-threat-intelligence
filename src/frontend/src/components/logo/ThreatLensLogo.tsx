import { useId, type SVGProps } from 'react'

export interface ThreatLensLogoProps {
  className?: string
  size?: number
  withWordmark?: boolean
  svgProps?: SVGProps<SVGSVGElement>
}

/**
 * ThreatLens logo — original SVG mark.
 *
 * Concept: a shield (protection) enclosing a targeting lens / scan rings
 * (visibility + correlation) around a gradient core (the detected signal).
 */
export function ThreatLensLogo({
  className = '',
  size = 36,
  withWordmark = false,
  svgProps,
}: ThreatLensLogoProps) {
  const uid = useId()
  const coreGradient = `tl-core-${uid}`

  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <svg
        viewBox="0 0 32 32"
        width={size}
        height={size}
        role="img"
        aria-label="ThreatLens logo"
        fill="none"
        {...svgProps}
      >
        <defs>
          <linearGradient id={coreGradient} x1="10" y1="8" x2="24" y2="26" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#818cf8" />
            <stop offset="1" stopColor="#22d3ee" />
          </linearGradient>
        </defs>

        <path
          d="M16 1.5 L28.56 8.75 L28.56 23.25 L16 30.5 L3.44 23.25 L3.44 8.75 Z"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
        <circle cx="16" cy="16" r="8.4" stroke="currentColor" strokeWidth="1.2" opacity="0.75" />
        <circle
          cx="16"
          cy="16"
          r="5.2"
          stroke="currentColor"
          strokeWidth="1.2"
          strokeDasharray="1.8 2.6"
          opacity="0.55"
        />
        <circle cx="16" cy="16" r="2" fill={`url(#${coreGradient})`} />
        <path
          d="M16 9.2 v2.2 M16 20.6 v2.2 M9.2 16 h2.2 M20.6 16 h2.2"
          stroke="currentColor"
          strokeWidth="1"
          strokeLinecap="round"
          opacity="0.85"
        />
      </svg>

      {withWordmark && (
        <span className="text-lg font-semibold tracking-[0.02em] text-foreground">
          Threat<span className="text-primary">Lens</span>
        </span>
      )}
    </span>
  )
}