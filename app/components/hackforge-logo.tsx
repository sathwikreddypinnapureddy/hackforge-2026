type HackForgeLogoProps = {
  variant?: "symbol" | "horizontal";
  theme?: "dark" | "light" | "monochrome";
  size?: number;
  className?: string;
  decorative?: boolean;
};

export function HackForgeLogo({
  variant = "symbol",
  theme = "dark",
  size = 40,
  className,
  decorative = false,
}: HackForgeLogoProps) {
  const monochrome = theme === "monochrome";
  const shield = theme === "dark" ? "#79DFB7" : "#0F2233";
  const terminal = theme === "dark" ? "#0F2233" : "#79DFB7";
  const symbol = (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 48 48"
      width={size}
      height={size}
      className={variant === "symbol" ? className : undefined}
      style={{ display: "block", flexShrink: 0 }}
      role={variant === "symbol" && !decorative ? "img" : undefined}
      aria-label={variant === "symbol" && !decorative ? "HackForge" : undefined}
      aria-hidden={decorative || variant === "horizontal" ? true : undefined}
      focusable="false"
    >
      <path
        d="M8 2H40Q46 2 46 8V22C46 34 34 42 24 46C14 42 2 34 2 22V8Q2 2 8 2Z"
        fill={monochrome ? "none" : shield}
        stroke={monochrome ? "currentColor" : undefined}
        strokeWidth={monochrome ? 3 : undefined}
      />
      <path
        d="M14 14L23 22L14 30M27 30H35"
        fill="none"
        stroke={monochrome ? "currentColor" : terminal}
        strokeWidth="4"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />
    </svg>
  );

  if (variant === "symbol") return symbol;

  return (
    <span
      className={className}
      aria-hidden={decorative ? true : undefined}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: size * 0.275,
        color: monochrome ? "currentColor" : theme === "dark" ? "#FFFFFF" : "#0F2233",
        fontFamily: "inherit",
        fontSize: size * 0.575,
        fontWeight: 750,
        letterSpacing: "-0.035em",
        lineHeight: 1.2,
        whiteSpace: "nowrap",
      }}
    >
      {symbol}
      <span>HackForge</span>
    </span>
  );
}
