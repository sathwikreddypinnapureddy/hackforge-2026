import Image from "next/image";

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
  // Lossless crops of the official logo sheet; never redraw the shield or terminal.
  const symbol = (
    <Image
      src={`/brand/hackforge-symbol-${theme}.png`}
      alt={variant === "symbol" && !decorative ? "HackForge" : ""}
      width={size}
      height={size}
      className={variant === "symbol" ? className : undefined}
      style={{ display: "block", flexShrink: 0, objectFit: "contain" }}
      aria-hidden={decorative || variant === "horizontal" ? true : undefined}
      loading="eager"
      unoptimized
    />
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
