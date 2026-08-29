import { cn } from "@/lib/cn";
import type { ReactNode } from "react";

/**
 * The small set of primitives every page is built from. Deliberately a handful
 * of components rather than a component library: the box serves these assets
 * over a LAN, and a dependency that ships a hundred variants to use six is a
 * slower first paint for no benefit.
 */

export function Card({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={cn(
        "rounded-xl border border-border bg-surface p-5 shadow-sm",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function Panel({
  title,
  description,
  actions,
  className,
  children,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section
      className={cn("rounded-xl border border-border bg-surface", className)}
    >
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold tracking-tight">{title}</h2>
          {description && (
            <p className="mt-1 text-xs leading-relaxed text-muted">{description}</p>
          )}
        </div>
        {actions && <div className="flex shrink-0 gap-2">{actions}</div>}
      </header>
      <div className="p-5">{children}</div>
    </section>
  );
}

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

export function Button({
  variant = "secondary",
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  const variants: Record<ButtonVariant, string> = {
    primary: "bg-accent text-white hover:opacity-90",
    secondary: "border border-border bg-raised hover:bg-border",
    danger: "border border-bad/40 text-bad hover:bg-bad/10",
    ghost: "hover:bg-raised",
  };
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5",
        "text-xs font-medium transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}

export function Input({
  className,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs",
        "placeholder:text-muted",
        className,
      )}
      {...props}
    />
  );
}

export function Select({
  className,
  ...props
}: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "w-full rounded-lg border border-border bg-bg px-3 py-1.5 text-xs",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({
  className,
  ...props
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "w-full rounded-lg border border-border bg-bg px-3 py-2 font-mono text-xs",
        "placeholder:text-muted",
        className,
      )}
      {...props}
    />
  );
}

type Tone = "ok" | "warn" | "bad" | "muted" | "accent";

export function Badge({
  tone = "muted",
  className,
  children,
}: {
  tone?: Tone;
  className?: string;
  children: ReactNode;
}) {
  const tones: Record<Tone, string> = {
    ok: "bg-ok/15 text-ok",
    warn: "bg-warn/15 text-warn",
    bad: "bg-bad/15 text-bad",
    muted: "bg-raised text-muted",
    accent: "bg-accent/15 text-accent",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium",
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/** The policy vocabulary, coloured consistently everywhere it appears. */
export function PolicyBadge({ policy, profiles }: { policy: string; profiles: string[] }) {
  if (policy === "proxy") return <Badge tone="accent">proxy</Badge>;
  if (policy === "direct") return <Badge tone="warn">direct</Badge>;
  if (policy === "block") return <Badge tone="bad">block</Badge>;
  // A profile is neither of the three, and saying so is the point: its
  // behaviour is "base, except…", which the badge cannot summarise.
  return (
    <Badge tone={profiles.includes(policy) ? "ok" : "muted"} className="font-mono">
      {policy}
    </Badge>
  );
}

export function Alert({
  tone = "bad",
  title,
  children,
}: {
  tone?: Tone;
  title?: string;
  children: ReactNode;
}) {
  const tones: Record<Tone, string> = {
    ok: "border-ok/30 bg-ok/10 text-ok",
    warn: "border-warn/30 bg-warn/10 text-warn",
    bad: "border-bad/30 bg-bad/10 text-bad",
    muted: "border-border bg-raised text-muted",
    accent: "border-accent/30 bg-accent/10 text-accent",
  };
  return (
    <div className={cn("rounded-lg border px-3 py-2 text-xs", tones[tone])}>
      {title && <p className="font-semibold">{title}</p>}
      <div className={cn(title && "mt-1", "leading-relaxed")}>{children}</div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-xs text-muted">{children}</p>;
}

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-block size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent",
        className,
      )}
      role="status"
      aria-label="loading"
    />
  );
}

/** A definition row, used for every label/value pair in the app. */
export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5 text-xs">
      <span className="shrink-0 text-muted">{label}</span>
      <span className="min-w-0 truncate text-right">{children}</span>
    </div>
  );
}
