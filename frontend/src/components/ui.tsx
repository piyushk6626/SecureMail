import { useEffect, useRef, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { X } from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...values: (string | false | null | undefined)[]): string {
  return twMerge(clsx(values));
}

export type LedgerTone = "danger" | "warning" | "info" | "neutral" | "success" | "unknown" | "not_observable";

/** Canonical evidence states deliberately do not share warning styling with visibility gaps. */
// eslint-disable-next-line react-refresh/only-export-components
export function evidence_state_tone(state: string | null | undefined): LedgerTone {
  if (state === "observed" || state === "verified") return "info";
  if (state === "inferred") return "neutral";
  if (state === "not_observable") return "not_observable";
  return "unknown";
}

// eslint-disable-next-line react-refresh/only-export-components
export function outcome_tone(outcome: string | null | undefined): LedgerTone {
  if (outcome === "pass") return "success";
  if (outcome === "fail") return "danger";
  if (outcome === "not_observable") return "not_observable";
  return "unknown";
}

export function Button({
  className,
  variant = "primary",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  return (
    <button
      className={cn(
        "inline-flex min-h-10 items-center justify-center gap-2 rounded px-3 text-sm font-semibold transition-colors focus-visible:outline-2 focus-visible:outline-offset-[3px] focus-visible:outline-[var(--accent)] disabled:pointer-events-none disabled:opacity-45",
        variant === "primary" && "bg-[var(--accent)] text-[var(--canvas)] hover:bg-[color-mix(in_srgb,var(--accent)_86%,white)]",
        variant === "secondary" &&
          "border border-[var(--border)] bg-[var(--surface)] text-[var(--text)] hover:bg-[var(--surface-raised)]",
        variant === "ghost" && "text-[var(--muted)] hover:bg-[var(--surface-raised)] hover:text-[var(--text)]",
        variant === "danger" && "border border-[var(--danger)] bg-transparent text-[var(--danger)] hover:bg-[color-mix(in_srgb,var(--danger)_12%,transparent)]",
        className,
      )}
      {...props}
    />
  );
}

export function Card({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-[3px] border border-[var(--rule)] bg-[var(--panel)]",
        className,
      )}
      {...props}
    />
  );
}

export function Badge({
  children,
  tone = "neutral",
  className,
}: {
  children: ReactNode;
  tone?: LedgerTone;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "ledger-flag inline-flex min-h-6 items-center rounded-sm border px-2 py-0.5 text-xs font-semibold uppercase tracking-[0.06em]",
        tone === "danger" && "ledger-danger",
        tone === "warning" && "ledger-warning",
        tone === "info" && "ledger-info",
        tone === "success" && "ledger-success",
        tone === "unknown" && "ledger-unknown",
        tone === "not_observable" && "ledger-not-observable",
        tone === "neutral" && "ledger-neutral",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Input({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-10 w-full rounded border border-[var(--rule)] bg-[var(--panel)] px-3 text-sm text-[var(--text)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none focus:ring-2 focus:ring-[color-mix(in_srgb,var(--accent)_25%,transparent)]",
        className,
      )}
      {...props}
    />
  );
}

export function Sheet({
  is_open,
  title,
  on_close,
  children,
}: {
  is_open: boolean;
  title: string;
  on_close: () => void;
  children: ReactNode;
}) {
  const sheet_ref = useRef<HTMLElement>(null);
  const previous_focus = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (!is_open) return;
    previous_focus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    function on_key(event: KeyboardEvent): void {
      if (event.key === "Escape") on_close();
      if (event.key !== "Tab" || !sheet_ref.current) return;
      const focusable = Array.from(sheet_ref.current.querySelectorAll<HTMLElement>("a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])"));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
    window.addEventListener("keydown", on_key);
    window.requestAnimationFrame(() => sheet_ref.current?.querySelector<HTMLElement>("[data-sheet-heading]")?.focus());
    return () => {
      document.body.style.overflow = previous;
      window.removeEventListener("keydown", on_key);
      previous_focus.current?.focus();
    };
  }, [is_open, on_close]);
  if (!is_open) return null;
  return (
    <div className="fixed inset-0 z-50" role="presentation">
      <button
        aria-label="Close evidence details"
        className="absolute inset-0 bg-black/70"
        onClick={on_close}
        type="button"
      />
      <section
        aria-label={title}
        aria-modal="true"
        className="absolute inset-y-0 right-0 w-full max-w-[min(920px,76vw)] overflow-y-auto border-l border-[var(--rule)] bg-[var(--canvas)] p-5 shadow-[0_18px_50px_rgb(0_0_0/0.38)] sm:p-6"
        ref={sheet_ref}
        role="dialog"
      >
        <div className="mb-5 flex items-center justify-between gap-4">
          <h2 className="text-xl font-semibold" data-sheet-heading tabIndex={-1}>{title}</h2>
          <Button aria-label="Close" onClick={on_close} variant="ghost">
            <X aria-hidden size={18} />
          </Button>
        </div>
        {children}
      </section>
    </div>
  );
}

export function LoadingState() {
  return (
    <div aria-label="Loading case" className="space-y-4">
      <div className="h-28 animate-pulse rounded bg-[var(--panel)]" />
      <div className="grid gap-4 md:grid-cols-2">
        <div className="h-64 animate-pulse rounded bg-[var(--panel)]" />
        <div className="h-64 animate-pulse rounded bg-[var(--panel)]" />
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded border border-dashed border-[var(--rule-strong)] p-8 text-center">
      <h3 className="font-semibold">{title}</h3>
      <p className="mt-2 max-w-md text-sm text-[var(--muted)]">{description}</p>
      {children ? <div className="mt-5">{children}</div> : null}
    </div>
  );
}
