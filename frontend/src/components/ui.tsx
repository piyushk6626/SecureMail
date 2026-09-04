import type {
  ButtonHTMLAttributes,
  HTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
} from "react";
import { X } from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...values: (string | false | null | undefined)[]): string {
  return twMerge(clsx(values));
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
        "inline-flex min-h-9 items-center justify-center gap-2 rounded-lg px-3 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400 disabled:pointer-events-none disabled:opacity-45",
        variant === "primary" && "bg-cyan-600 text-white hover:bg-cyan-500",
        variant === "secondary" &&
          "border border-[var(--border)] bg-[var(--surface)] text-[var(--text)] hover:bg-[var(--surface-raised)]",
        variant === "ghost" && "text-[var(--muted)] hover:bg-[var(--surface-raised)] hover:text-[var(--text)]",
        variant === "danger" && "bg-red-600 text-white hover:bg-red-500",
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
        "rounded-xl border border-[var(--border)] bg-[var(--surface)] shadow-[0_1px_0_rgb(255_255_255/0.03)]",
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
  tone?: "danger" | "warning" | "info" | "neutral" | "success" | "unknown";
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-[0.08em]",
        tone === "danger" && "border-red-500/35 bg-red-500/10 text-red-400",
        tone === "warning" && "border-amber-500/35 bg-amber-500/10 text-amber-400",
        tone === "info" && "border-cyan-500/35 bg-cyan-500/10 text-cyan-400",
        tone === "success" && "border-emerald-500/35 bg-emerald-500/10 text-emerald-400",
        tone === "unknown" && "border-violet-500/35 bg-violet-500/10 text-violet-300",
        tone === "neutral" && "border-[var(--border)] bg-[var(--surface-raised)] text-[var(--muted)]",
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
        "h-9 w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 text-sm text-[var(--text)] placeholder:text-[var(--muted)] focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20",
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
  if (!is_open) return null;
  return (
    <div className="fixed inset-0 z-50" role="presentation">
      <button
        aria-label="Close evidence details"
        className="absolute inset-0 bg-slate-950/65 backdrop-blur-[2px]"
        onClick={on_close}
        type="button"
      />
      <section
        aria-label={title}
        aria-modal="true"
        className="absolute inset-y-0 right-0 w-full max-w-xl overflow-y-auto border-l border-[var(--border)] bg-[var(--background)] p-5 shadow-2xl"
        role="dialog"
      >
        <div className="mb-5 flex items-center justify-between gap-4">
          <h2 className="text-lg font-semibold">{title}</h2>
          <Button aria-label="Close" onClick={on_close} variant="ghost">
            <X aria-hidden size={18} />
          </Button>
        </div>
        {children}
      </section>
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
    <div className="flex min-h-48 flex-col items-center justify-center rounded-xl border border-dashed border-[var(--border)] p-8 text-center">
      <h3 className="font-semibold">{title}</h3>
      <p className="mt-2 max-w-md text-sm text-[var(--muted)]">{description}</p>
      {children ? <div className="mt-5">{children}</div> : null}
    </div>
  );
}
