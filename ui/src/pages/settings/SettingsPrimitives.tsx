import { type ReactNode, useEffect, useRef, useState } from "react";

export const INPUT_CLS =
  "w-full min-w-0 rounded-xl border border-[var(--line)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]";
export const BTN_CLS =
  "inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3 py-1.5 text-xs font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50";

export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors"
      style={{
        backgroundColor: checked ? "var(--accent)" : "var(--bg-elevated)",
        borderColor: checked ? "var(--accent)" : "var(--line-strong)",
      }}
    >
      <span
        className="inline-block h-3.5 w-3.5 rounded-full transition-transform"
        style={{
          backgroundColor: checked ? "var(--accent-ink)" : "var(--muted)",
          transform: checked ? "translateX(17px)" : "translateX(2px)",
        }}
      />
    </button>
  );
}

export function Card({
  title,
  sub,
  action,
  children,
}: {
  title: string;
  sub?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="cc-card cc-glass min-w-0 space-y-3 rounded-2xl p-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--line)] pb-2">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-[var(--text)]">{title}</h3>
          {sub && <p className="text-[11px] text-[var(--muted)]">{sub}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

export function SwitchRow({
  title,
  desc,
  checked,
  onChange,
  badge,
}: {
  title: string;
  desc: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  badge?: ReactNode;
}) {
  return (
    <div className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2 text-xs font-medium text-[var(--text)]">
          <span>{title}</span>
          {badge}
        </div>
        <p className="mt-0.5 text-[11px] text-[var(--muted)]">{desc}</p>
      </div>
      <Toggle checked={checked} onChange={onChange} label={title} />
    </div>
  );
}

export function SegButtons<T extends string | number>({
  options,
  value,
  onChange,
  mono = false,
}: {
  options: ReadonlyArray<readonly [T, string]>;
  value: T;
  onChange: (v: T) => void;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map(([opt, text]) => {
        const on = value === opt;
        return (
          <button
            key={String(opt)}
            type="button"
            onClick={() => onChange(opt)}
            className={`rounded-lg px-2.5 py-1 text-xs transition-colors ${mono ? "cc-mono" : ""}`}
            style={{
              backgroundColor: on ? "var(--accent-soft)" : "var(--bg-elevated)",
              color: on ? "var(--accent)" : "var(--muted)",
              border: `1px solid ${on ? "var(--accent)" : "var(--line)"}`,
            }}
          >
            {text}
          </button>
        );
      })}
    </div>
  );
}

export function NumericDraftInput({
  value,
  min,
  max,
  fallback,
  onCommit,
  className,
}: {
  value: number;
  min?: number;
  max?: number;
  fallback: number;
  onCommit: (next: number) => void;
  className?: string;
}) {
  const [text, setText] = useState<string>(() => String(value));
  const focusedRef = useRef(false);

  useEffect(() => {
    if (!focusedRef.current) {
      setText(String(value));
    }
  }, [value]);

  const clampValue = (n: number): number => {
    let result = Math.round(n);
    if (min !== undefined && result < min) result = min;
    if (max !== undefined && result > max) result = max;
    return result;
  };

  return (
    <input
      type="number"
      min={min}
      max={max}
      value={text}
      onFocus={() => {
        focusedRef.current = true;
      }}
      onChange={(e) => {
        const raw = e.target.value;
        setText(raw);
        const trimmed = raw.trim();
        if (!trimmed) return;
        const parsed = Number(trimmed);
        if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) return;
        if (min !== undefined && parsed < min) return;
        if (max !== undefined && parsed > max) return;
        if (parsed !== value) {
          onCommit(parsed);
        }
      }}
      onBlur={() => {
        focusedRef.current = false;
        const trimmed = text.trim();
        const parsed = trimmed ? Number(trimmed) : NaN;
        const resolved =
          Number.isFinite(parsed) && parsed > 0
            ? clampValue(parsed)
            : clampValue(Number.isFinite(value) && value > 0 ? value : fallback);
        if (resolved !== value) {
          onCommit(resolved);
        }
        setText(String(resolved));
      }}
      className={className}
    />
  );
}
