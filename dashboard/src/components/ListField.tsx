import { Textarea } from "./ui";
import { formatList, parseList } from "@/lib/config";

/**
 * A list of strings, edited one per line.
 *
 * One per line rather than comma-separated: these hold domain rules and CIDRs,
 * which are long enough that a comma-separated line wraps unreadably at exactly
 * the moment someone is checking it.
 */
export function ListField({
  label,
  hint,
  value,
  rows = 4,
  placeholder,
  onChange,
}: {
  label: string;
  hint?: React.ReactNode;
  value: string[] | undefined;
  rows?: number;
  placeholder?: string;
  onChange: (next: string[]) => void;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-medium">{label}</span>
      {hint && <span className="text-[11px] leading-relaxed text-muted">{hint}</span>}
      <Textarea
        rows={rows}
        placeholder={placeholder}
        defaultValue={formatList(value)}
        onBlur={(e) => onChange(parseList(e.target.value))}
      />
    </label>
  );
}

/** A single-line text field with a label and an optional explanation. */
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-medium">{label}</span>
      {hint && <span className="text-[11px] leading-relaxed text-muted">{hint}</span>}
      {children}
    </label>
  );
}

/** A checkbox that reads as a sentence rather than a bare box. */
export function Toggle({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint?: React.ReactNode;
  checked: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-start gap-2.5">
      <input
        type="checkbox"
        className="mt-0.5 size-3.5 accent-[rgb(var(--accent))]"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="min-w-0">
        <span className="text-xs font-medium">{label}</span>
        {hint && <span className="mt-0.5 block text-[11px] leading-relaxed text-muted">{hint}</span>}
      </span>
    </label>
  );
}
