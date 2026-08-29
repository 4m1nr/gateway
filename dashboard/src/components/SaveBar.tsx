import { useState } from "react";
import { Alert, Button } from "./ui";
import { writeSection } from "@/lib/config";
import { ApiError } from "@/lib/api";

/**
 * The save control every config page shares.
 *
 * A save is refused whole if the result would not load, and the reason comes
 * from the config loader itself — the same sentence you would get on the box.
 * That is worth surfacing verbatim rather than paraphrasing: it names the field
 * and says what to write instead.
 */
export function SaveBar({
  section,
  value,
  dirty,
  onSaved,
  children,
}: {
  section: string;
  value: unknown;
  dirty: boolean;
  onSaved: () => void;
  children?: React.ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await writeSection(section, value);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      {error && (
        <Alert tone="bad" title="Not saved">
          <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed">
            {error}
          </pre>
        </Alert>
      )}
      <div className="flex items-center justify-between gap-3">
        <p className="text-[11px] text-muted">
          {children ?? "Saved to gateway.toml immediately; run Apply to make it live."}
        </p>
        <Button variant="primary" onClick={() => void save()} disabled={!dirty || busy}>
          {busy ? "Saving…" : dirty ? "Save" : "Saved"}
        </Button>
      </div>
    </div>
  );
}
