import { useRef, useState } from "react";
import { Download, Upload } from "lucide-react";
import { api, ApiError, type BackupPreview, type BackupResult } from "@/lib/api";
import { Alert, Badge, Button, Panel, Row, Spinner } from "@/components/ui";
import { Toggle } from "@/components/ListField";

/**
 * Backup and restore.
 *
 * A gateway is gateway.toml plus the outbound files it points at. Everything
 * else on the box is generated from those two, so this is the whole thing —
 * and it is small enough to keep anywhere.
 */
export function Backup({ onPending }: { onPending: () => void }) {
  const [secrets, setSecrets] = useState(true);
  const [busy, setBusy] = useState<"create" | "inspect" | "restore" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BackupResult | null>(null);
  const [preview, setPreview] = useState<BackupPreview | null>(null);
  const [archive, setArchive] = useState<string>("");
  const [restored, setRestored] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  async function create() {
    setBusy("create");
    setError(null);
    try {
      const res = await api.post<BackupResult>("/api/backup", { secrets });
      setResult(res);
      download(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  /** Turn the base64 archive into a file the browser saves. */
  function download(res: BackupResult) {
    const bytes = Uint8Array.from(atob(res.archive), (c) => c.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/gzip" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = res.filename;
    link.click();
    URL.revokeObjectURL(url);
  }

  async function inspect(file: File) {
    setBusy("inspect");
    setError(null);
    setPreview(null);
    setRestored(null);
    try {
      const buffer = await file.arrayBuffer();
      let binary = "";
      for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
      const encoded = btoa(binary);
      setArchive(encoded);
      setPreview(await api.post<BackupPreview>("/api/backup/inspect", { archive: encoded }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function restore() {
    setBusy("restore");
    setError(null);
    try {
      const res = await api.post<{ message: string; warning?: string; restored: string[] }>(
        "/api/backup/restore",
        { archive },
      );
      setRestored(res.warning || res.message);
      setPreview(null);
      setArchive("");
      if (fileInput.current) fileInput.current.value = "";
      onPending();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Backup</h1>
        <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-muted">
          A gateway is <span className="font-mono">gateway.toml</span> and the
          outbound files it points at. Everything else on the box is generated
          from those, so this archive is the whole thing — small enough to keep
          anywhere, and enough to rebuild the box from scratch.
        </p>
      </div>

      {error && <Alert tone="bad">{error}</Alert>}

      <Panel title="Download a backup">
        <Toggle
          label="Include the outbound credentials"
          hint="The UUIDs and passwords that reach your servers. Without them the restored gateway has its full configuration and cannot connect — with them, this file is enough to stand your tunnel up somewhere else."
          checked={secrets}
          onChange={setSecrets}
        />
        {secrets && (
          <div className="mt-3">
            <Alert tone="warn" title="This file is a credential">
              Treat it the way you would treat the share links themselves.
            </Alert>
          </div>
        )}
        <div className="mt-4 flex items-center justify-between gap-3">
          <p className="text-[11px] text-muted">
            {result ? `Last download: ${result.filename} (${result.bytes} bytes)` : ""}
          </p>
          <Button variant="primary" onClick={() => void create()} disabled={busy !== null}>
            {busy === "create" ? <Spinner /> : <Download className="size-3.5" />}
            Download
          </Button>
        </div>
        {result?.skipped && result.skipped.length > 0 && (
          <div className="mt-3">
            <Alert tone="warn" title="Some outbounds were left out">
              <p>
                These are referenced from outside the gateway directory, so a
                restore could not put them back:
              </p>
              <ul className="mt-1 list-disc pl-4 font-mono">
                {result.skipped.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </Alert>
          </div>
        )}
      </Panel>

      <Panel
        title="Restore"
        description="The archive is read and checked before anything is written, and the files it replaces are kept so a restore of the wrong file is itself undoable."
      >
        <input
          ref={fileInput}
          type="file"
          accept=".gz,.tar.gz,application/gzip"
          className="block w-full text-xs file:mr-3 file:rounded-lg file:border file:border-border file:bg-raised file:px-3 file:py-1.5 file:text-xs file:font-medium"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void inspect(file);
          }}
        />

        {busy === "inspect" && (
          <p className="mt-3 text-xs text-muted">
            <Spinner /> Reading the archive…
          </p>
        )}

        {preview && (
          <div className="mt-4 space-y-3">
            <div className="divide-y divide-border rounded-lg border border-border px-3">
              <Row label="Taken">
                {new Date(preview.manifest.created).toLocaleString()}
              </Row>
              <Row label="From host">
                <span className="font-mono">{preview.manifest.host || "unknown"}</span>
              </Row>
              <Row label="Credentials">
                {preview.manifest.secrets ? (
                  <Badge tone="warn">included</Badge>
                ) : (
                  <Badge tone="muted">not included</Badge>
                )}
              </Row>
              <Row label="Files">
                <span className="font-mono">{preview.files.join(", ")}</span>
              </Row>
            </div>

            {preview.config_error && (
              <Alert tone="warn" title="The config in this archive does not load on its own">
                <pre className="whitespace-pre-wrap font-mono text-[11px]">
                  {preview.config_error}
                </pre>
                <p className="mt-1.5">
                  That is normal when the outbounds are restored alongside it —
                  they are not in place yet.
                </p>
              </Alert>
            )}

            <Alert tone="bad" title="This replaces your current configuration">
              Every file listed above is overwritten. The versions being replaced
              are kept beside them, and nothing is live until you apply.
            </Alert>

            <div className="flex justify-end gap-2">
              <Button onClick={() => { setPreview(null); setArchive(""); }}>Cancel</Button>
              <Button variant="danger" onClick={() => void restore()} disabled={busy !== null}>
                {busy === "restore" ? <Spinner /> : <Upload className="size-3.5" />}
                Restore
              </Button>
            </div>
          </div>
        )}

        {restored && (
          <div className="mt-4">
            <Alert tone={restored.startsWith("restored,") ? "warn" : "ok"} title="Restored">
              {restored}
              <p className="mt-1.5">Nothing is live until you apply.</p>
            </Alert>
          </div>
        )}
      </Panel>
    </div>
  );
}
