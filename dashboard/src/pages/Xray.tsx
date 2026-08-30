import { useEffect, useState } from "react";
import { Download, QrCode } from "lucide-react";
import QRCode from "qrcode";
import { api, ApiError, type Outbound } from "@/lib/api";
import { readConfig, section } from "@/lib/config";
import { Alert, Badge, Button, Empty, Input, Panel, Select } from "@/components/ui";
import { Field, Toggle } from "@/components/ListField";
import { SaveBar } from "@/components/SaveBar";
import { JsonEditor } from "@/components/JsonEditor";

/**
 * The Xray page: the raw config, in front of you, in the panel.
 *
 * Outbounds are shown exactly as the gateway loaded them, including the two
 * fields it injects — the tag, which routing rules reference, and
 * sockopt.mark, the loop guard. Seeing them is the point: they are what makes
 * a pasted outbound safe to use here, and they are invisible in the file you
 * pasted.
 */
export function Xray({ onPending }: { onPending: () => void }) {
  const [outbounds, setOutbounds] = useState<Outbound[] | null>(null);
  const [generated, setGenerated] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"outbounds" | "failover" | "generated" | "import">(
    "outbounds",
  );
  const [selected, setSelected] = useState(0);

  useEffect(() => {
    void (async () => {
      try {
        const res = await api.get<{ outbounds: Outbound[] }>("/api/outbounds");
        setOutbounds(res.outbounds);
      } catch (err) {
        setError(err instanceof ApiError ? err.message : String(err));
      }
    })();
  }, []);

  useEffect(() => {
    if (tab !== "generated" || generated) return;
    void (async () => {
      try {
        const res = await api.get<{ config: string }>("/api/config/generated");
        setGenerated(res.config);
      } catch (err) {
        setError(err instanceof ApiError ? err.message : String(err));
      }
    })();
  }, [tab, generated]);

  const tabs = [
    { id: "outbounds" as const, label: "Outbounds" },
    { id: "failover" as const, label: "Failover" },
    { id: "generated" as const, label: "Generated config" },
    { id: "import" as const, label: "Import a link" },
  ];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Xray</h1>
        <p className="mt-0.5 text-xs leading-relaxed text-muted">
          Outbounds are Xray's own JSON, used verbatim. The gateway owns exactly
          two fields inside them: <span className="font-mono">tag</span>, because
          routing rules reference it, and{" "}
          <span className="font-mono">streamSettings.sockopt.mark</span>, the loop
          guard — without it Xray's own packets become eligible for TPROXY and
          the box deadlocks.
        </p>
      </div>

      {error && <Alert tone="bad">{error}</Alert>}

      <div className="flex gap-1 border-b border-border">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={
              "-mb-px border-b-2 px-3 py-2 text-xs font-medium transition-colors " +
              (tab === t.id
                ? "border-accent text-accent"
                : "border-transparent text-muted hover:text-fg")
            }
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "outbounds" && (
        <OutboundView outbounds={outbounds} selected={selected} onSelect={setSelected} />
      )}
      {tab === "failover" && <FailoverView onSaved={onPending} />}
      {tab === "generated" && <GeneratedView config={generated} />}
      {tab === "import" && <ImportView />}
    </div>
  );
}

function OutboundView({
  outbounds,
  selected,
  onSelect,
}: {
  outbounds: Outbound[] | null;
  selected: number;
  onSelect: (i: number) => void;
}) {
  if (!outbounds) return <Empty>Loading…</Empty>;
  if (outbounds.length === 0) return <Empty>No outbounds are configured.</Empty>;
  const current = outbounds[Math.min(selected, outbounds.length - 1)];
  if (!current) return <Empty>No outbounds are configured.</Empty>;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5">
        {outbounds.map((ob, i) => (
          <button
            key={ob.tag}
            onClick={() => onSelect(i)}
            className={
              "rounded-lg px-3 py-1.5 font-mono text-xs transition-colors " +
              (i === selected
                ? "bg-accent text-white"
                : "border border-border bg-raised hover:bg-border")
            }
          >
            {ob.tag}
          </button>
        ))}
      </div>

      <Panel
        title={current.tag}
        description={
          <>
            From <span className="font-mono">{current.origin}</span>
            {current.address && (
              <>
                {" · server "}
                <span className="font-mono">{current.address}</span>
              </>
            )}
            {current.resolved_ip && (
              <>
                {" pinned to "}
                <span className="font-mono">{current.resolved_ip}</span>
              </>
            )}
          </>
        }
      >
        <JsonEditor value={current.json} readOnly height="440px" />
        <p className="mt-3 text-[11px] leading-relaxed text-muted">
          Read-only here. Edit the file this came from, then run{" "}
          <span className="font-mono">gw apply</span> — the whole config is
          validated with <span className="font-mono">xray -test</span> before
          anything is reloaded, so a rejected config never reaches the running
          service.
        </p>
      </Panel>
    </div>
  );
}

// -------------------------------------------------------------- failover --

interface FallbackSettings {
  enabled?: boolean;
  file?: string;
  json?: string;
  server_ip?: string;
  [key: string]: unknown;
}

interface XraySettings {
  fallback?: FallbackSettings;
  [key: string]: unknown;
}

/**
 * The second server, and what turning it on does to routing.
 *
 * Worth stating plainly in the panel: enabling this does not add a rule, it
 * changes what every existing rule means. "Through the tunnel" stops being one
 * server and becomes a balancer across two, chosen by observed latency — for
 * profile devices as much as for everyone else.
 */
function FailoverView({ onSaved }: { onSaved: () => void }) {
  const [xray, setXray] = useState<XraySettings | null>(null);
  const [after, setAfter] = useState<number | null>(null);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const res = await readConfig();
      setXray(section<XraySettings>(res.config, "xray", {}));
      setAfter(
        section<{ fallback_after_fails?: number }>(res.config, "health", {})
          .fallback_after_fails ?? 6,
      );
      setDirty(false);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  useEffect(() => {
    void load();
  }, []);

  if (error) return <Alert tone="bad" title="Could not read the config">{error}</Alert>;
  if (!xray) return <Empty>Loading…</Empty>;

  const fb: FallbackSettings = xray.fallback ?? {};
  // Which of the two mutually exclusive sources this fallback uses. A config
  // that sets neither yet is treated as a file, because that is what `gw init`
  // writes and what the example ships.
  const source: "file" | "json" = fb.json ? "json" : "file";

  // Patch inside [xray], never replace it: the section also holds the ports,
  // the loop-guard mark and the main outbound, and none of those are on this
  // page to be re-sent.
  const patch = (next: Partial<FallbackSettings>) => {
    setXray({ ...xray, fallback: { ...fb, ...next } });
    setDirty(true);
  };

  // Exactly one of file/json may be set, and the loader rejects both — so
  // switching source drops the other rather than leaving a stale value behind
  // to fail validation on save.
  const useSource = (next: "file" | "json") => {
    if (next === source) return;
    const { file: _file, json: _json, ...rest } = fb;
    setXray({
      ...xray,
      fallback: next === "file" ? { ...rest, file: "" } : { ...rest, json: "" },
    });
    setDirty(true);
  };

  return (
    <div className="space-y-4">
      <Panel
        title="Failover"
        description="A second server. When it is enabled, Xray load-balances between the two by observed latency and drops a server that stops answering."
        actions={
          <Badge tone={fb.enabled ? "ok" : "muted"}>
            {fb.enabled ? "enabled" : "off"}
          </Badge>
        }
      >
        <div className="space-y-4">
          <Toggle
            label="Use a fallback server"
            hint={
              <>
                This changes what every rule that says "the tunnel" resolves to:
                instead of the single <span className="font-mono">proxy</span>{" "}
                outbound they all point at a balancer named{" "}
                <span className="font-mono">tunnel</span> that selects between{" "}
                <span className="font-mono">proxy</span> and{" "}
                <span className="font-mono">fallback</span>. Profile devices are
                included — a profile with{" "}
                <span className="font-mono">base = "proxy"</span> fails over with
                everything else rather than staying pinned to a dead server.
              </>
            }
            checked={fb.enabled ?? false}
            onChange={(enabled) => patch({ enabled })}
          />

          <Field
            label="Where the outbound comes from"
            hint="Exactly one of the two. The gateway refuses a config that sets both, because there would be no way to tell which one you meant."
          >
            <Select value={source} onChange={(e) => useSource(e.target.value as "file" | "json")}>
              <option value="file">A file in outbounds/</option>
              <option value="json">Inline JSON</option>
            </Select>
          </Field>

          {source === "file" ? (
            <Field
              label="File"
              hint="Relative to gateway.toml, so it survives the repo moving."
            >
              <Input
                className="font-mono"
                placeholder="outbounds/backup.json"
                value={fb.file ?? ""}
                onChange={(e) => patch({ file: e.target.value })}
              />
            </Field>
          ) : (
            <Field
              label="Outbound"
              hint="A complete Xray outbound object, used verbatim. The tag and sockopt.mark are added when it loads."
            >
              <JsonEditor
                value={fb.json ?? ""}
                height="320px"
                onChange={(json) => patch({ json })}
              />
            </Field>
          )}

          <Field
            label="Server IP"
            hint="Optional. Pins the address so the fallback does not need DNS at boot — which matters most in exactly the situation it exists for."
          >
            <Input
              className="font-mono"
              placeholder="leave empty to resolve normally"
              value={fb.server_ip ?? ""}
              onChange={(e) => patch({ server_ip: e.target.value })}
            />
          </Field>

          <SaveBar
            section="xray"
            value={xray}
            dirty={dirty}
            onSaved={() => {
              onSaved();
              void load();
            }}
          />
        </div>
      </Panel>

      <Panel
        title="When the gateway gives up on a server"
        description="The health agent probes continuously and escalates in steps, so one timeout is never treated as an outage."
      >
        <p className="text-xs leading-relaxed text-muted">
          After <span className="font-mono">{after ?? 6}</span> consecutive failed
          probes the health agent switches the balancer to the fallback; before
          that it retries and restarts Xray. Xray's own latency-based selection
          works continuously and does not wait for that count — this is the
          backstop for a server that answers but carries no traffic. The count
          lives in <span className="font-mono">[health]</span> on the Settings
          page.
        </p>
      </Panel>
    </div>
  );
}

function GeneratedView({ config }: { config: string }) {
  if (!config) return <Empty>Loading…</Empty>;
  return (
    <Panel
      title="Generated config"
      description="Exactly what /usr/local/etc/xray/config.json holds. Routing rules are matched first to last, so the order below is the behaviour."
      actions={
        <Button
          onClick={() => void navigator.clipboard.writeText(config)}
          title="Copy to the clipboard"
        >
          <Download className="size-3.5" /> Copy
        </Button>
      }
    >
      <JsonEditor value={config} readOnly height="560px" />
    </Panel>
  );
}

function ImportView() {
  const [link, setLink] = useState("");
  const [result, setResult] = useState<{ json: string; name: string; protocol: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function importLink() {
    setBusy(true);
    setError(null);
    setQr(null);
    try {
      const res = await api.post<{ json: string; name: string; protocol: string }>(
        "/api/outbounds/import",
        { link },
      );
      setResult(res);
    } catch (err) {
      setResult(null);
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function showQr() {
    try {
      setQr(await QRCode.toDataURL(link, { margin: 1, width: 240 }));
    } catch {
      setError("could not render a QR code for that link");
    }
  }

  return (
    <div className="space-y-4">
      <Panel
        title="Import a share link"
        description="vless://, vmess://, trojan:// or ss://. Nothing is written — the JSON appears below for you to review and save into outbounds/."
      >
        <div className="flex gap-2">
          <Input
            placeholder="vless://…"
            value={link}
            onChange={(e) => setLink(e.target.value)}
            className="font-mono"
          />
          <Button variant="primary" onClick={() => void importLink()} disabled={busy || !link}>
            {busy ? "Reading…" : "Import"}
          </Button>
          <Button onClick={() => void showQr()} disabled={!link} title="Show as a QR code">
            <QrCode className="size-3.5" />
          </Button>
        </div>

        <Alert tone="warn" title="A share link is a credential">
          It carries the server's UUID or password. Treat this box's screen the
          way you would treat the link itself.
        </Alert>

        {error && <div className="mt-3"><Alert tone="bad">{error}</Alert></div>}
        {qr && (
          <div className="mt-3 flex justify-center">
            <img src={qr} alt="the share link as a QR code" className="rounded-lg" />
          </div>
        )}
      </Panel>

      {result && (
        <Panel
          title={result.name || "Imported outbound"}
          description={`Parsed as ${result.protocol}. Save this into outbounds/ and point xray.outbound.file at it.`}
          actions={
            <Button onClick={() => void navigator.clipboard.writeText(result.json)}>
              <Download className="size-3.5" /> Copy
            </Button>
          }
        >
          <JsonEditor value={result.json} readOnly height="380px" />
          <p className="mt-3 text-[11px] leading-relaxed text-muted">
            No <span className="font-mono">tag</span> and no{" "}
            <span className="font-mono">sockopt.mark</span>: the gateway adds both
            when it loads the file, and a mark that disagrees with the firewall is
            rejected rather than silently overwritten.
          </p>
        </Panel>
      )}
    </div>
  );
}
