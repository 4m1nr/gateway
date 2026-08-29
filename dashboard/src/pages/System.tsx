import { RotateCw } from "lucide-react";
import { useState } from "react";
import { api, ApiError, type Status } from "@/lib/api";
import { bytes, duration } from "@/lib/format";
import { Alert, Badge, Button, Empty, Panel, Row } from "@/components/ui";
import { usePoll } from "@/lib/usePoll";

/** Units the dashboard is allowed to restart. The server keeps its own
 *  whitelist; this only decides which buttons to draw. */
const restartable = new Set([
  "xray.service",
  "gw-network.service",
  "AdGuardHome.service",
  "gateway.target",
]);

export function System() {
  const { data: status, error, refresh } = usePoll<Status>(
    () => api.get<Status>("/api/status"),
    10000,
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function restart(unit: string) {
    setBusy(unit);
    setActionError(null);
    try {
      await api.post(`/api/units/${encodeURIComponent(unit)}/restart`);
      await refresh();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  if (error) return <Alert tone="bad" title="Could not read the status">{error}</Alert>;
  if (!status) return <Empty>Loading…</Empty>;

  const sys = status.system;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">System</h1>
        <p className="mt-0.5 text-xs text-muted">
          Services, boot state, and the box itself.
        </p>
      </div>

      {actionError && <Alert tone="bad">{actionError}</Alert>}

      <Panel
        title="Services"
        description="Restarting Xray drops every live connection on every client — which is what a device 'losing the internet for a moment' looks like."
      >
        {status.units.length === 0 ? (
          <Empty>Nothing is installed yet. Run the setup scripts.</Empty>
        ) : (
          <div className="divide-y divide-border">
            {status.units.map((u) => (
              <div key={u.name} className="flex items-center justify-between gap-4 py-2.5">
                <div className="min-w-0">
                  <p className="font-mono text-xs">{u.name}</p>
                  <p className="mt-0.5 text-[11px] text-muted">
                    {u.enabled === "enabled" ? "starts on boot" : "NOT enabled at boot"}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Badge tone={u.active === "active" ? "ok" : "bad"}>{u.active}</Badge>
                  {restartable.has(u.name) && (
                    <Button
                      onClick={() => void restart(u.name)}
                      disabled={busy !== null}
                      title={`Restart ${u.name}`}
                    >
                      <RotateCw className={busy === u.name ? "size-3.5 animate-spin" : "size-3.5"} />
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Box">
          <div className="divide-y divide-border">
            <Row label="Uptime">{duration(sys.uptime)}</Row>
            <Row label="Load">
              {sys.load.map((l) => l.toFixed(2)).join("  ") || "—"}
            </Row>
            <Row label="Memory">
              {bytes(sys.mem_total - sys.mem_available)} / {bytes(sys.mem_total)}
            </Row>
            <Row label="Disk free">
              {bytes(sys.disk_free)} of {bytes(sys.disk_total)}
            </Row>
            {sys.xray_uptime_sec > 0 && (
              <Row label="Xray up">{duration(sys.xray_uptime_sec)}</Row>
            )}
          </div>
        </Panel>

        <Panel title="Network">
          <div className="divide-y divide-border">
            <Row label="LAN">
              <span className="font-mono">{status.lan || "—"}</span>
            </Row>
            <Row label="This box">
              <span className="font-mono">{status.box_ip || "—"}</span>
            </Row>
            <Row label="Default policy">
              <span className="font-mono">{status.default_policy}</span>
            </Row>
            <Row label="Firewall">
              {status.firewall.loaded ? (
                <Badge tone="ok">loaded</Badge>
              ) : (
                <Badge tone="bad">not loaded</Badge>
              )}
            </Row>
            <Row label="Killswitch drops">
              {status.firewall.killswitch_drops.toLocaleString()}
            </Row>
          </div>
        </Panel>
      </div>
    </div>
  );
}
