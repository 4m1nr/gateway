import { ArrowDown, ArrowUp } from "lucide-react";
import { api, type Status } from "@/lib/api";
import { bytes, count, duration } from "@/lib/format";
import { Alert, Badge, Card, Empty, Panel, Row } from "@/components/ui";
import { usePoll } from "@/lib/usePoll";

function StatCard({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "ok" | "warn" | "bad";
}) {
  const colours = { ok: "text-ok", warn: "text-warn", bad: "text-bad" };
  return (
    <Card>
      <p className="text-[11px] font-medium uppercase tracking-wide text-muted">{label}</p>
      <p className={`mt-1.5 text-2xl font-semibold ${tone ? colours[tone] : ""}`}>{value}</p>
      {sub && <p className="mt-1 text-[11px] leading-snug text-muted">{sub}</p>}
    </Card>
  );
}

function tunnelCard(s: Status) {
  switch (s.tunnel) {
    case "up":
      return { value: "Up", tone: "ok" as const, sub: "intercepted traffic reaches the tunnel" };
    case "degraded":
      return {
        value: "Degraded",
        tone: "bad" as const,
        // The distinction that matters: Xray is fine, the packets are not
        // getting to it.
        sub: `tunnel up, interception broken · ${s.fails} failed probes`,
      };
    case "down":
      return { value: "Down", tone: "bad" as const, sub: `${s.fails} consecutive failed probes` };
    default:
      return { value: "Unknown", tone: "warn" as const, sub: "the health check has not run yet" };
  }
}

export function Overview() {
  const { data: status, error } = usePoll<Status>(() => api.get<Status>("/api/status"), 5000);

  if (error) return <Alert tone="bad" title="Could not read the status">{error}</Alert>;
  if (!status) return <Empty>Loading…</Empty>;

  const tunnel = tunnelCard(status);
  const sys = status.system;
  const memUsed = sys.mem_total - sys.mem_available;
  const traffic = Object.entries(status.traffic);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Overview</h1>
        <p className="mt-0.5 text-xs text-muted">
          {status.lan ? `Serving ${status.lan}` : "Not applied yet"}
        </p>
      </div>

      {status.detail && <Alert tone="warn">{status.detail}</Alert>}

      {status.lifeline && (
        <Alert tone="warn" title="Tailscale lifeline engaged">
          The tunnel has been down long enough that tailscaled is now talking
          directly, so remote access survives. Client traffic stays fail-closed.
        </Alert>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Tunnel" value={tunnel.value} tone={tunnel.tone} sub={tunnel.sub} />
        <StatCard
          label="Default policy"
          value={status.default_policy}
          sub="for any device pointing here"
        />
        <StatCard
          label="Killswitch drops"
          value={count(status.firewall.killswitch_drops)}
          sub="packets refused, not leaked"
        />
        <StatCard
          label="Uptime"
          value={duration(sys.uptime)}
          sub={`load ${(sys.load[0] ?? 0).toFixed(2)} · ${bytes(memUsed)}/${bytes(sys.mem_total)}`}
        />
      </div>

      {sys.xray_uptime_sec > 0 && sys.xray_uptime_sec < 900 && (
        <Alert tone="warn" title="Xray restarted recently">
          Started {Math.floor(sys.xray_uptime_sec / 60)}m {sys.xray_uptime_sec % 60}s
          ago. Every connection open before that was dropped — which is what a
          client "losing the internet for a moment" looks like.
        </Alert>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title="Traffic by route"
          description="Counters reset when Xray restarts."
        >
          {traffic.length === 0 ? (
            <Empty>No counters yet.</Empty>
          ) : (
            <div className="divide-y divide-border">
              {traffic.map(([tag, t]) => (
                <div key={tag} className="flex items-center justify-between gap-4 py-2">
                  <span className="font-mono text-xs">{tag}</span>
                  <span className="flex gap-4 text-xs tabular-nums text-muted">
                    <span className="flex items-center gap-1">
                      <ArrowUp className="size-3" />
                      {bytes(t.uplink)}
                    </span>
                    <span className="flex items-center gap-1">
                      <ArrowDown className="size-3" />
                      {bytes(t.downlink)}
                    </span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Firewall">
          {!status.firewall.loaded ? (
            <Alert tone="bad" title="The ruleset is not loaded">
              Nothing is being intercepted, and nothing is being blocked. Run{" "}
              <code className="font-mono">sudo gw apply</code>.
            </Alert>
          ) : (
            <div className="divide-y divide-border">
              <Row label="Intercepted">
                {status.firewall.proxy_clients.length === 0 ? (
                  <span className="text-muted">none listed</span>
                ) : (
                  <span className="font-mono">
                    {status.firewall.proxy_clients.join(", ")}
                  </span>
                )}
              </Row>
              <Row label="Direct">
                <span className="font-mono">
                  {status.firewall.direct_clients.join(", ") || "—"}
                </span>
              </Row>
              <Row label="Blocked">
                <span className="font-mono">
                  {status.firewall.blocked_clients.join(", ") || "—"}
                </span>
              </Row>
              {status.profiles.length > 0 && (
                <Row label="Profiles">
                  <span className="flex flex-wrap justify-end gap-1">
                    {status.profiles.map((p) => (
                      <Badge key={p} tone="ok" className="font-mono">
                        {p}
                      </Badge>
                    ))}
                  </span>
                </Row>
              )}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
