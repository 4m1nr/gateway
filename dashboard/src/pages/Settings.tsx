import { useEffect, useState } from "react";
import type { ConfigDoc } from "@/lib/api";
import { readConfig, section } from "@/lib/config";
import { Alert, Empty, Input, Panel, Select } from "@/components/ui";
import { Field, ListField, Toggle } from "@/components/ListField";
import { SaveBar } from "@/components/SaveBar";
import { AccessPanel } from "@/components/AccessPanel";
import { api, type Status } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";

/** Everything that was previously SSH-only. */
export function Settings({ onPending }: { onPending: () => void }) {
  const { data: status } = usePoll<Status>(() => api.get<Status>("/api/status"), 30000);
  const [doc, setDoc] = useState<ConfigDoc | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [configError, setConfigError] = useState("");

  const load = async () => {
    try {
      const res = await readConfig();
      setDoc(res.config);
      setConfigError(res.config_error);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  useEffect(() => {
    void load();
  }, []);

  if (error) return <Alert tone="bad" title="Could not read the config">{error}</Alert>;
  if (!doc) return <Empty>Loading…</Empty>;

  const saved = () => { onPending(); void load(); };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Settings</h1>
        <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-muted">
          The rest of gateway.toml. Each panel saves its own section, so an edit
          here cannot disturb one you did not touch.
        </p>
      </div>

      {configError && (
        <Alert tone="bad" title="The config does not currently load">
          <pre className="whitespace-pre-wrap font-mono text-[11px]">{configError}</pre>
        </Alert>
      )}

      <DashboardAccess doc={doc} lanCidr={status?.lan ?? ""} onSaved={saved} />
      <GeoSplit doc={doc} onSaved={saved} />
      <Tailscale doc={doc} onSaved={saved} />
      <Health doc={doc} onSaved={saved} />
      <SystemPanel doc={doc} onSaved={saved} />
      <Performance doc={doc} onSaved={saved} />
    </div>
  );
}

// ------------------------------------------------------- dashboard access --

interface WebSettings {
  enabled?: boolean;
  allow_cidrs?: string[];
  [key: string]: unknown;
}

function DashboardAccess({
  doc,
  lanCidr,
  onSaved,
}: {
  doc: ConfigDoc;
  lanCidr: string;
  onSaved: () => void;
}) {
  const web = section<WebSettings>(doc, "web", {});
  return (
    <AccessPanel
      title="Who may reach this dashboard"
      description="The first of its four gates. nftables refuses the port from anywhere else, and the server re-checks the address itself — a header claiming otherwise is ignored, because nothing proxies this service."
      section="web"
      field="allow_cidrs"
      service="this dashboard"
      lanCidr={lanCidr}
      value={web}
      onSaved={onSaved}
      disabledNotice={
        <>
          You would lose access to this page on the next apply. Reach it again by
          forwarding the port over SSH, or set <span className="font-mono">enabled</span>{" "}
          to false and use the CLI.
        </>
      }
    />
  );
}

// -------------------------------------------------------------- geo split --

interface RoutingSettings {
  direct_geosite?: string[];
  direct_geoip?: string[];
  block_geosite?: string[];
  block_bittorrent?: boolean;
  extra_local_networks?: string[];
  drop_private_destinations?: boolean;
}

function GeoSplit({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [v, setV] = useState<RoutingSettings>(() => section(doc, "routing", {}));
  const [dirty, setDirty] = useState(false);
  const patch = (c: Partial<RoutingSettings>) => { setV({ ...v, ...c }); setDirty(true); };

  return (
    <Panel
      title="The global split"
      description="What bypasses the tunnel. Matched after per-client policy and after a profile's own rules, so both still win."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <ListField
          label="Direct domains"
          value={v.direct_geosite}
          placeholder={"geosite:private\ngeosite:category-ir"}
          onChange={(direct_geosite) => patch({ direct_geosite })}
        />
        <ListField
          label="Direct networks"
          value={v.direct_geoip}
          placeholder={"geoip:private\ngeoip:ir"}
          onChange={(direct_geoip) => patch({ direct_geoip })}
        />
        <ListField
          label="Blocked domains"
          rows={3}
          value={v.block_geosite}
          placeholder="geosite:category-ads-all"
          onChange={(block_geosite) => patch({ block_geosite })}
        />
        <ListField
          label="Other local networks"
          hint="Private ranges genuinely reachable here, beyond this LAN."
          rows={3}
          value={v.extra_local_networks}
          onChange={(extra_local_networks) => patch({ extra_local_networks })}
        />
      </div>
      <div className="mt-4 space-y-3">
        <Toggle
          label="Drop unreachable private destinations"
          hint="A filtering resolver answers a blocked name with a private address. Without this the client's traffic goes there, is never intercepted, and dies with no counter and no log — one site failing, everything else fine."
          checked={v.drop_private_destinations ?? true}
          onChange={(drop_private_destinations) => patch({ drop_private_destinations })}
        />
        <Toggle
          label="Block BitTorrent"
          checked={v.block_bittorrent ?? false}
          onChange={(block_bittorrent) => patch({ block_bittorrent })}
        />
      </div>
      <div className="mt-4">
        <SaveBar section="routing" value={v} dirty={dirty} onSaved={() => { setDirty(false); onSaved(); }} />
      </div>
    </Panel>
  );
}

// -------------------------------------------------------------- tailscale --

interface TailscaleSettings {
  enabled?: boolean;
  ssh?: boolean;
  exit_node?: boolean;
  subnet_router?: boolean;
  exit_node_policy?: string;
  route_control_via_xray?: boolean;
  lifeline_after_min?: number;
}

function Tailscale({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [v, setV] = useState<TailscaleSettings>(() => section(doc, "tailscale", {}));
  const [dirty, setDirty] = useState(false);
  const patch = (c: Partial<TailscaleSettings>) => { setV({ ...v, ...c }); setDirty(true); };

  const profiles = section<{ name: string }[]>(doc, "profile", []).map((p) => p.name);
  const policies = ["proxy", "direct", "block", ...profiles.filter(Boolean)];

  return (
    <Panel title="Tailscale" description="Subnet router and exit node.">
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-3">
          <Toggle label="Enabled" checked={v.enabled ?? true} onChange={(enabled) => patch({ enabled })} />
          <Toggle label="Tailscale SSH" checked={v.ssh ?? true} onChange={(ssh) => patch({ ssh })} />
          <Toggle
            label="Advertise as an exit node"
            checked={v.exit_node ?? true}
            onChange={(exit_node) => patch({ exit_node })}
          />
          <Toggle
            label="Advertise the LAN as a subnet route"
            checked={v.subnet_router ?? true}
            onChange={(subnet_router) => patch({ subnet_router })}
          />
        </div>
        <div className="space-y-4">
          <Field
            label="Exit-node policy"
            hint="How traffic from a remote device is routed — any policy or profile, so a phone abroad can take the same path a laptop here does."
          >
            <Select
              value={v.exit_node_policy ?? "proxy"}
              onChange={(e) => patch({ exit_node_policy: e.target.value })}
            >
              {policies.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </Select>
          </Field>
          <Field
            label="Lifeline after, minutes"
            hint="If the tunnel stays down this long, tailscaled is allowed to talk direct so you do not lose remote access exactly when you need it. Client traffic stays fail-closed regardless."
          >
            <Input
              type="number"
              className="font-mono"
              value={v.lifeline_after_min ?? 10}
              onChange={(e) => patch({ lifeline_after_min: Number(e.target.value) })}
            />
          </Field>
          <Toggle
            label="Tunnel tailscaled's control-plane traffic"
            hint="Useful where Tailscale itself is blocked."
            checked={v.route_control_via_xray ?? true}
            onChange={(route_control_via_xray) => patch({ route_control_via_xray })}
          />
        </div>
      </div>
      <div className="mt-4">
        <SaveBar section="tailscale" value={v} dirty={dirty} onSaved={() => { setDirty(false); onSaved(); }} />
      </div>
    </Panel>
  );
}

// ----------------------------------------------------------------- health --

interface HealthSettings {
  interval_sec?: number;
  probe_url?: string;
  probe_timeout_sec?: number;
  domestic_probe_url?: string;
  restart_after_fails?: number;
  fallback_after_fails?: number;
}

function Health({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [v, setV] = useState<HealthSettings>(() => section(doc, "health", {}));
  const [dirty, setDirty] = useState(false);
  const patch = (c: Partial<HealthSettings>) => { setV({ ...v, ...c }); setDirty(true); };

  return (
    <Panel
      title="Health watchdog"
      description="Probes the path a client's traffic actually takes, not a SOCKS shortcut — a probe that cannot see the failure is worse than none."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label="Interval, seconds">
          <Input type="number" className="font-mono" value={v.interval_sec ?? 30}
            onChange={(e) => patch({ interval_sec: Number(e.target.value) })} />
        </Field>
        <Field label="Probe timeout, seconds">
          <Input type="number" className="font-mono" value={v.probe_timeout_sec ?? 8}
            onChange={(e) => patch({ probe_timeout_sec: Number(e.target.value) })} />
        </Field>
        <Field label="Probe URL">
          <Input className="font-mono" value={v.probe_url ?? ""}
            onChange={(e) => patch({ probe_url: e.target.value })} />
        </Field>
        <Field label="Domestic probe URL" hint="Tells a broken tunnel apart from a broken link.">
          <Input className="font-mono" value={v.domestic_probe_url ?? ""}
            onChange={(e) => patch({ domestic_probe_url: e.target.value })} />
        </Field>
        <Field
          label="Restart Xray after failures"
          hint="A restart drops every live connection on every client, so this should not be 1."
        >
          <Input type="number" className="font-mono" value={v.restart_after_fails ?? 3}
            onChange={(e) => patch({ restart_after_fails: Number(e.target.value) })} />
        </Field>
        <Field label="Engage the lifeline after failures">
          <Input type="number" className="font-mono" value={v.fallback_after_fails ?? 6}
            onChange={(e) => patch({ fallback_after_fails: Number(e.target.value) })} />
        </Field>
      </div>
      <div className="mt-4">
        <SaveBar section="health" value={v} dirty={dirty} onSaved={() => { setDirty(false); onSaved(); }} />
      </div>
    </Panel>
  );
}

// ----------------------------------------------------------------- system --

interface SystemSettings {
  timezone?: string;
  journal_max_use?: string;
  zram?: boolean;
  bbr?: boolean;
  unattended_upgrades?: boolean;
  auto_update?: string;
  auto_update_schedule?: string;
  ssh_allow_lan?: boolean;
  ssh_allow_tailnet?: boolean;
}

function SystemPanel({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [v, setV] = useState<SystemSettings>(() => section(doc, "system", {}));
  const [dirty, setDirty] = useState(false);
  const patch = (c: Partial<SystemSettings>) => { setV({ ...v, ...c }); setDirty(true); };

  return (
    <Panel title="System" description="The box itself, and what it updates on its own.">
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label="Timezone" hint="The clock is load-bearing: TLS and REALITY both fail on skew.">
          <Input className="font-mono" value={v.timezone ?? ""}
            onChange={(e) => patch({ timezone: e.target.value })} />
        </Field>
        <Field label="Journal size cap">
          <Input className="font-mono" value={v.journal_max_use ?? ""}
            onChange={(e) => patch({ journal_max_use: e.target.value })} />
        </Field>
        <Field
          label="Automatic updates"
          hint="services is the default: geodata, Xray and AdGuard each test themselves and roll back. An unattended apt upgrade on the box the whole house routes through does not."
        >
          <Select value={v.auto_update ?? "services"} onChange={(e) => patch({ auto_update: e.target.value })}>
            <option value="off">off</option>
            <option value="check">check — report only</option>
            <option value="services">services — geodata, Xray, AdGuard</option>
            <option value="all">all — adds apt upgrade and a re-apply</option>
          </Select>
        </Field>
        <Field label="Update schedule" hint="Any systemd OnCalendar. Validated before it is installed.">
          <Input className="font-mono" value={v.auto_update_schedule ?? "weekly"}
            onChange={(e) => patch({ auto_update_schedule: e.target.value })} />
        </Field>
      </div>
      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <Toggle label="Unattended security upgrades" checked={v.unattended_upgrades ?? true}
          onChange={(unattended_upgrades) => patch({ unattended_upgrades })} />
        <Toggle label="BBR congestion control" checked={v.bbr ?? true}
          onChange={(bbr) => patch({ bbr })} />
        <Toggle label="zram" checked={v.zram ?? true} onChange={(zram) => patch({ zram })} />
        <Toggle label="SSH from the LAN" checked={v.ssh_allow_lan ?? true}
          onChange={(ssh_allow_lan) => patch({ ssh_allow_lan })} />
        <Toggle label="SSH from the tailnet" checked={v.ssh_allow_tailnet ?? true}
          onChange={(ssh_allow_tailnet) => patch({ ssh_allow_tailnet })} />
      </div>
      <div className="mt-4">
        <SaveBar section="system" value={v} dirty={dirty} onSaved={() => { setDirty(false); onSaved(); }} />
      </div>
    </Panel>
  );
}

// ------------------------------------------------------------ performance --

interface PerformanceSettings {
  buffer_size_kb?: number;
  tcp_congestion?: string;
  tcp_no_delay?: boolean;
  conn_idle_sec?: number;
}

function Performance({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [v, setV] = useState<PerformanceSettings>(() => section(doc, "performance", {}));
  const [dirty, setDirty] = useState(false);
  const patch = (c: Partial<PerformanceSettings>) => { setV({ ...v, ...c }); setDirty(true); };

  return (
    <Panel
      title="Performance"
      description="Left mostly unset on purpose. Picking these without measuring the specific link is how you make things slower while believing you tuned them — run Bench first."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <Field
          label="Buffer size, KB"
          hint="-1 leaves Xray's own default alone. Shrinking it caps throughput on a high-latency path, and a censored route is usually long."
        >
          <Input type="number" className="font-mono" value={v.buffer_size_kb ?? -1}
            onChange={(e) => patch({ buffer_size_kb: Number(e.target.value) })} />
        </Field>
        <Field label="Congestion control" hint="bbr helps most on a lossy path.">
          <Input className="font-mono" value={v.tcp_congestion ?? "bbr"}
            onChange={(e) => patch({ tcp_congestion: e.target.value })} />
        </Field>
        <Field label="Connection idle, seconds">
          <Input type="number" className="font-mono" value={v.conn_idle_sec ?? 300}
            onChange={(e) => patch({ conn_idle_sec: Number(e.target.value) })} />
        </Field>
        <div className="flex items-end">
          <Toggle label="TCP_NODELAY" checked={v.tcp_no_delay ?? true}
            onChange={(tcp_no_delay) => patch({ tcp_no_delay })} />
        </div>
      </div>
      <div className="mt-4">
        <SaveBar section="performance" value={v} dirty={dirty} onSaved={() => { setDirty(false); onSaved(); }} />
      </div>
    </Panel>
  );
}
