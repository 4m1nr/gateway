import { useEffect, useState } from "react";
import { ExternalLink } from "lucide-react";
import { api, type ConfigDoc, type DnsSettings, type Status } from "@/lib/api";
import { readConfig, section } from "@/lib/config";
import { Alert, Badge, Empty, Input, Panel, Row } from "@/components/ui";
import { Field, ListField, Toggle } from "@/components/ListField";
import { SaveBar } from "@/components/SaveBar";
import { usePoll } from "@/lib/usePoll";

/**
 * DNS.
 *
 * The page states the thing that catches people out: DNS here is not just
 * filtering. A device that keeps using the router's resolver gets a private
 * address back for a blocked name, sends real traffic there, and the gateway
 * drops it as unreachable — one site failing while everything else works.
 */
export function Dns({ onPending }: { onPending: () => void }) {
  const [doc, setDoc] = useState<ConfigDoc | null>(null);
  const [dns, setDns] = useState<DnsSettings>({});
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { data: status } = usePoll<Status>(() => api.get<Status>("/api/status"), 15000);

  const load = async () => {
    try {
      const res = await readConfig();
      setDoc(res.config);
      setDns(section<DnsSettings>(res.config, "dns", {}));
      setDirty(false);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const patch = (changes: Partial<DnsSettings>) => {
    setDns((current) => ({ ...current, ...changes }));
    setDirty(true);
  };

  if (error) return <Alert tone="bad" title="Could not read the config">{error}</Alert>;
  if (!doc) return <Empty>Loading…</Empty>;

  const adguard = status?.units.find((u) => u.name === "AdGuardHome.service");
  const uiPort = dns.adguard_ui_port ?? 3000;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">DNS</h1>
        <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-muted">
          AdGuard Home serves the LAN. Its upstream DoH is captured by the output
          chain like any other local process, so it resolves through the tunnel,
          while domestic names go to plain resolvers directly.
        </p>
      </div>

      <Alert tone="warn" title="Point devices here for DNS as well as routing">
        A device that keeps using the router's resolver gets a private address
        back for a blocked name, sends real traffic there, and the gateway drops
        it as unreachable. The symptom is one site failing while everything else
        works — not an obvious DNS problem at all.
      </Alert>

      <Panel
        title="AdGuard Home"
        description="Filtering, the query log and the block lists are managed in AdGuard's own interface. gw apply leaves anything set there alone."
      >
        <div className="divide-y divide-border">
          <Row label="Service">
            {adguard ? (
              <Badge tone={adguard.active === "active" ? "ok" : "bad"}>{adguard.active}</Badge>
            ) : (
              <span className="text-muted">not installed</span>
            )}
          </Row>
          <Row label="Admin interface">
            {status?.box_ip ? (
              <a
                className="inline-flex items-center gap-1"
                href={`http://${status.box_ip}:${uiPort}`}
                target="_blank"
                rel="noreferrer noopener"
              >
                <span className="font-mono">{status.box_ip}:{uiPort}</span>
                <ExternalLink className="size-3" />
              </a>
            ) : (
              <span className="text-muted">apply has not run yet</span>
            )}
          </Row>
        </div>
        <p className="mt-3 text-[11px] leading-relaxed text-muted">
          AdGuard's own admin password is the one thing not managed here — a
          password hash does not belong in a git repo.
        </p>
      </Panel>

      <Panel title="Resolvers" description="Where names are actually looked up.">
        <div className="grid gap-4 lg:grid-cols-2">
          <ListField
            label="Through the tunnel"
            hint={
              <>
                DoH, which rides the tunnel. These must be IP literals — a hostname
                here would need DNS to resolve the DNS server, which cannot work at
                boot.
              </>
            }
            value={dns.upstreams_proxied}
            placeholder="https://1.1.1.1/dns-query"
            onChange={(upstreams_proxied) => patch({ upstreams_proxied })}
          />
          <ListField
            label="Direct"
            hint="Plain resolvers for domestic names, reached without the tunnel."
            value={dns.upstreams_direct}
            placeholder="1.1.1.1"
            onChange={(upstreams_direct) => patch({ upstreams_direct })}
          />
          <ListField
            label="Domestic suffixes"
            hint="Names ending in these go to the direct resolvers."
            rows={3}
            value={dns.direct_suffixes}
            placeholder="ir"
            onChange={(direct_suffixes) => patch({ direct_suffixes })}
          />
          <ListField
            label="Bootstrap"
            hint="Used to resolve the DoH endpoints themselves, before anything else works."
            rows={3}
            value={dns.bootstrap}
            placeholder="1.1.1.1"
            onChange={(bootstrap) => patch({ bootstrap })}
          />
        </div>
        <p className="mt-4 text-[11px] leading-relaxed text-muted">
          There is deliberately no fallback from DoH to the direct resolvers.
          Whenever DoH is slow — which is exactly when the network is being
          interfered with — a fallback asks a resolver that lies, and caches the
          lie. Failing closed on DNS is the same choice the firewall makes.
        </p>
      </Panel>

      <Panel title="Interception and retention">
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="space-y-4">
            <Toggle
              label="Redirect plain DNS from LAN clients"
              hint="Catches a device pointed at a public resolver. One pointed at the router resolves over the local segment and never reaches this box at all — for those, set the router's DHCP to hand out this address."
              checked={dns.intercept ?? true}
              onChange={(intercept) => patch({ intercept })}
            />
            <Field label="DNS port">
              <Input
                type="number"
                className="font-mono"
                value={dns.adguard_port ?? 53}
                onChange={(e) => patch({ adguard_port: Number(e.target.value) })}
              />
            </Field>
            <Field label="Admin interface port">
              <Input
                type="number"
                className="font-mono"
                value={dns.adguard_ui_port ?? 3000}
                onChange={(e) => patch({ adguard_ui_port: Number(e.target.value) })}
              />
            </Field>
          </div>
          <div className="space-y-4">
            <Field
              label="Query log, days"
              hint="Thin-client flash is small and slow; short retention is deliberate."
            >
              <Input
                type="number"
                className="font-mono"
                value={dns.querylog_days ?? 3}
                onChange={(e) => patch({ querylog_days: Number(e.target.value) })}
              />
            </Field>
            <Field label="Statistics, days">
              <Input
                type="number"
                className="font-mono"
                value={dns.statslog_days ?? 7}
                onChange={(e) => patch({ statslog_days: Number(e.target.value) })}
              />
            </Field>
            <ListField
              label="Block lists"
              hint="Filter URLs merged into AdGuard's configuration."
              rows={3}
              value={dns.blocklists}
              onChange={(blocklists) => patch({ blocklists })}
            />
          </div>
        </div>
      </Panel>

      <SaveBar
        section="dns"
        value={dns}
        dirty={dirty}
        onSaved={() => { setDirty(false); onPending(); void load(); }}
      >
        Applying merges these into AdGuard's own config, leaving what you set in its UI alone.
      </SaveBar>
    </div>
  );
}
