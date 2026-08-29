import { useEffect, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import type { ConfigDoc, CustomRoute, Profile, Upstream } from "@/lib/api";
import { readConfig, section } from "@/lib/config";
import { Alert, Badge, Button, Empty, Input, Panel, Select } from "@/components/ui";
import { Field, ListField } from "@/components/ListField";
import { SaveBar } from "@/components/SaveBar";

/**
 * Profiles, upstreams and the custom routing table.
 *
 * These three are one page because they are one decision: a profile's rule
 * points at an upstream, and a custom route competes with the profile's rules
 * for the same traffic. Splitting them across tabs would hide the relationship
 * that actually matters.
 */
export function Routing({ onPending }: { onPending: () => void }) {
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

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Routing</h1>
        <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-muted">
          Where intercepted traffic goes. Xray matches rules first to last, so the
          order on this page is the behaviour — a profile's own rules are placed
          ahead of the global geo split, and its fallthrough behind it.
        </p>
      </div>

      {configError && (
        <Alert tone="bad" title="The config does not currently load">
          <pre className="whitespace-pre-wrap font-mono text-[11px]">{configError}</pre>
        </Alert>
      )}

      <Upstreams doc={doc} onSaved={() => { onPending(); void load(); }} />
      <Profiles doc={doc} onSaved={() => { onPending(); void load(); }} />
      <CustomRoutes doc={doc} onSaved={() => { onPending(); void load(); }} />
    </div>
  );
}

/** Every target a rule may point at: the built-ins plus each upstream. */
function targets(doc: ConfigDoc): string[] {
  const upstreams = section<Upstream[]>(doc, "upstream", []);
  return ["proxy", "direct", "block", ...upstreams.map((u) => u.name).filter(Boolean)];
}

// ------------------------------------------------------------- upstreams --

function Upstreams({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [items, setItems] = useState<Upstream[]>(() => section<Upstream[]>(doc, "upstream", []));
  const [dirty, setDirty] = useState(false);

  const update = (next: Upstream[]) => {
    setItems(next);
    setDirty(true);
  };

  return (
    <Panel
      title="Upstreams"
      description="Extra Xray servers a profile can send selected traffic through — a work VPN, a second exit country. Each is a complete outbound, used verbatim."
      actions={
        <Button onClick={() => update([...items, { name: "", file: "outbounds/.json" }])}>
          <Plus className="size-3.5" /> Add
        </Button>
      }
    >
      {items.length === 0 ? (
        <Empty>No upstreams. Profiles can still route to proxy, direct and block.</Empty>
      ) : (
        <div className="space-y-3">
          {items.map((item, i) => (
            <div key={i} className="grid gap-2 rounded-lg border border-border p-3 sm:grid-cols-[1fr_2fr_1fr_auto]">
              <Input
                placeholder="work"
                value={item.name ?? ""}
                onChange={(e) => update(items.map((u, j) => (j === i ? { ...u, name: e.target.value } : u)))}
              />
              <Input
                placeholder="outbounds/work.json"
                className="font-mono"
                value={item.file ?? ""}
                onChange={(e) => update(items.map((u, j) => (j === i ? { ...u, file: e.target.value } : u)))}
              />
              <Input
                placeholder="pin IP (optional)"
                className="font-mono"
                value={item.server_ip ?? ""}
                onChange={(e) =>
                  update(items.map((u, j) => (j === i ? { ...u, server_ip: e.target.value } : u)))
                }
              />
              <Button variant="danger" onClick={() => update(items.filter((_, j) => j !== i))}>
                <Trash2 className="size-3.5" />
              </Button>
            </div>
          ))}
        </div>
      )}
      <div className="mt-4">
        <SaveBar
          section="upstream"
          value={items.length ? items : null}
          dirty={dirty}
          onSaved={() => { setDirty(false); onSaved(); }}
        >
          The name becomes an Xray outbound tag, so keep it lowercase and boring.
        </SaveBar>
      </div>
    </Panel>
  );
}

// -------------------------------------------------------------- profiles --

function Profiles({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [items, setItems] = useState<Profile[]>(() => section<Profile[]>(doc, "profile", []));
  const [dirty, setDirty] = useState(false);
  const available = targets(doc);

  const update = (next: Profile[]) => {
    setItems(next);
    setDirty(true);
  };
  const patch = (i: number, changes: Partial<Profile>) =>
    update(items.map((p, j) => (j === i ? { ...p, ...changes } : p)));

  return (
    <Panel
      title="Profiles"
      description="A built-in policy plus destination exceptions: behave like the base, except send these domains or networks somewhere else."
      actions={
        <Button
          onClick={() =>
            update([...items, { name: "", base: "proxy", route: [{ via: "direct", domains: [] }] }])
          }
        >
          <Plus className="size-3.5" /> Add
        </Button>
      }
    >
      <Alert tone="warn" title="A profile device is always intercepted">
        Splitting traffic by destination requires Xray to see it, so a profile is
        fail-closed even with a base of <span className="font-mono">direct</span> —
        if the tunnel dies it loses connectivity rather than falling back. That is
        the cost of the split, not a bug.
      </Alert>

      {items.length === 0 ? (
        <div className="mt-4"><Empty>No profiles.</Empty></div>
      ) : (
        <div className="mt-4 space-y-4">
          {items.map((profile, i) => (
            <div key={i} className="rounded-lg border border-border p-4">
              <div className="grid gap-3 sm:grid-cols-[2fr_1fr_auto]">
                <Field label="Name">
                  <Input
                    placeholder="work-laptop"
                    className="font-mono"
                    value={profile.name ?? ""}
                    onChange={(e) => patch(i, { name: e.target.value })}
                  />
                </Field>
                <Field label="Base" hint="what unmatched traffic does">
                  <Select
                    value={profile.base ?? "proxy"}
                    onChange={(e) => patch(i, { base: e.target.value })}
                  >
                    <option value="proxy">proxy</option>
                    <option value="direct">direct</option>
                  </Select>
                </Field>
                <div className="flex items-end">
                  <Button variant="danger" onClick={() => update(items.filter((_, j) => j !== i))}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </div>

              <p className="mt-4 text-[11px] font-medium uppercase tracking-wide text-muted">
                Exceptions — matched before the global geo split
              </p>
              <div className="mt-2 space-y-3">
                {(profile.route ?? []).map((rule, r) => (
                  <div key={r} className="grid gap-2 rounded-lg bg-raised p-3 sm:grid-cols-[1fr_2fr_2fr_auto]">
                    <Field label="Via">
                      <Select
                        value={rule.via}
                        onChange={(e) =>
                          patch(i, {
                            route: (profile.route ?? []).map((x, k) =>
                              k === r ? { ...x, via: e.target.value } : x,
                            ),
                          })
                        }
                      >
                        {available.map((t) => (
                          <option key={t} value={t}>{t}</option>
                        ))}
                      </Select>
                    </Field>
                    <ListField
                      label="Domains"
                      rows={2}
                      placeholder={"domain:corp.example\ngeosite:category-ads-all"}
                      value={rule.domains}
                      onChange={(domains) =>
                        patch(i, {
                          route: (profile.route ?? []).map((x, k) => (k === r ? { ...x, domains } : x)),
                        })
                      }
                    />
                    <ListField
                      label="Networks"
                      rows={2}
                      placeholder={"10.20.0.0/16\ngeoip:ir"}
                      value={rule.ips}
                      onChange={(ips) =>
                        patch(i, {
                          route: (profile.route ?? []).map((x, k) => (k === r ? { ...x, ips } : x)),
                        })
                      }
                    />
                    <div className="flex items-end">
                      <Button
                        variant="danger"
                        onClick={() =>
                          patch(i, { route: (profile.route ?? []).filter((_, k) => k !== r) })
                        }
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    </div>
                  </div>
                ))}
                <Button
                  onClick={() =>
                    patch(i, { route: [...(profile.route ?? []), { via: "direct", domains: [] }] })
                  }
                >
                  <Plus className="size-3.5" /> Add an exception
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="mt-4">
        <SaveBar
          section="profile"
          value={items.length ? items : null}
          dirty={dirty}
          onSaved={() => { setDirty(false); onSaved(); }}
        >
          A profile with no exceptions is just its base policy, and is refused.
        </SaveBar>
      </div>
    </Panel>
  );
}

// --------------------------------------------------------- custom routes --

const positions = [
  { value: "first", label: "first — ahead of everything, including per-client policy" },
  { value: "before", label: "before — after per-client policy, ahead of the geo split" },
  { value: "after", label: "after — after the geo split, before the fallthrough" },
];

function CustomRoutes({ doc, onSaved }: { doc: ConfigDoc; onSaved: () => void }) {
  const [items, setItems] = useState<CustomRoute[]>(() => section<CustomRoute[]>(doc, "route", []));
  const [dirty, setDirty] = useState(false);
  const available = targets(doc);

  const update = (next: CustomRoute[]) => {
    setItems(next);
    setDirty(true);
  };
  const patch = (i: number, changes: Partial<CustomRoute>) =>
    update(items.map((r, j) => (j === i ? { ...r, ...changes } : r)));

  return (
    <Panel
      title="Custom rules"
      description="Spliced into the generated pipeline. The table IS the Xray rule — every field but position is passed through as written."
      actions={
        <Button onClick={() => update([...items, { position: "before", outboundTag: "direct" }])}>
          <Plus className="size-3.5" /> Add
        </Button>
      }
    >
      {items.length === 0 ? (
        <Empty>No custom rules. The geo split and per-client policy handle everything.</Empty>
      ) : (
        <div className="space-y-3">
          {items.map((rule, i) => (
            <div key={i} className="rounded-lg border border-border p-3">
              <div className="grid gap-3 sm:grid-cols-[2fr_1fr_auto]">
                <Field label="Position">
                  <Select
                    value={rule.position ?? "before"}
                    onChange={(e) => patch(i, { position: e.target.value })}
                  >
                    {positions.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </Select>
                </Field>
                <Field label="Send to">
                  <Select
                    value={rule.outboundTag ?? "direct"}
                    onChange={(e) => patch(i, { outboundTag: e.target.value })}
                  >
                    {available.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </Select>
                </Field>
                <div className="flex items-end">
                  <Button variant="danger" onClick={() => update(items.filter((_, j) => j !== i))}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <ListField
                  label="Domains"
                  rows={2}
                  placeholder="domain:intranet.example.com"
                  value={rule.domain}
                  onChange={(domain) => patch(i, { domain })}
                />
                <ListField
                  label="Networks"
                  rows={2}
                  placeholder="198.51.100.0/24"
                  value={rule.ip}
                  onChange={(ip) => patch(i, { ip })}
                />
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <Field label="Port" hint="optional, e.g. 22 or 1000-2000">
                  <Input
                    className="font-mono"
                    value={rule.port ?? ""}
                    onChange={(e) => patch(i, { port: e.target.value || undefined })}
                  />
                </Field>
                <Field label="Network" hint="optional: tcp, udp, or tcp,udp">
                  <Input
                    className="font-mono"
                    value={rule.network ?? ""}
                    onChange={(e) => patch(i, { network: e.target.value || undefined })}
                  />
                </Field>
              </div>
              {rule.position === "first" && (
                <div className="mt-3">
                  <Badge tone="warn">
                    matched before per-client policy — even a blocked device's traffic reaches this
                  </Badge>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <div className="mt-4">
        <SaveBar
          section="route"
          value={items.length ? items : null}
          dirty={dirty}
          onSaved={() => { setDirty(false); onSaved(); }}
        >
          A rule that matches nothing is refused; give it a domain, network or port.
        </SaveBar>
      </div>
    </Panel>
  );
}
