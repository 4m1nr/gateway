import { useState } from "react";
import { Alert, Badge, Panel } from "./ui";
import { ListField, Toggle } from "./ListField";
import { SaveBar } from "./SaveBar";

const TAILNET = "100.64.0.0/10";

/**
 * Who may reach a service.
 *
 * The stored value is a list of networks, and the toggles are a view onto it:
 * ticking both writes the LAN and the tailnet, ticking one writes just that.
 * Presenting it as two switches rather than a CIDR box is the difference
 * between "make this unavailable on the LAN" being obvious and being something
 * you work out.
 */
export function AccessPanel({
  title,
  description,
  section,
  /** The key inside that section holding the list. The dashboard's is
   *  allow_cidrs; AdGuard's is ui_allow_cidrs, in the [dns] table. */
  field,
  service,
  lanCidr,
  value,
  extraFields,
  onSaved,
  disabledNotice,
}: {
  title: string;
  description: string;
  section: string;
  field: string;
  service: string;
  lanCidr: string;
  /** The section as stored, so unrelated keys survive the save. */
  value: Record<string, unknown>;
  extraFields?: React.ReactNode;
  onSaved: () => void;
  disabledNotice?: React.ReactNode;
}) {
  const stored = (value[field] as string[] | undefined) ?? [];
  // An empty list means the documented default, which is what an untouched
  // config has.
  const effective = stored.length > 0 ? stored : defaultsFor(section, lanCidr);

  const [lan, setLan] = useState(() => effective.includes(lanCidr));
  const [tailnet, setTailnet] = useState(() => effective.includes(TAILNET));
  const [custom, setCustom] = useState<string[]>(() =>
    effective.filter((c) => c !== lanCidr && c !== TAILNET),
  );
  const [dirty, setDirty] = useState(false);

  const next = [
    ...(lan ? [lanCidr] : []),
    ...(tailnet ? [TAILNET] : []),
    ...custom,
  ];
  const closed = next.length === 0;

  const change = (fn: () => void) => {
    fn();
    setDirty(true);
  };

  return (
    <Panel title={title} description={description}>
      <div className="space-y-3">
        <Toggle
          label={`Reachable from the LAN (${lanCidr || "not applied yet"})`}
          checked={lan}
          onChange={(v) => change(() => setLan(v))}
        />
        <Toggle
          label="Reachable over Tailscale"
          hint="The tailnet range, so a device on your tailnet reaches it from anywhere without opening anything to the internet."
          checked={tailnet}
          onChange={(v) => change(() => setTailnet(v))}
        />
        <ListField
          label="Other networks"
          hint="One CIDR per line. Rarely needed."
          rows={2}
          value={custom}
          onChange={(v) => change(() => setCustom(v))}
        />
      </div>

      {extraFields && <div className="mt-4">{extraFields}</div>}

      <div className="mt-4 space-y-3">
        {closed ? (
          <Alert tone="warn" title={`This leaves ${service} unreachable`}>
            {disabledNotice ?? (
              <>With no networks listed, the firewall opens the port to nobody.</>
            )}
          </Alert>
        ) : (
          <p className="text-[11px] text-muted">
            Will be reachable from{" "}
            {next.map((c) => (
              <Badge key={c} tone="muted" className="mr-1 font-mono">
                {c}
              </Badge>
            ))}
          </p>
        )}

        <SaveBar
          section={section}
          value={{ ...value, [field]: next }}
          dirty={dirty}
          onSaved={() => {
            setDirty(false);
            onSaved();
          }}
        >
          The firewall rule changes on the next apply, not on save — so a mistake
          here is undoable from this page.
        </SaveBar>
      </div>
    </Panel>
  );
}

/** What an empty list means for each section, as the config documents it. */
function defaultsFor(section: string, lanCidr: string): string[] {
  // The dashboard defaults to the LAN plus the tailnet; AdGuard's admin
  // interface to the LAN alone, which is what its hardcoded rule used to do.
  return section === "web" ? [lanCidr, TAILNET] : [lanCidr];
}
