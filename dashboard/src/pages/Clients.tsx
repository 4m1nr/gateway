import { useState, type FormEvent } from "react";
import { Trash2 } from "lucide-react";
import { api, ApiError, type ClientsResponse } from "@/lib/api";
import {
  Alert,
  Button,
  Empty,
  Input,
  Panel,
  PolicyBadge,
  Select,
} from "@/components/ui";
import { usePoll } from "@/lib/usePoll";

const policyHint: Record<string, string> = {
  proxy: "force through the tunnel",
  direct: "bypass the tunnel",
  block: "drop at the gateway",
};

export function Clients({ onPending }: { onPending: () => void }) {
  const { data, error, refresh } = usePoll<ClientsResponse>(
    () => api.get<ClientsResponse>("/api/clients"),
    15000,
  );
  const [ip, setIp] = useState("");
  const [name, setName] = useState("");
  const [policy, setPolicy] = useState("proxy");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function add(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await api.post("/api/clients", { ip, name, policy });
      setIp("");
      setName("");
      onPending();
      await refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "could not add the device");
    } finally {
      setBusy(false);
    }
  }

  async function remove(clientIp: string) {
    try {
      await api.del(`/api/clients/${encodeURIComponent(clientIp)}`);
      onPending();
      await refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "could not remove the device");
    }
  }

  if (error) return <Alert tone="bad" title="Could not read the client list">{error}</Alert>;
  if (!data) return <Empty>Loading…</Empty>;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Clients</h1>
        <p className="mt-0.5 text-xs leading-relaxed text-muted">
          The default is <span className="font-mono">{data.default_policy}</span> —
          any device that points its gateway at this box gets that without being
          listed. Entries below are overrides, and each needs a static IP or a
          DHCP reservation on the router.
        </p>
      </div>

      {data.config_error && (
        <Alert tone="bad" title="The config does not load">
          {data.config_error}
          <p className="mt-1">
            Only the built-in policies are offered until this is fixed.
          </p>
        </Alert>
      )}

      <Panel title="Add an override">
        <form onSubmit={add} className="grid gap-3 sm:grid-cols-[1fr_1fr_1fr_auto]">
          <Input
            placeholder="192.168.1.50"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            required
          />
          <Input
            placeholder="living room tv"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <Select value={policy} onChange={(e) => setPolicy(e.target.value)}>
            {data.policies.map((p) => (
              <option key={p} value={p}>
                {p}
                {policyHint[p] ? ` — ${policyHint[p]}` : data.profiles.includes(p) ? " — profile" : ""}
              </option>
            ))}
          </Select>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Saving…" : "Add"}
          </Button>
        </form>
        {formError && <div className="mt-3"><Alert tone="bad">{formError}</Alert></div>}

        {data.profiles.includes(policy) && (
          <div className="mt-3">
            <Alert tone="warn" title="A profile device is always intercepted">
              Splitting traffic by destination requires Xray to see it, so a
              profile is fail-closed like any proxied device — if the tunnel
              dies it loses connectivity rather than falling back to a direct
              path. That is the cost of the split, not a bug.
            </Alert>
          </div>
        )}
      </Panel>

      <Panel
        title="Overrides"
        description={`${data.clients.length} listed — every [[client]] in gateway.toml, however it was written`}
      >
        {data.clients.length === 0 ? (
          <Empty>No overrides — every device gets the default.</Empty>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted">
                <th className="pb-2 font-medium">Address</th>
                <th className="pb-2 font-medium">Name</th>
                <th className="pb-2 font-medium">Policy</th>
                <th className="pb-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data.clients.map((c) => (
                <tr key={c.ip}>
                  <td className="py-2 font-mono">{c.ip}</td>
                  <td className="py-2">{c.name}</td>
                  <td className="py-2">
                    <PolicyBadge policy={c.policy} profiles={data.profiles} />
                  </td>
                  <td className="py-2 text-right">
                    {c.editable ? (
                      <Button
                        variant="danger"
                        onClick={() => void remove(c.ip)}
                        title={`Remove ${c.ip}`}
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    ) : (
                      <span
                        className="text-[11px] text-muted"
                        title="This entry holds settings the editor does not model. It is in force; change it in gateway.toml."
                      >
                        edit in the file
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
