import { useState, type FormEvent } from "react";
import { Pause, Play, Trash2 } from "lucide-react";
import { api, ApiError, type Job } from "@/lib/api";
import {
  Alert,
  Badge,
  Button,
  Empty,
  Input,
  Panel,
  Textarea,
} from "@/components/ui";
import { usePoll } from "@/lib/usePoll";

export function Jobs({ onPending }: { onPending: () => void }) {
  const { data, error, refresh } = usePoll<{ jobs: Job[] }>(
    () => api.get<{ jobs: Job[] }>("/api/jobs"),
    30000,
  );
  const [name, setName] = useState("");
  const [schedule, setSchedule] = useState("");
  const [user, setUser] = useState("root");
  const [description, setDescription] = useState("");
  const [script, setScript] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await api.post("/api/jobs", { name, schedule, user, description, script });
      setName("");
      setSchedule("");
      setDescription("");
      setScript("");
      onPending();
      await refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "could not save the job");
    } finally {
      setBusy(false);
    }
  }

  async function act(fn: () => Promise<unknown>) {
    try {
      await fn();
      onPending();
      await refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : String(err));
    }
  }

  if (error) return <Alert tone="bad" title="Could not read the job list">{error}</Alert>;
  if (!data) return <Empty>Loading…</Empty>;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Jobs</h1>
        <p className="mt-0.5 text-xs leading-relaxed text-muted">
          Bash on a cron schedule, stored in gateway.toml so a rebuilt box comes
          back with them.
        </p>
      </div>

      <Alert tone="bad" title="Jobs run as root unless the user says otherwise">
        This editor is the most powerful thing on the box: anyone past the login
        can run arbitrary code as root. That is inherent to the feature, not a
        flaw in it — but it means the dashboard password is a root password. Set{" "}
        <span className="font-mono">[web] enabled = false</span> if you would
        rather not have that reachable over the network.
      </Alert>

      <Panel
        title="Add a job"
        description="Output goes to the journal, where `gw logs` can find it — a box with no MTA silently discards what cron would otherwise mail."
      >
        <form onSubmit={save} className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-4">
            <Input
              placeholder="nightly-backup"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <Input
              placeholder="0 4 * * *  or  @daily"
              value={schedule}
              onChange={(e) => setSchedule(e.target.value)}
              className="font-mono"
              required
            />
            <Input placeholder="root" value={user} onChange={(e) => setUser(e.target.value)} />
            <Input
              placeholder="what it does"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <Textarea
            rows={8}
            placeholder={"#!/bin/bash is added for you\ntar -czf /tmp/gateway.tgz /opt/gateway"}
            value={script}
            onChange={(e) => setScript(e.target.value)}
            required
          />
          <div className="flex items-center justify-between gap-3">
            <p className="text-[11px] leading-snug text-muted">
              Stored as a TOML literal string, so backslash continuations and
              <span className="font-mono"> \n </span> survive exactly as typed.
            </p>
            <Button type="submit" variant="primary" disabled={busy}>
              {busy ? "Saving…" : "Save job"}
            </Button>
          </div>
        </form>
        {formError && <div className="mt-3"><Alert tone="bad">{formError}</Alert></div>}
      </Panel>

      <Panel title="Scheduled" description={`${data.jobs.length} defined`}>
        {data.jobs.length === 0 ? (
          <Empty>No scheduled jobs.</Empty>
        ) : (
          <div className="divide-y divide-border">
            {data.jobs.map((job) => (
              <div key={job.name} className="flex items-start justify-between gap-4 py-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-medium">{job.name}</span>
                    <Badge tone={job.enabled ? "ok" : "muted"}>
                      {job.enabled ? "enabled" : "disabled"}
                    </Badge>
                    <span className="font-mono text-[11px] text-muted">{job.schedule}</span>
                    <Badge tone={job.user === "root" ? "warn" : "muted"}>{job.user}</Badge>
                    {!job.managed && (
                      <Badge tone="accent" className="font-normal">
                        hand-written
                      </Badge>
                    )}
                  </div>
                  {job.description && (
                    <p className="mt-1 text-[11px] text-muted">{job.description}</p>
                  )}
                  <pre className="mt-2 max-h-24 overflow-auto rounded-lg bg-raised p-2 font-mono text-[11px] leading-relaxed">
                    {job.script.trim()}
                  </pre>
                </div>
                <div className="flex shrink-0 gap-1.5">
                  <Button
                    onClick={() =>
                      void act(() =>
                        api.post(`/api/jobs/${encodeURIComponent(job.name)}/toggle`, {
                          enabled: !job.enabled,
                        }),
                      )
                    }
                    disabled={!job.managed}
                    title={job.managed ? "" : "Hand-written jobs are edited in gateway.toml"}
                  >
                    {job.enabled ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
                  </Button>
                  <Button
                    variant="danger"
                    onClick={() =>
                      void act(() => api.del(`/api/jobs/${encodeURIComponent(job.name)}`))
                    }
                    disabled={!job.managed}
                    title={job.managed ? "" : "Hand-written jobs are removed in gateway.toml"}
                  >
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
