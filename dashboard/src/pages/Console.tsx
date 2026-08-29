import { useEffect, useRef, useState } from "react";
import { Play, TriangleAlert } from "lucide-react";
import { api, ApiError, type CommandResult, type GwCommand } from "@/lib/api";
import { Alert, Badge, Button, Empty, Input, Panel, Spinner } from "@/components/ui";

/**
 * Running gw commands from the dashboard.
 *
 * The server holds a whitelist of fixed argument lists — this page cannot ask
 * for anything that is not on it, and the one free argument some commands take
 * is validated there rather than here. What this page adds is the part a server
 * cannot judge: whether the person meant to interrupt everyone's internet.
 */
export function Console() {
  const [commands, setCommands] = useState<GwCommand[] | null>(null);
  const [excluded, setExcluded] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [result, setResult] = useState<CommandResult | null>(null);
  const [args, setArgs] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState<string | null>(null);
  const outputRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    void (async () => {
      try {
        const res = await api.get<{ commands: GwCommand[]; excluded: string[] }>("/api/commands");
        setCommands(res.commands);
        setExcluded(res.excluded ?? []);
      } catch (err) {
        setError(err instanceof ApiError ? err.message : String(err));
      }
    })();
  }, []);

  useEffect(() => {
    outputRef.current?.scrollTo({ top: outputRef.current.scrollHeight });
  }, [result]);

  async function run(command: GwCommand) {
    setRunning(command.name);
    setConfirming(null);
    setError(null);
    setResult(null);
    try {
      const value = args[command.name]?.trim();
      const res = await api.post<CommandResult>(
        `/api/commands/${encodeURIComponent(command.name)}`,
        { args: command.argument && value ? [value] : [] },
      );
      setResult(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setRunning(null);
    }
  }

  if (error && !commands) return <Alert tone="bad" title="Could not load the command list">{error}</Alert>;
  if (!commands) return <Empty>Loading…</Empty>;

  const safe = commands.filter((c) => !c.disruptive);
  const disruptive = commands.filter((c) => c.disruptive);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Console</h1>
        <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-muted">
          The gw commands, run on the box. Output is captured and shown below;
          nothing here is interactive.
        </p>
      </div>

      {error && <Alert tone="bad">{error}</Alert>}

      <Panel title="Read-only" description="These change nothing. Run them freely.">
        <div className="grid gap-2 sm:grid-cols-2">
          {safe.map((c) => (
            <CommandRow
              key={c.name}
              command={c}
              running={running}
              argValue={args[c.name] ?? ""}
              onArg={(v) => setArgs((a) => ({ ...a, [c.name]: v }))}
              onRun={() => void run(c)}
            />
          ))}
        </div>
      </Panel>

      <Panel
        title="Disruptive"
        description="Each of these interrupts service. Applying reloads the firewall and restarts Xray; restarting or updating drops every live connection on every client."
      >
        <div className="grid gap-2 sm:grid-cols-2">
          {disruptive.map((c) => (
            <CommandRow
              key={c.name}
              command={c}
              running={running}
              argValue={args[c.name] ?? ""}
              onArg={(v) => setArgs((a) => ({ ...a, [c.name]: v }))}
              confirming={confirming === c.name}
              onRun={() => (confirming === c.name ? void run(c) : setConfirming(c.name))}
              onCancel={() => setConfirming(null)}
            />
          ))}
        </div>
      </Panel>

      {excluded.length > 0 && (
        <Alert tone="muted" title="Not available here, on purpose">
          <p>
            <span className="font-mono">{excluded.join(", ")}</span>
          </p>
          <p className="mt-1.5">
            <span className="font-mono">panic</span> removes the killswitch and lets
            everything out unproxied — the command you run when you have lost
            confidence in the gateway, which is when you want a console rather than
            its web UI. <span className="font-mono">disable</span> would take the
            dashboard down with it. The rest are interactive or long-lived, and need
            a terminal.
          </p>
        </Alert>
      )}

      {(running || result) && (
        <Panel
          title={running ? `Running gw ${running}…` : `gw ${result?.command}`}
          actions={
            result ? (
              <Badge tone={result.status === "ok" ? "ok" : result.status === "timeout" ? "warn" : "bad"}>
                {result.status}
              </Badge>
            ) : (
              <Spinner className="text-muted" />
            )
          }
        >
          <pre
            ref={outputRef}
            className="max-h-[28rem] overflow-auto rounded-lg bg-raised p-3 font-mono text-[11px] leading-relaxed"
          >
            {result?.output || (running ? "waiting for output…" : "")}
          </pre>
          {result?.status === "failed" && (
            <p className="mt-2 text-[11px] text-muted">
              A non-zero exit is a result, not a transport failure —{" "}
              <span className="font-mono">gw check</span> exits non-zero when a check
              fails, and the output above is the answer.
            </p>
          )}
        </Panel>
      )}
    </div>
  );
}

function CommandRow({
  command,
  running,
  argValue,
  onArg,
  onRun,
  onCancel,
  confirming = false,
}: {
  command: GwCommand;
  running: string | null;
  argValue: string;
  onArg: (v: string) => void;
  onRun: () => void;
  onCancel?: () => void;
  confirming?: boolean;
}) {
  const busy = running === command.name;
  const blocked = running !== null && !busy;

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-xs font-medium">gw {command.args?.slice(1).length ? command.args.join(" ") : command.name}</p>
          <p className="mt-0.5 text-[11px] leading-relaxed text-muted">{command.summary}</p>
        </div>
        {command.disruptive && <TriangleAlert className="size-3.5 shrink-0 text-warn" />}
      </div>

      {command.argument && (
        <Input
          className="font-mono"
          placeholder={command.argument}
          value={argValue}
          onChange={(e) => onArg(e.target.value)}
        />
      )}

      {confirming ? (
        <div className="flex gap-2">
          <Button variant="danger" className="flex-1" onClick={onRun} disabled={busy}>
            Yes, run it
          </Button>
          <Button onClick={onCancel}>Cancel</Button>
        </div>
      ) : (
        <Button
          variant={command.disruptive ? "secondary" : "primary"}
          onClick={onRun}
          disabled={busy || blocked}
        >
          {busy ? <Spinner /> : <Play className="size-3.5" />}
          {busy ? "Running…" : command.disruptive ? "Run…" : "Run"}
        </Button>
      )}
    </div>
  );
}
