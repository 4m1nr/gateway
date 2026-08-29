import { useState, type FormEvent } from "react";
import { api, ApiError, setCsrf } from "@/lib/api";
import { Alert, Button, Input } from "./ui";

/**
 * The login screen.
 *
 * It distinguishes three states, because they have three different fixes: no
 * password set (run `gw web-passwd`), the wrong password (try again), and the
 * privileged helper not answering (nothing typed here will help). Collapsing
 * the third into the first is how someone ends up running web-passwd over and
 * over while the page keeps saying no password is set.
 */
export function Login({
  passwordSet,
  helperError,
  onSignedIn,
}: {
  passwordSet: boolean;
  helperError: string;
  onSignedIn: () => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<{ csrf: string }>("/api/login", { password });
      setCsrf(res.csrf);
      onSignedIn();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "could not sign in");
    } finally {
      setBusy(false);
      setPassword("");
    }
  }

  return (
    <div className="flex h-full items-center justify-center p-6">
      <form onSubmit={submit} className="w-full max-w-xs space-y-4">
        <div className="text-center">
          <p className="text-3xl">🛡️</p>
          <h1 className="mt-2 text-lg font-semibold tracking-tight">Gateway</h1>
          <p className="mt-1 text-xs text-muted">
            {helperError
              ? "Cannot reach the privileged helper."
              : passwordSet
                ? "Enter the dashboard password."
                : "No password is set yet."}
          </p>
        </div>

        {helperError ? (
          <Alert tone="bad" title="The privileged helper is not answering">
            <p>
              The dashboard cannot ask the box anything, so it cannot tell
              whether a password is set. Running{" "}
              <code className="font-mono">gw web-passwd</code> will not fix this.
            </p>
            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-[11px] opacity-80">
              {helperError}
            </pre>
            <p className="mt-2">
              On the box: <code className="font-mono">sudo gw apply</code> to
              reinstall the helper and its sudo grant, then{" "}
              <code className="font-mono">journalctl -u gw-web -n 50</code>.
            </p>
          </Alert>
        ) : !passwordSet ? (
          <Alert tone="warn" title="No dashboard password">
            Run <code className="font-mono">sudo gw web-passwd</code> on the box.
            Until then every login is refused.
          </Alert>
        ) : null}

        <Input
          type="password"
          autoComplete="current-password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={!passwordSet || !!helperError || busy}
          autoFocus
          required
        />

        {error && <Alert tone="bad">{error}</Alert>}

        <Button
          type="submit"
          variant="primary"
          className="w-full py-2"
          disabled={!passwordSet || !!helperError || busy || !password}
        >
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </div>
  );
}
