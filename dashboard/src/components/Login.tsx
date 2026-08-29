import { useState, type FormEvent } from "react";
import { api, ApiError, setCsrf } from "@/lib/api";
import { Alert, Button, Input } from "./ui";

/**
 * The login screen. It reports the difference between "no password is set" and
 * "wrong password", because the first is fixed on the box with
 * `sudo gw web-passwd` and the second is not.
 */
export function Login({
  passwordSet,
  onSignedIn,
}: {
  passwordSet: boolean;
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
            {passwordSet
              ? "Enter the dashboard password."
              : "No password is set yet."}
          </p>
        </div>

        {!passwordSet && (
          <Alert tone="warn" title="No dashboard password">
            Run <code className="font-mono">sudo gw web-passwd</code> on the box.
            Until then every login is refused.
          </Alert>
        )}

        <Input
          type="password"
          autoComplete="current-password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={!passwordSet || busy}
          autoFocus
          required
        />

        {error && <Alert tone="bad">{error}</Alert>}

        <Button
          type="submit"
          variant="primary"
          className="w-full py-2"
          disabled={!passwordSet || busy || !password}
        >
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </div>
  );
}
