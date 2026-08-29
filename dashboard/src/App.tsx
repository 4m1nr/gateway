import { Suspense, lazy, useCallback, useEffect, useState } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { api, setCsrf, setSignedOutHandler, type Session, type Status } from "@/lib/api";
import { Layout } from "@/components/Layout";
import { Login } from "@/components/Login";
import { Alert, Button, Spinner } from "@/components/ui";
import { Overview } from "@/pages/Overview";
import { Clients } from "@/pages/Clients";
import { Jobs } from "@/pages/Jobs";
import { System } from "@/pages/System";
import { usePoll } from "@/lib/usePoll";

// The JSON editor is the largest dependency in the app and is only needed on
// one page. Loading it lazily keeps the first paint to the parts every visit
// uses; the editor arrives when you actually open Xray.
const Xray = lazy(() => import("@/pages/Xray").then((m) => ({ default: m.Xray })));

/**
 * A change is saved to gateway.toml the moment it is made, but nothing is live
 * until apply renders, validates and reloads. This banner is the difference,
 * and it is deliberately hard to miss: a config saved and never applied is the
 * single most confusing state this box can be in.
 */
function PendingApply({ onApplied }: { onApplied: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="sticky top-0 z-10 border-b border-warn/30 bg-warn/10 px-6 py-2.5">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-warn">
          Changes are saved but not live. Apply renders, validates with{" "}
          <span className="font-mono">nft -c</span> and{" "}
          <span className="font-mono">xray -test</span>, then reloads — a config
          that would break the gateway is refused rather than half-applied.
        </p>
        <Button
          variant="primary"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            setError(null);
            api
              .post("/api/apply")
              .then(onApplied)
              .catch((err) => setError(err instanceof Error ? err.message : String(err)))
              .finally(() => setBusy(false));
          }}
        >
          {busy ? <Spinner /> : null} {busy ? "Applying…" : "Apply"}
        </Button>
      </div>
      {error && (
        <div className="mx-auto mt-2 max-w-5xl">
          <Alert tone="bad" title="Apply failed — nothing was changed">
            <pre className="whitespace-pre-wrap font-mono text-[11px]">{error}</pre>
          </Alert>
        </div>
      )}
    </div>
  );
}

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [pending, setPending] = useState(false);

  const loadSession = useCallback(async () => {
    const s = await api.get<Session>("/api/session");
    setCsrf(s.csrf);
    setSession(s);
  }, []);

  useEffect(() => {
    setSignedOutHandler(() => {
      setSession((prev) => (prev ? { ...prev, authenticated: false, csrf: null } : prev));
    });
    void loadSession();
  }, [loadSession]);

  // Status is polled once here and handed to the layout, so the sidebar and the
  // overview never disagree about whether the tunnel is up.
  const { data: status } = usePoll<Status>(
    () => api.get<Status>("/api/status"),
    5000,
  );

  if (!session) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner className="text-muted" />
      </div>
    );
  }

  if (!session.authenticated) {
    return <Login passwordSet={session.password_set} onSignedIn={() => void loadSession()} />;
  }

  const signOut = () => {
    void api.post("/api/logout").finally(() => void loadSession());
  };

  return (
    <BrowserRouter>
      {pending && <PendingApply onApplied={() => setPending(false)} />}
      <Routes>
        <Route element={<Layout status={status} onSignOut={signOut} />}>
          <Route index element={<Overview />} />
          <Route path="clients" element={<Clients onPending={() => setPending(true)} />} />
          <Route
            path="xray"
            element={
              <Suspense fallback={<div className="py-10 text-center"><Spinner className="text-muted" /></div>}>
                <Xray />
              </Suspense>
            }
          />
          <Route path="jobs" element={<Jobs onPending={() => setPending(true)} />} />
          <Route path="system" element={<System />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
