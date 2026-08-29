import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  CalendarClock,
  Globe,
  LayoutDashboard,
  LogOut,
  MonitorSmartphone,
  Moon,
  Route,
  Settings2,
  Sun,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { Badge, Button } from "./ui";
import type { Status } from "@/lib/api";
import { useEffect, useState } from "react";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/clients", label: "Clients", icon: MonitorSmartphone },
  { to: "/routing", label: "Routing", icon: Route },
  { to: "/dns", label: "DNS", icon: Globe },
  { to: "/xray", label: "Xray", icon: Activity },
  { to: "/jobs", label: "Jobs", icon: CalendarClock },
  { to: "/console", label: "Console", icon: Terminal },
  { to: "/settings", label: "Settings", icon: Settings2 },
];

/** Tunnel state is in the sidebar on every page: it is the one fact that
 *  changes what any other page means. */
function TunnelPill({ status }: { status: Status | null }) {
  if (!status) return <Badge tone="muted">checking…</Badge>;
  switch (status.tunnel) {
    case "up":
      return <Badge tone="ok">tunnel up</Badge>;
    case "degraded":
      // Distinct from "down" on purpose: Xray is fine and the packets are not
      // reaching it, which is a different half of the system to go look at.
      return <Badge tone="bad">interception broken</Badge>;
    case "down":
      return <Badge tone="bad">tunnel down</Badge>;
    default:
      return <Badge tone="warn">unknown</Badge>;
  }
}

function useTheme() {
  const [dark, setDark] = useState(
    () => localStorage.getItem("gw-theme") !== "light",
  );
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("gw-theme", dark ? "dark" : "light");
  }, [dark]);
  return [dark, setDark] as const;
}

export function Layout({
  status,
  onSignOut,
}: {
  status: Status | null;
  onSignOut: () => void;
}) {
  const [dark, setDark] = useTheme();

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-surface">
        <div className="flex items-center gap-2 px-5 py-5">
          <span className="text-lg">🛡️</span>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold tracking-tight">Gateway</p>
            <p className="truncate font-mono text-[11px] text-muted">
              {status?.box_ip || "…"}
            </p>
          </div>
        </div>

        <nav className="flex-1 space-y-0.5 px-3">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors",
                  isActive
                    ? "bg-accent/10 text-accent"
                    : "text-muted hover:bg-raised hover:text-fg",
                )
              }
            >
              <Icon className="size-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="space-y-3 border-t border-border p-3">
          <div className="px-2">
            <TunnelPill status={status} />
            {status?.lifeline && (
              <p className="mt-2 text-[11px] leading-snug text-warn">
                Lifeline engaged — tailscaled is bypassing the tunnel so remote
                access survives. Client traffic stays fail-closed.
              </p>
            )}
          </div>
          <div className="flex gap-1.5">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => setDark(!dark)}
              title={dark ? "Switch to light" : "Switch to dark"}
            >
              {dark ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
            </Button>
            <Button variant="ghost" className="flex-1" onClick={onSignOut} title="Sign out">
              <LogOut className="size-3.5" />
            </Button>
          </div>
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-5xl p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
