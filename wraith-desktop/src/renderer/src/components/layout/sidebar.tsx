import React from "react";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  GitBranch,
  Bot,
  Clock,
  Shield,
  Key,
  AlertTriangle,
  FileText,
  Wifi,
  WifiOff,
  Crosshair,
  Play,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useEngagementStore } from "@/stores/engagement-store";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  separator?: boolean;
}

const navItems: NavItem[] = [
  {
    label: "New Engagement",
    href: "/launch",
    icon: Play,
    separator: true,
  },
  {
    label: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    label: "Attack Graph",
    href: "/graph",
    icon: GitBranch,
  },
  {
    label: "Agents",
    href: "/agents",
    icon: Bot,
  },
  {
    label: "Timeline",
    href: "/timeline",
    icon: Clock,
  },
  {
    label: "MITRE ATT&CK",
    href: "/mitre",
    icon: Shield,
  },
  {
    label: "Credentials",
    href: "/credentials",
    icon: Key,
  },
  {
    label: "Findings",
    href: "/findings",
    icon: AlertTriangle,
  },
  {
    label: "Report",
    href: "/report",
    icon: FileText,
  },
  {
    label: "Knowledge Graph",
    href: "/ontology",
    icon: GitBranch,
  },
];

export function Sidebar() {
  const { pathname } = useLocation();
  const sseConnected = useEngagementStore((s) => s.sseConnected);

  return (
    <aside className="w-60 shrink-0 flex flex-col h-full border-r border-border bg-sidebar overflow-hidden">
      {/* Brand */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
        <div className="flex items-center justify-center w-8 h-8 rounded bg-primary/10 border border-primary/30">
          <Crosshair className="w-4 h-4 text-primary" />
        </div>
        <div className="flex flex-col leading-none">
          <span className="text-sm font-bold tracking-widest uppercase text-foreground">
            Wraith
          </span>
          <span className="text-[10px] text-muted-foreground tracking-wider">
            PENTEST CONSOLE
          </span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto scrollbar-thin">
        <p className="px-2 pb-2 text-[10px] font-semibold tracking-widest uppercase text-muted-foreground/60">
          Navigation
        </p>
        {navItems.map(({ label, href, icon: Icon, separator }) => {
          const isActive =
            href === "/" ? pathname === "/" : pathname.startsWith(href);
          const isLaunch = href === "/launch";
          return (
            <React.Fragment key={href}>
              <Tooltip>
                <TooltipTrigger
                  className="w-full text-left"
                  render={
                    <Link
                      to={href}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-150 group",
                        isLaunch
                          ? isActive
                            ? "bg-red-500/15 text-red-500 border border-red-500/25"
                            : "text-red-500/80 hover:text-red-500 hover:bg-red-500/10 border border-transparent"
                          : isActive
                            ? "bg-primary/10 text-primary border border-primary/20"
                            : "text-muted-foreground hover:text-foreground hover:bg-secondary border border-transparent"
                      )}
                    >
                      <Icon
                        className={cn(
                          "w-4 h-4 shrink-0",
                          isLaunch
                            ? isActive
                              ? "text-red-500"
                              : "text-red-500/70 group-hover:text-red-500"
                            : isActive
                              ? "text-primary"
                              : "text-muted-foreground group-hover:text-foreground"
                        )}
                      />
                      <span className="truncate">{label}</span>
                      {isActive && (
                        <span
                          className={cn(
                            "ml-auto w-1 h-1 rounded-full",
                            isLaunch ? "bg-red-500" : "bg-primary"
                          )}
                        />
                      )}
                    </Link>
                  }
                />
                <TooltipContent side="right" className="text-xs">
                  {label}
                </TooltipContent>
              </Tooltip>
              {separator && (
                <div className="mx-2 my-2 h-px bg-border" />
              )}
            </React.Fragment>
          );
        })}
      </nav>

      {/* Connection status footer */}
      <div className="px-5 py-3 border-t border-border">
        <div className="flex items-center gap-2">
          {sseConnected ? (
            <Wifi className="w-3.5 h-3.5 text-emerald-500" />
          ) : (
            <WifiOff className="w-3.5 h-3.5 text-muted-foreground" />
          )}
          <span className="text-[11px] text-muted-foreground">
            {sseConnected ? (
              <span className="text-emerald-400">Live feed active</span>
            ) : (
              "Not connected"
            )}
          </span>
          {sseConnected && (
            <span className="ml-auto flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
          )}
        </div>
      </div>
    </aside>
  );
}
