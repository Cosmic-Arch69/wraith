
import { useEffect, useState, useCallback, useRef } from "react";
import { Key, Eye, EyeOff, ChevronUp, ChevronDown, ChevronsUpDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { useEngagementStore } from "@/stores/engagement-store";
import { getCredentialRows } from "@/lib/api-extended";
import type { CredentialRow, CredentialScope } from "@/lib/api-extended";
import { cn } from "@/lib/utils";

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const SOURCE_STYLES: Record<string, string> = {
  sqli: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  spray: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  kerberoast: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  dcsync: "bg-red-500/15 text-red-400 border-red-500/30",
  lsass: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  config: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const SCOPE_STYLES: Record<string, string> = {
  domain: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  web: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  local: "bg-green-500/15 text-green-400 border-green-500/30",
};

type SortKey = "username" | "source" | "scope" | "discovered_at";
type SortDir = "asc" | "desc";

function sortCreds(
  creds: CredentialRow[],
  key: SortKey,
  dir: SortDir
): CredentialRow[] {
  return [...creds].sort((a, b) => {
    let av = a[key] as string;
    let bv = b[key] as string;
    if (key === "discovered_at") {
      return dir === "asc"
        ? new Date(av).getTime() - new Date(bv).getTime()
        : new Date(bv).getTime() - new Date(av).getTime();
    }
    av = (av ?? "").toLowerCase();
    bv = (bv ?? "").toLowerCase();
    return dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
  });
}

// -----------------------------------------------------------------------
// Sub-components
// -----------------------------------------------------------------------

function PasswordCell({ row }: { row: CredentialRow }) {
  const [revealed, setRevealed] = useState(false);

  if (row.password) {
    return (
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-xs text-foreground">
          {revealed ? row.password : "••••••••"}
        </span>
        <button
          onClick={() => setRevealed((v) => !v)}
          className="text-muted-foreground hover:text-foreground transition-colors"
          aria-label={revealed ? "Hide password" : "Show password"}
        >
          {revealed ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
        </button>
      </div>
    );
  }

  if (row.hash) {
    const preview = row.hash.length > 16 ? `${row.hash.slice(0, 16)}...` : row.hash;
    return (
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-xs text-muted-foreground">
          {revealed ? row.hash : preview}
        </span>
        {row.hash.length > 16 && (
          <button
            onClick={() => setRevealed((v) => !v)}
            className="text-muted-foreground hover:text-foreground transition-colors"
            aria-label={revealed ? "Collapse hash" : "Expand hash"}
          >
            {revealed ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
          </button>
        )}
      </div>
    );
  }

  return <span className="text-xs text-muted-foreground/50">--</span>;
}

function SortIcon({
  col,
  sortKey,
  sortDir,
}: {
  col: SortKey;
  sortKey: SortKey;
  sortDir: SortDir;
}) {
  if (col !== sortKey) return <ChevronsUpDown className="size-3 opacity-30" />;
  return sortDir === "asc" ? (
    <ChevronUp className="size-3" />
  ) : (
    <ChevronDown className="size-3" />
  );
}

// -----------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------

export default function CredentialsPage() {
  const [rows, setRows] = useState<CredentialRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<"all" | CredentialScope>("all");
  const [sortKey, setSortKey] = useState<SortKey>("discovered_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const prevIdsRef = useRef<Set<string>>(new Set());

  // Pull from SSE-fed store for live updates
  const storeCredentials = useEngagementStore((s) => s.credentials);

  const load = useCallback(async () => {
    try {
      const data = await getCredentialRows();
      setRows(data);
      prevIdsRef.current = new Set(data.map((r) => r.id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load credentials");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Merge live SSE credentials into rows
  useEffect(() => {
    if (storeCredentials.length === 0) return;

    const mapped: CredentialRow[] = storeCredentials.map((c) => ({
      id: c.id,
      username: c.username,
      password: c.plaintext,
      hash: c.hash,
      source: (c.source as CredentialRow["source"]) ?? "config",
      scope: (c.domain ? "domain" : "local") as CredentialScope,
      hosts_valid: c.usedIn ?? [],
      hosts_failed: [],
      discovered_at: c.foundAt,
    }));

    setRows((prev) => {
      const existing = new Map(prev.map((r) => [r.id, r]));
      const added: string[] = [];
      for (const m of mapped) {
        if (!existing.has(m.id)) {
          existing.set(m.id, m);
          if (prevIdsRef.current.has(m.id) === false) {
            added.push(m.id);
          }
        }
      }
      if (added.length > 0) {
        setNewIds((n) => {
          const next = new Set(n);
          added.forEach((id) => next.add(id));
          return next;
        });
        // Clear highlight after 3s
        setTimeout(() => {
          setNewIds((n) => {
            const next = new Set(n);
            added.forEach((id) => next.delete(id));
            return next;
          });
        }, 3000);
        prevIdsRef.current = new Set([...prevIdsRef.current, ...added]);
      }
      return Array.from(existing.values());
    });
  }, [storeCredentials]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const filtered =
    scope === "all" ? rows : rows.filter((r) => r.scope === scope);
  const sorted = sortCreds(filtered, sortKey, sortDir);

  const domainCount = rows.filter((r) => r.scope === "domain").length;
  const webCount = rows.filter((r) => r.scope === "web").length;
  const localCount = rows.filter((r) => r.scope === "local").length;
  const crackedCount = rows.filter((r) => r.password).length;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Key className="w-5 h-5 text-primary" />
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground">
            Credentials
          </h1>
          <p className="text-sm text-muted-foreground">
            All harvested credentials -- hashes, plaintext, Kerberos tickets
          </p>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: "Total", value: rows.length, color: "text-foreground" },
          { label: "Domain", value: domainCount, color: "text-purple-400" },
          { label: "Web", value: webCount, color: "text-blue-400" },
          { label: "Cracked", value: crackedCount, color: "text-green-400" },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="rounded-lg border border-border bg-card p-4 flex flex-col gap-1"
          >
            <span className="text-xs font-medium uppercase tracking-widest text-muted-foreground">
              {label}
            </span>
            <span className={cn("text-2xl font-bold font-mono", color)}>
              {value}
            </span>
          </div>
        ))}
      </div>

      {/* Scope tabs + table */}
      <Tabs
        value={scope}
        onValueChange={(v) => setScope(v as typeof scope)}
      >
        <TabsList>
          <TabsTrigger value="all">All ({rows.length})</TabsTrigger>
          <TabsTrigger value="domain">Domain ({domainCount})</TabsTrigger>
          <TabsTrigger value="web">Web ({webCount})</TabsTrigger>
          <TabsTrigger value="local">Local ({localCount})</TabsTrigger>
        </TabsList>

        {(["all", "domain", "web", "local"] as const).map((tab) => (
          <TabsContent key={tab} value={tab}>
            {loading ? (
              <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
                Loading credentials...
              </div>
            ) : error ? (
              <div className="rounded-lg border border-destructive/30 bg-card p-6 text-center text-sm text-destructive">
                {error}
              </div>
            ) : sorted.length === 0 ? (
              <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
                <Key className="w-8 h-8 mx-auto mb-2 text-muted-foreground/40" />
                <p>No credentials found for this scope.</p>
              </div>
            ) : (
              <div className="rounded-lg border border-border bg-card overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b border-border hover:bg-transparent">
                      <TableHead>
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => handleSort("username")}
                          className="gap-1 font-medium text-foreground"
                        >
                          Username
                          <SortIcon col="username" sortKey={sortKey} sortDir={sortDir} />
                        </Button>
                      </TableHead>
                      <TableHead className="text-foreground font-medium">
                        Password / Hash
                      </TableHead>
                      <TableHead>
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => handleSort("source")}
                          className="gap-1 font-medium text-foreground"
                        >
                          Source
                          <SortIcon col="source" sortKey={sortKey} sortDir={sortDir} />
                        </Button>
                      </TableHead>
                      <TableHead>
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => handleSort("scope")}
                          className="gap-1 font-medium text-foreground"
                        >
                          Scope
                          <SortIcon col="scope" sortKey={sortKey} sortDir={sortDir} />
                        </Button>
                      </TableHead>
                      <TableHead className="text-foreground font-medium">
                        Hosts Valid
                      </TableHead>
                      <TableHead>
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => handleSort("discovered_at")}
                          className="gap-1 font-medium text-foreground"
                        >
                          Discovered
                          <SortIcon col="discovered_at" sortKey={sortKey} sortDir={sortDir} />
                        </Button>
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {sorted.map((row) => (
                      <TableRow
                        key={row.id}
                        className={cn(
                          "border-b border-border/50 transition-colors",
                          newIds.has(row.id) &&
                            "animate-pulse bg-primary/10 border-primary/30"
                        )}
                      >
                        <TableCell>
                          <span className="font-bold font-mono text-sm text-foreground">
                            {row.username}
                          </span>
                        </TableCell>
                        <TableCell>
                          <PasswordCell row={row} />
                        </TableCell>
                        <TableCell>
                          <span
                            className={cn(
                              "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
                              SOURCE_STYLES[row.source] ?? SOURCE_STYLES.config
                            )}
                          >
                            {row.source}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span
                            className={cn(
                              "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
                              SCOPE_STYLES[row.scope] ?? SCOPE_STYLES.local
                            )}
                          >
                            {row.scope}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="font-mono text-xs text-muted-foreground">
                            {row.hosts_valid.length > 0
                              ? row.hosts_valid.join(", ")
                              : "--"}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="font-mono text-xs text-muted-foreground">
                            {relativeTime(row.discovered_at)}
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
