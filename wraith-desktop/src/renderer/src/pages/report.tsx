
import { useEffect, useState, useCallback, useRef, useMemo } from "react";
import { FileText, Printer, ChevronDown, ChevronRight, BookOpen } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Button } from "@/components/ui/button";
import { getReportMarkdown, NotFoundError } from "@/lib/api-extended";
import { cn } from "@/lib/utils";

// -----------------------------------------------------------------------
// Extract h2 headings from markdown for the ToC
// -----------------------------------------------------------------------

interface TocEntry {
  id: string;
  text: string;
}

function extractH2Headings(markdown: string): TocEntry[] {
  const lines = markdown.split("\n");
  const headings: TocEntry[] = [];
  for (const line of lines) {
    const match = /^## (.+)$/.exec(line);
    if (match) {
      const text = match[1].trim();
      const id = text
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "");
      headings.push({ id, text });
    }
  }
  return headings;
}

// -----------------------------------------------------------------------
// Collapsible H2 section wrapper
// -----------------------------------------------------------------------

interface CollapsibleSectionProps {
  id: string;
  title: string;
  children: React.ReactNode;
}

function CollapsibleSection({ id, title, children }: CollapsibleSectionProps) {
  const [open, setOpen] = useState(true);

  return (
    <section id={id} className="mb-6">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 group text-left mb-3"
      >
        {open ? (
          <ChevronDown className="size-4 text-muted-foreground group-hover:text-foreground transition-colors shrink-0" />
        ) : (
          <ChevronRight className="size-4 text-muted-foreground group-hover:text-foreground transition-colors shrink-0" />
        )}
        <h2 className="text-lg font-semibold text-foreground group-hover:text-primary transition-colors">
          {title}
        </h2>
      </button>
      {open && <div className="pl-6">{children}</div>}
    </section>
  );
}

// -----------------------------------------------------------------------
// Markdown prose styles (manual, no @tailwindcss/typography)
// -----------------------------------------------------------------------

const proseComponents = {
  h1: ({ children }: { children?: React.ReactNode }) => (
    <h1 className="text-2xl font-bold text-foreground mt-8 mb-4 border-b border-border pb-2">
      {children}
    </h1>
  ),
  h2: ({ children }: { children?: React.ReactNode }) => {
    const text = String(children ?? "");
    const id = text
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    return (
      <CollapsibleSection id={id} title={text}>
        {/* Children rendered by parent logic -- this h2 is the trigger */}
        <></>
      </CollapsibleSection>
    );
  },
  h3: ({ children }: { children?: React.ReactNode }) => (
    <h3 className="text-base font-semibold text-foreground mt-5 mb-2">
      {children}
    </h3>
  ),
  h4: ({ children }: { children?: React.ReactNode }) => (
    <h4 className="text-sm font-semibold text-foreground mt-4 mb-1.5">
      {children}
    </h4>
  ),
  p: ({ children }: { children?: React.ReactNode }) => (
    <p className="text-sm text-foreground/85 leading-relaxed mb-3">{children}</p>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <ul className="list-disc list-outside pl-5 mb-3 text-sm text-foreground/85 space-y-1">
      {children}
    </ul>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <ol className="list-decimal list-outside pl-5 mb-3 text-sm text-foreground/85 space-y-1">
      {children}
    </ol>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <li className="leading-relaxed">{children}</li>
  ),
  blockquote: ({ children }: { children?: React.ReactNode }) => (
    <blockquote className="border-l-2 border-primary pl-4 my-3 text-sm text-muted-foreground italic">
      {children}
    </blockquote>
  ),
  code: ({ children, className }: { children?: React.ReactNode; className?: string }) => {
    const isBlock = className?.startsWith("language-");
    if (isBlock) {
      return (
        <code className="block font-mono text-xs text-foreground/90 bg-muted/60 rounded-lg p-3 mb-3 overflow-x-auto whitespace-pre">
          {children}
        </code>
      );
    }
    return (
      <code className="font-mono text-xs text-primary bg-primary/10 rounded px-1.5 py-0.5">
        {children}
      </code>
    );
  },
  pre: ({ children }: { children?: React.ReactNode }) => (
    <pre className="mb-3">{children}</pre>
  ),
  table: ({ children }: { children?: React.ReactNode }) => (
    <div className="overflow-x-auto mb-4">
      <table className="w-full text-sm border-collapse border border-border rounded">
        {children}
      </table>
    </div>
  ),
  thead: ({ children }: { children?: React.ReactNode }) => (
    <thead className="bg-muted/50">{children}</thead>
  ),
  tr: ({ children }: { children?: React.ReactNode }) => (
    <tr className="border-b border-border">{children}</tr>
  ),
  th: ({ children }: { children?: React.ReactNode }) => (
    <th className="px-3 py-2 text-left font-semibold text-foreground text-xs uppercase tracking-wide">
      {children}
    </th>
  ),
  td: ({ children }: { children?: React.ReactNode }) => (
    <td className="px-3 py-2 text-foreground/85">{children}</td>
  ),
  hr: () => <hr className="border-border my-6" />,
  a: ({ href, children }: { href?: string; children?: React.ReactNode }) => (
    <a
      href={href}
      className="text-primary underline underline-offset-2 hover:text-primary/80 transition-colors"
      target="_blank"
      rel="noopener noreferrer"
    >
      {children}
    </a>
  ),
  strong: ({ children }: { children?: React.ReactNode }) => (
    <strong className="font-semibold text-foreground">{children}</strong>
  ),
  em: ({ children }: { children?: React.ReactNode }) => (
    <em className="italic text-muted-foreground">{children}</em>
  ),
};

// -----------------------------------------------------------------------
// Table of Contents sidebar
// -----------------------------------------------------------------------

function TableOfContents({
  headings,
  activeId,
}: {
  headings: TocEntry[];
  activeId: string | null;
}) {
  if (headings.length === 0) return null;

  return (
    <nav className="sticky top-0 w-52 shrink-0 hidden xl:block">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="size-3.5 text-muted-foreground" />
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Contents
          </span>
        </div>
        <ul className="space-y-1">
          {headings.map(({ id, text }) => (
            <li key={id}>
              <a
                href={`#${id}`}
                className={cn(
                  "block text-xs py-0.5 transition-colors truncate",
                  activeId === id
                    ? "text-primary font-medium"
                    : "text-muted-foreground hover:text-foreground"
                )}
                onClick={(e) => {
                  e.preventDefault();
                  document.getElementById(id)?.scrollIntoView({
                    behavior: "smooth",
                    block: "start",
                  });
                }}
              >
                {text}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}

// -----------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------

export default function ReportPage() {
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const text = await getReportMarkdown();
      setMarkdown(text);
    } catch (e) {
      if (e instanceof NotFoundError) {
        setNotFound(true);
      } else {
        setError(e instanceof Error ? e.message : "Failed to load report");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const headings = useMemo(
    () => (markdown ? extractH2Headings(markdown) : []),
    [markdown]
  );

  // Intersection observer to track active heading
  useEffect(() => {
    if (!contentRef.current || headings.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id);
          }
        }
      },
      { rootMargin: "-20% 0px -70% 0px" }
    );

    headings.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, [headings]);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="w-5 h-5 text-primary" />
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-foreground">
              Report
            </h1>
            <p className="text-sm text-muted-foreground">
              Full engagement report with executive summary and remediation
            </p>
          </div>
        </div>

        {markdown && (
          <Button
            variant="outline"
            size="sm"
            onClick={handlePrint}
            className="gap-1.5 print:hidden"
          >
            <Printer className="size-4" />
            Print
          </Button>
        )}
      </div>

      {/* Body */}
      {loading ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          Loading report...
        </div>
      ) : notFound ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          <FileText className="w-8 h-8 mx-auto mb-2 text-muted-foreground/40" />
          <p>Report not available.</p>
          <p className="text-xs mt-1">
            The report renders after Wraith completes report generation.
          </p>
        </div>
      ) : error ? (
        <div className="rounded-lg border border-destructive/30 bg-card p-6 text-center text-sm text-destructive">
          {error}
        </div>
      ) : markdown ? (
        <div className="flex gap-6 items-start">
          {/* Main content */}
          <div
            ref={contentRef}
            className="flex-1 min-w-0 rounded-lg border border-border bg-card p-6 print-content"
          >
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={proseComponents}
            >
              {markdown}
            </ReactMarkdown>
          </div>

          {/* Sidebar ToC */}
          <TableOfContents headings={headings} activeId={activeId} />
        </div>
      ) : null}

      {/* Print styles */}
      <style>{`
        @media print {
          body > * { display: none !important; }
          .print-content { display: block !important; }
          .print\\:hidden { display: none !important; }
          .print-content {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: white;
            color: black;
            padding: 2rem;
            overflow: auto;
            border: none;
            border-radius: 0;
          }
        }
      `}</style>
    </div>
  );
}
