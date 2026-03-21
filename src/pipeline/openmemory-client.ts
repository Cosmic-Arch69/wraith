// HTTP client for OpenMemory MCP server
// Stores attack facts and queries semantic memory for the planner
// v3.1.0: Wraith agents store findings, planner queries for cross-run intelligence

// Kali (10.0.0.223) reaches Lenovo (10.0.0.21) directly on management subnet
const DEFAULT_URL = 'http://10.0.0.21:8080/mcp';

interface FactTriple {
  subject: string;
  predicate: string;
  object: string;
  confidence?: number;
}

export class OpenMemoryClient {
  private url: string;

  constructor(url?: string) {
    this.url = url ?? process.env.OPENMEMORY_URL ?? DEFAULT_URL;
  }

  async store(
    content: string,
    tags: string[],
    facts?: FactTriple[],
  ): Promise<void> {
    try {
      await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'tools/call',
          id: Date.now(),
          params: {
            name: 'openmemory_store',
            arguments: {
              content,
              type: facts && facts.length > 0 ? 'both' : 'contextual',
              user_id: 'wraith',
              tags,
              ...(facts && facts.length > 0 ? { facts } : {}),
            },
          },
        }),
      });
    } catch (err) {
      console.warn(`[openmemory] Store failed: ${err}`);
    }
  }

  async query(question: string): Promise<string> {
    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'tools/call',
          id: Date.now(),
          params: {
            name: 'openmemory_query',
            arguments: {
              query: question,
              type: 'unified',
              user_id: 'wraith',
              k: 5,
            },
          },
        }),
      });

      const data = await response.json() as { result?: { content?: Array<{ text?: string }> } };
      return data.result?.content?.[0]?.text ?? 'No results from OpenMemory.';
    } catch (err) {
      console.warn(`[openmemory] Query failed: ${err}`);
      return 'OpenMemory unavailable.';
    }
  }
}
