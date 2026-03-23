// v3.7.0: Pipeline event bus for Console (v4.0.0)
// Components emit events; Console subscribes via SSE in v4.0.0
// In v3.7.0, events go nowhere (no subscribers) -- establishes the contract

import type { SSEEvent, SSEEventType } from './types.js';

type EventHandler = (event: SSEEvent) => void;

export class WraithEventBus {
  private handlers = new Map<string, EventHandler[]>();

  emit(type: SSEEventType, data: unknown): void {
    const event: SSEEvent = {
      type,
      timestamp: new Date().toISOString(),
      data,
    };

    // Emit to specific type handlers
    const typeHandlers = this.handlers.get(type);
    if (typeHandlers) {
      for (const handler of typeHandlers) {
        try { handler(event); } catch { /* non-critical */ }
      }
    }

    // Emit to wildcard handlers
    const wildcardHandlers = this.handlers.get('*');
    if (wildcardHandlers) {
      for (const handler of wildcardHandlers) {
        try { handler(event); } catch { /* non-critical */ }
      }
    }
  }

  on(type: SSEEventType | '*', handler: EventHandler): void {
    const existing = this.handlers.get(type) ?? [];
    existing.push(handler);
    this.handlers.set(type, existing);
  }

  off(type: SSEEventType | '*', handler: EventHandler): void {
    const existing = this.handlers.get(type);
    if (!existing) return;
    const index = existing.indexOf(handler);
    if (index !== -1) existing.splice(index, 1);
  }

  removeAll(): void {
    this.handlers.clear();
  }
}

// Singleton instance
export const eventBus = new WraithEventBus();
