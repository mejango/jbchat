export interface JsonRpcTransport {
  readonly providerId: string;
  /** Returns the JSON-RPC `result` value, or throws on any failure. */
  readonly request: (method: string, params: readonly unknown[]) => Promise<unknown>;
}

const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const REQUEST_TIMEOUT_MILLISECONDS = 10_000;

/**
 * Minimal strict JSON-RPC 2.0 HTTP transport. Any HTTP error, RPC error
 * object, id mismatch, timeout, or oversized body throws; callers treat a
 * throw as that provider being unavailable. No retries here - quorum
 * logic decides what a missing answer means.
 */
export function createHttpJsonRpcTransport(context: {
  readonly providerId: string;
  readonly url: string;
  readonly fetchImplementation?: typeof fetch;
}): JsonRpcTransport {
  const fetchImplementation = context.fetchImplementation ?? fetch;
  let nextId = 0;
  return Object.freeze({
    providerId: context.providerId,
    async request(method: string, params: readonly unknown[]): Promise<unknown> {
      nextId += 1;
      const id = nextId;
      const response = await fetchImplementation(context.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MILLISECONDS),
      });
      if (!response.ok) {
        throw new Error(`JSON-RPC HTTP status ${response.status}.`);
      }
      const text = await response.text();
      if (text.length > MAX_RESPONSE_BYTES) {
        throw new Error("JSON-RPC response exceeds the size ceiling.");
      }
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (parsed.id !== id || parsed.jsonrpc !== "2.0") {
        throw new Error("JSON-RPC response identity mismatch.");
      }
      if ("error" in parsed) {
        throw new Error("JSON-RPC provider returned an error.");
      }
      if (!("result" in parsed)) {
        throw new Error("JSON-RPC response carries no result.");
      }
      return parsed.result;
    },
  });
}
