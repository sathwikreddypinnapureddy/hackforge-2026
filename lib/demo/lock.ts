import "server-only";

// Prevent scans observing a partially applied fix/reset in this Node process.
const state = globalThis as typeof globalThis & { hackforgeDemoQueue?: Promise<unknown> };
export function withDemoLock<T>(operation: () => Promise<T>): Promise<T> {
  const result = (state.hackforgeDemoQueue ?? Promise.resolve()).then(operation);
  state.hackforgeDemoQueue = result.catch(() => undefined);
  return result;
}
