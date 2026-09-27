import "server-only";
import { constants } from "node:fs";
import { mkdir, lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import type { RemediationSession } from "./workflow-types.ts";

// Each record is a new projection and event. There is no update/delete operation.
export class RemediationJournal {
  private queue: Promise<unknown> = Promise.resolve();
  private directory: string;
  constructor(directory = path.join(process.cwd(), ".hackforge-data", "remediations")) { this.directory = directory; }
  private async prepare() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    if ((await lstat(this.directory)).isSymbolicLink() || await realpath(this.directory) !== this.directory) throw new Error("Unsafe journal");
    return path.join(this.directory, "timeline.jsonl");
  }
  append(session: RemediationSession) {
    const copy = structuredClone(session);
    const result = this.queue.then(async () => {
      const handle = await open(await this.prepare(), constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_NOFOLLOW, 0o600);
      try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.nlink !== 1 || stat.size > 16 * 1024 * 1024) throw new Error("Journal limit");
        await handle.writeFile(JSON.stringify(copy) + "\n"); await handle.sync();
      } finally { await handle.close(); }
    });
    this.queue = result.catch(() => undefined); return result;
  }
  async list(projectId: string): Promise<RemediationSession[]> {
    await this.queue;
    let handle;
    try { handle = await open(await this.prepare(), constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return []; throw error; }
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 17 * 1024 * 1024) throw new Error("Journal limit");
      const latest = new Map<string, RemediationSession>();
      for (const line of (await handle.readFile("utf8")).split("\n").filter(Boolean)) {
        const session = JSON.parse(line) as RemediationSession;
        if (session.projectId === projectId) latest.set(session.id, session);
      }
      return [...latest.values()].map((s) => ({ ...s, timeline: s.timeline.sort((a, b) => a.timestamp.localeCompare(b.timestamp)) }));
    } finally { await handle.close(); }
  }
}
