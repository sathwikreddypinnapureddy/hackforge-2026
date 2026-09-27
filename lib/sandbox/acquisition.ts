import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { randomBytes } from "node:crypto";
import { mkdir, lstat, readdir } from "node:fs/promises";
import path from "node:path";
import { validateRepositoryUrl } from "../projects/url.ts";
import { AnalysisError, LIMITS, SAFE_GIT } from "./policy.ts";
import { runCommand } from "./process.ts";

export interface RepositoryAcquisition { clone(repositoryUrl: string, workspace: string): Promise<string> }

export class TransferBudget {
  private received = 0;
  private readonly limit: number;
  constructor(limit = LIMITS.transferBytes) { this.limit = limit; }
  take(bytes: number) {
    this.received += bytes;
    if (this.received > this.limit) throw new AnalysisError("REPOSITORY_LIMIT");
  }
}

// This is a reverse proxy for two fixed Git read endpoints, not a general proxy.
// Counting response bytes here enforces the transfer limit even for shallow
// clones of huge repositories; monitoring final pack size would be too late.
export async function githubReadProxy(repositoryUrl: string) {
  const repository = validateRepositoryUrl(repositoryUrl);
  const prefix = `/${randomBytes(24).toString("hex")}`;
  const budget = new TransferBudget();
  let failure: AnalysisError | undefined;
  const upstreams = new Set<ReturnType<typeof httpsRequest>>();
  let requests = 0;
  const server = createServer((req, res) => {
    const endpoint = req.url?.slice(prefix.length);
    const valid = req.url?.startsWith(prefix) && (
      (req.method === "GET" && endpoint === "/info/refs?service=git-upload-pack") ||
      (req.method === "POST" && endpoint === "/git-upload-pack"));
    if (!valid || ++requests > 8 || failure) { res.writeHead(403).end(); return; }
    const upstream = httpsRequest(`${repository.repositoryUrl}${endpoint}`, {
      method: req.method, timeout: LIMITS.cloneMs,
      headers: { "User-Agent": "HackForge-static-analysis", "Accept-Encoding": "identity",
        ...(req.method === "POST" ? { "Content-Type": "application/x-git-upload-pack-request" } : {}),
        // A constant protocol header; never forward arbitrary client headers.
        "Git-Protocol": "version=2" },
    }, (response) => {
      if (response.statusCode !== 200) {
        failure = new AnalysisError([301, 302, 307, 308, 401, 403, 404].includes(response.statusCode ?? 0)
          ? "REPOSITORY_UNAVAILABLE" : "NETWORK_UNAVAILABLE");
        response.destroy(); res.writeHead(502).end(); return;
      }
      const expected = req.method === "POST" ? "application/x-git-upload-pack-result" : "application/x-git-upload-pack-advertisement";
      if (response.headers["content-type"]?.split(";")[0] !== expected || response.headers["content-encoding"]) {
        failure = new AnalysisError("UNSUPPORTED_REPOSITORY"); response.destroy(); res.writeHead(502).end(); return;
      }
      res.writeHead(200, { "Content-Type": expected });
      response.on("data", (chunk: Buffer) => {
        try { budget.take(chunk.length); }
        catch { failure = new AnalysisError("REPOSITORY_LIMIT"); response.destroy(); res.destroy(); return; }
        if (!res.write(chunk)) response.pause();
      });
      res.on("drain", () => response.resume());
      response.on("end", () => res.end());
      response.on("error", () => { failure ??= new AnalysisError("NETWORK_UNAVAILABLE"); res.destroy(); });
    });
    upstreams.add(upstream);
    upstream.on("close", () => upstreams.delete(upstream));
    upstream.on("timeout", () => { failure = new AnalysisError("CLONE_TIMEOUT"); upstream.destroy(); });
    upstream.on("error", () => { failure ??= new AnalysisError("NETWORK_UNAVAILABLE"); res.destroy(); });
    let requestBytes = 0;
    req.on("data", (chunk: Buffer) => {
      requestBytes += chunk.length;
      if (requestBytes > 64 * 1024) { failure = new AnalysisError("REPOSITORY_LIMIT"); req.destroy(); upstream.destroy(); }
    });
    req.on("error", () => upstream.destroy());
    res.on("close", () => upstream.destroy());
    req.pipe(upstream);
  });
  server.headersTimeout = 5000;
  server.requestTimeout = LIMITS.cloneMs;
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw new AnalysisError("ANALYSIS_FAILED");
  return {
    url: `http://127.0.0.1:${address.port}${prefix}`,
    failure: () => failure,
    close: async () => {
      for (const upstream of upstreams) upstream.destroy();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export async function validateAcquiredTree(root: string) {
  let bytes = 0; let entries = 0;
  async function visit(directory: string, depth: number): Promise<void> {
    if (depth > 30) throw new AnalysisError("REPOSITORY_LIMIT");
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (++entries > 20_000) throw new AnalysisError("REPOSITORY_LIMIT");
      const filename = path.join(directory, entry.name);
      const stat = await lstat(filename);
      if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1))) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
      if (stat.isDirectory()) await visit(filename, depth + 1);
      else { bytes += stat.size; if (bytes > LIMITS.repositoryBytes) throw new AnalysisError("REPOSITORY_LIMIT"); }
    }
  }
  await visit(root, 0);
}

export class PublicGitHubAcquisition implements RepositoryAcquisition {
  async clone(repositoryUrl: string, workspace: string): Promise<string> {
    validateRepositoryUrl(repositoryUrl);
    const proxy = await githubReadProxy(repositoryUrl);
    const root = path.join(workspace, "repository");
    await mkdir(path.join(workspace, "empty-template"));
    try {
      // No checkout, hooks, templates, credentials, submodules, LFS, or helpers.
      // The host only receives Git objects; source materialization is in Docker.
      await runCommand("git", [...SAFE_GIT, "clone", "--quiet", "--depth=1", "--single-branch", "--no-tags",
        "--no-checkout", "--no-recurse-submodules", `--template=${path.join(workspace, "empty-template")}`,
        "--", proxy.url, root], { cwd: workspace, timeoutMs: LIMITS.cloneMs, timeoutCode: "CLONE_TIMEOUT", failureCode: "REPOSITORY_UNAVAILABLE" });
      if (proxy.failure()) throw proxy.failure();
      await validateAcquiredTree(root);
      return root;
    } catch (error) { throw proxy.failure() ?? error; }
    finally { await proxy.close(); }
  }
}
