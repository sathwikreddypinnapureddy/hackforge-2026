export function validateRepositoryUrl(value: unknown) {
  // Validate the original spelling, before URL normalization can erase traversal,
  // encoded separators, credentials, ports, queries, or trailing segments.
  if (typeof value !== "string" || value.length > 256) throw new Error("Invalid GitHub URL");
  const match = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)\/([A-Za-z0-9_.-]{1,100})$/.exec(value);
  if (!match) throw new Error("Invalid GitHub URL");
  const owner = match[1];
  const repo = match[2].endsWith(".git") ? match[2].slice(0, -4) : match[2];
  if (!repo || repo === "." || repo === ".." || repo.startsWith("-") || owner.includes("--")
    || /(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16})/.test(`${owner}/${repo}`)) {
    throw new Error("Invalid GitHub URL");
  }
  return { repositoryUrl: `https://github.com/${owner}/${repo}.git`, repositoryOwner: owner, repositoryName: repo };
}

export const PROJECT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function validateProjectId(value: unknown): string {
  if (typeof value !== "string" || !PROJECT_ID.test(value)) throw new Error("Invalid project ID");
  return value;
}
