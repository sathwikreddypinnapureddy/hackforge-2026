import assert from "node:assert/strict";
import { test } from "node:test";
import { sameOrigin } from "../lib/http.ts";
import { sameOrigin as projectSameOrigin } from "../lib/projects/http.ts";
import { sessionCookie } from "../lib/remediation/scan-store.ts";
import { POST as projects } from "../app/api/projects/route.ts";
import { POST as explain } from "../app/api/explain/route.ts";
import { POST as fix } from "../app/api/fix-demo/route.ts";
import { GET as report } from "../app/api/projects/[id]/report/route.ts";

function request(headers: Record<string, string> = {}, url = "http://127.0.0.1:3000/api/projects") {
  return new Request(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: "{}" });
}
const publicHeaders = { origin: "https://hackforge.us", host: "hackforge.us", "sec-fetch-site": "same-origin" };

test("same-origin validation accepts public proxy hosts and localhost, with URL host fallback", () => {
  assert.equal(sameOrigin(request(publicHeaders)), true);
  assert.equal(sameOrigin(request({ ...publicHeaders, host: "127.0.0.1:3000", "x-forwarded-host": "hackforge.us" })), true);
  assert.equal(sameOrigin(request({ origin: "http://localhost:3000", host: "localhost:3000" })), true);
  assert.equal(sameOrigin(request({ origin: "https://127.0.0.1:3000" })), true);
  assert.equal(sameOrigin(request({ origin: "http://LOCALHOST:3000", host: "localhost:3000" })), true);
  assert.equal(sameOrigin(request({ origin: "http://[::1]:3000", host: "[::1]:3000" })), true);
  assert.equal(sameOrigin(request({ origin: "https://hackforge.us:8443", host: "hackforge.us:8443" })), true);
  assert.equal(sameOrigin(request({ ...publicHeaders, host: "hackforge.us:8443" })), false);
  assert.equal(sameOrigin(request()), true);
});

test("same-origin validation rejects attacks, cross-site fetches and malformed origins", () => {
  assert.equal(sameOrigin(request({ ...publicHeaders, origin: "https://evil.example" })), false);
  assert.equal(sameOrigin(request({ ...publicHeaders, "sec-fetch-site": "cross-site" })), false);
  assert.equal(sameOrigin(request({ "sec-fetch-site": "cross-site" })), false);
  for (const origin of ["", "null", "malformed", "https://", "ftp://hackforge.us", "https://hackforge.us/",
    "https://hackforge.us/path", "https://hackforge.us?x", "https://hackforge.us#x", "https://user@hackforge.us",
    "https://evil.example@hackforge.us", "https://hackforge.us https://evil.example", "https://hackforge.us,https://evil.example",
    "https://hackforge.us:99999", "https://hackforge.us\\evil", "https://hackforge%2eus", "https://*.hackforge.us"]) {
    assert.equal(sameOrigin(request({ ...publicHeaders, origin })), false, origin);
  }
  assert.equal(sameOrigin(request({ ...publicHeaders, origin: "https://hackforge.us.evil.example" })), false);
});

test("forwarded host uses the trimmed first value and rejects malformed supplied authorities", () => {
  assert.equal(sameOrigin(request({ ...publicHeaders, "x-forwarded-host": " hackforge.us , evil.example " })), true);
  assert.equal(sameOrigin(request({ ...publicHeaders, "x-forwarded-host": "evil.example, hackforge.us" })), false);
  assert.equal(sameOrigin(request({ ...publicHeaders, host: "hackforge.us,evil.example" })), false);
  for (const host of ["", "https://hackforge.us", "user@hackforge.us", "hackforge.us/path", "hackforge.us?x",
    "hackforge.us#x", "hackforge.us\\evil", "hackforge%2eus", "hackforge.us:99999", "hackforge.us:",
    "hackforge..us", "-hackforge.us", "*.hackforge.us"]) {
    assert.equal(sameOrigin(request({ ...publicHeaders, host })), false, host);
    assert.equal(sameOrigin(request({ ...publicHeaders, "x-forwarded-host": host })), false, host);
  }
});

test("route guards accept proxy origins while retaining query, JSON and bounded input checks", async () => {
  for (const route of [projects, explain, fix]) {
    // Invalid input reaches validation, without creating projects or invoking mutations/Gemini.
    assert.equal((await route(request(publicHeaders))).status, 400);
    assert.equal((await route(request({ ...publicHeaders, "x-forwarded-host": " hackforge.us , internal.example " }))).status, 400);
    assert.equal((await route(request({ ...publicHeaders, origin: "https://evil.example" }))).status, 403);
    assert.equal((await route(request({ ...publicHeaders, "sec-fetch-site": "cross-site" }))).status, 403);
    assert.equal((await route(request({ ...publicHeaders, origin: "null" }))).status, 403);
    assert.equal((await route(request({ ...publicHeaders, "content-type": "text/plain" }))).status, route === explain ? 400 : 403);
    assert.equal((await route(new Request("http://127.0.0.1:3000/api/projects", {
      method: "POST", headers: { ...publicHeaders, "content-type": "application/json" }, body: JSON.stringify({ padding: "x".repeat(2000) }),
    }))).status, 400);
  }
  assert.equal(projectSameOrigin(request(publicHeaders, "http://127.0.0.1:3000/api/projects?x=1")), false);
  for (const route of [projects, fix]) {
    assert.equal((await route(request(publicHeaders, "http://127.0.0.1:3000/api/projects?x=1"))).status, 403);
  }
  const context = { params: Promise.resolve({ id: "invalid" }) };
  assert.equal((await report(new Request("http://127.0.0.1:3000/api/projects/invalid/report?format=json", { headers: publicHeaders }), context)).status, 404);
  assert.equal((await report(new Request("http://127.0.0.1:3000/api/projects/invalid/report?extra=1", { headers: publicHeaders }), context)).status, 403);
  assert.equal((await report(new Request("http://127.0.0.1:3000/api/projects/invalid/report", { headers: { ...publicHeaders, origin: "https://evil.example" } }), context)).status, 403);
});

test("scan session Secure follows the first public protocol and retains cookie attributes", () => {
  const token = "a926133d-25a9-4625-81c8-af9160b4c574";
  const base = `hackforge-scan-session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=900`;
  for (const proto of ["https", " https , http ", "HTTPS"]) {
    assert.equal(sessionCookie(token, request({ "x-forwarded-proto": proto })), `${base}; Secure`);
  }
  for (const proto of ["http", "http, https", "", "https://", "invalid"]) {
    assert.equal(sessionCookie(token, request({ "x-forwarded-proto": proto })), base);
  }
  assert.equal(sessionCookie(token, request()), base);
  assert.equal(sessionCookie(token, request({}, "https://hackforge.us/api/scan")), `${base}; Secure`);
  assert.equal(sessionCookie(token, request({ "x-forwarded-proto": "http" }, "https://hackforge.us/api/scan")), base);
});
