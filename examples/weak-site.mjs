#!/usr/bin/env node
/**
 * A deliberately weak, LOCAL-ONLY demo site for trying SentinelScan safely.
 *
 * - Binds to 127.0.0.1 only. It is never reachable from your network.
 * - Serves static strings. It has no real login, no database, and stores nothing.
 * - Every weakness below exists so the scanner has something to report:
 *   plain HTTP, missing security headers, loose cookies, a GET password form,
 *   an external script without SRI, exposed Git metadata, and a robots.txt that
 *   points at sensitive-looking paths.
 *
 * Usage:
 *   node examples/weak-site.mjs                 # http://127.0.0.1:4599
 *   PORT=4700 node examples/weak-site.mjs
 */
import http from "node:http";
import { pathToFileURL } from "node:url";

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Demo Shop</title></head><body>
  <h1>Demo Shop</h1>
  <form action="/login" method="get">
    <input type="text" name="user"><input type="password" name="password">
  </form>
  <script src="https://cdn.example.test/analytics.js"></script>
  <script src="/app.js"></script>
  <a href="/status">Status</a>
  <a href="https://partner.example.test" target="_blank">Partner</a>
</body></html>`;

export function createWeakSite() {
  return http.createServer((request, response) => {
    const path = (request.url || "/").split("?")[0];
    if (path === "/.git/HEAD") {
      response.writeHead(200, { "content-type": "text/plain" });
      return response.end("ref: refs/heads/main\n");
    }
    if (path === "/robots.txt") {
      response.writeHead(200, { "content-type": "text/plain" });
      return response.end("User-agent: *\nDisallow: /admin\nDisallow: /backup\n");
    }
    if (path === "/app.js") {
      response.writeHead(200, { "content-type": "application/javascript" });
      return response.end('fetch("/api/v1/orders");\nfetch("/api/v1/users/me");\n');
    }
    if (path === "/status") {
      response.writeHead(200, { "content-type": "text/html" });
      return response.end("<html><body><a href='/'>Home</a></body></html>");
    }
    if (path === "/" || path === "/login") {
      response.writeHead(200, {
        "content-type": "text/html",
        server: "demo-shop/2.4",
        "set-cookie": ["session=abc123", "prefs=dark; Path=/"],
      });
      return response.end(PAGE);
    }
    response.writeHead(404);
    return response.end();
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 4599);
  createWeakSite().listen(port, "127.0.0.1", () => {
    process.stdout.write(`Weak demo site (local only): http://127.0.0.1:${port}\n`);
    process.stdout.write("Scan it with:\n");
    process.stdout.write(`  node src/cli.mjs --target http://127.0.0.1:${port}/ --scope examples/weak-site.scope.json --confirm-authorized --delay-ms 0\n`);
  });
}
