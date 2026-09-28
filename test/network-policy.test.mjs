import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { fetchWithNetworkPolicy, isPrivateAddress, resolveAllowedAddresses, NetworkPolicyError } from "../src/network-policy.mjs";

function startServer(handler, host = "127.0.0.1") {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => resolve(server));
  });
}

test("private addresses and reserved ranges are blocked by default", () => {
  for (const address of [
    "0.0.0.0", "10.1.2.3", "100.64.1.2", "127.0.0.1", "169.254.10.20", "172.20.1.1",
    "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.4", "203.0.113.4", "224.0.0.1",
    "::", "::1", "::ffff:7f00:1", "::ffff:192.168.1.1", "fc00::1", "fe80::1", "2001:db8::1",
  ]) assert.equal(isPrivateAddress(address), true, address);
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  assert.equal(isPrivateAddress("::ffff:8.8.8.8"), false);
  assert.equal(isPrivateAddress("2001:4860:4860::8888"), false);
});

test("private hostnames require explicit opt-in", async () => {
  await assert.rejects(
    () => resolveAllowedAddresses("localhost"),
    (error) => error instanceof NetworkPolicyError && error.code === "NETWORK_POLICY_BLOCKED",
  );
  const addresses = await resolveAllowedAddresses("127.0.0.1", { allowPrivateNetwork: true });
  assert.equal(addresses[0].address, "127.0.0.1");
});

test("bodyless responses and duplicate cookies are represented safely", async (t) => {
  const server = await startServer((request, response) => {
    if (request.url === "/empty") return response.writeHead(204, { "set-cookie": ["first=1; Secure", "second=2; Secure"] }).end();
    if (request.url === "/reset") return response.writeHead(205).end();
    if (request.url === "/not-modified") return response.writeHead(304).end();
    response.writeHead(200, { "content-type": "text/plain" });
    return response.end("ok");
  });
  t.after(() => server.close());
  const { port } = server.address();
  const response = await fetchWithNetworkPolicy(`http://127.0.0.1:${port}/empty`, { allowPrivateNetwork: true });
  assert.equal(response.status, 204);
  assert.equal(await response.text(), "");
  const cookies = response.headers.getSetCookie?.() || [];
  if (cookies.length) assert.equal(cookies.length, 2);
  else assert.match(response.headers.get("set-cookie") || "", /first=1/);
  for (const [path, status] of [["/reset", 205], ["/not-modified", 304]]) {
    const bodyless = await fetchWithNetworkPolicy(`http://127.0.0.1:${port}${path}`, { allowPrivateNetwork: true });
    assert.equal(bodyless.status, status);
    assert.equal(await bodyless.text(), "");
  }
});

test("IPv6 literal requests use an unbracketed transport host when available", async (t) => {
  let server;
  try {
    server = await startServer((request, response) => response.end("ipv6"), "::1");
  } catch (error) {
    t.skip(`IPv6 loopback unavailable: ${error.message}`);
    return;
  }
  t.after(() => server.close());
  const { port } = server.address();
  const response = await fetchWithNetworkPolicy(`http://[::1]:${port}/`, { allowPrivateNetwork: true });
  assert.equal(await response.text(), "ipv6");
});

test("DNS resolution honors an already-aborted signal", async () => {
  const controller = new AbortController();
  controller.abort(new DOMException("Canceled", "AbortError"));
  await assert.rejects(
    () => resolveAllowedAddresses("example.com", { signal: controller.signal, timeoutMs: 100 }),
    (error) => error.name === "AbortError",
  );
});
