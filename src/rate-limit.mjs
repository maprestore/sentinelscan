export class RateLimiter {
  constructor({ windowMs = 60_000, max = 30, maxKeys = 2_000 } = {}) {
    this.windowMs = windowMs;
    this.max = max;
    this.maxKeys = maxKeys;
    this.entries = new Map();
  }

  check(key, now = Date.now()) {
    const normalized = String(key || "anonymous").slice(0, 200);
    const previous = this.entries.get(normalized);
    if (!previous || now - previous.startedAt >= this.windowMs) {
      this.entries.set(normalized, { startedAt: now, count: 1 });
      this.prune(now);
      return { allowed: true, retryAfterMs: 0 };
    }
    previous.count += 1;
    this.prune(now);
    if (previous.count <= this.max) return { allowed: true, retryAfterMs: 0 };
    return { allowed: false, retryAfterMs: Math.max(1, this.windowMs - (now - previous.startedAt)) };
  }

  prune(now = Date.now()) {
    for (const [key, entry] of this.entries) if (now - entry.startedAt >= this.windowMs) this.entries.delete(key);
    while (this.entries.size > this.maxKeys) this.entries.delete(this.entries.keys().next().value);
  }
}
