import { describe, expect, it } from "vitest";

import { consumeRateLimit, getClientIp, getClientRateLimitKey } from "@/lib/rate-limit";

describe("getClientIp", () => {
  it("normaliza IPv4 mapeada en IPv6 y prioriza headers directos", () => {
    const request = new Request("https://example.com", {
      headers: {
        "cf-connecting-ip": "::ffff:203.0.113.10",
        "x-forwarded-for": "198.51.100.8, 198.51.100.9",
      },
    });

    expect(getClientIp(request)).toBe("203.0.113.10");
  });
});

describe("getClientRateLimitKey", () => {
  it("devuelve una clave hasheada y no la IP en claro", () => {
    const request = new Request("https://example.com", {
      headers: {
        "x-real-ip": "198.51.100.44",
      },
    });

    const key = getClientRateLimitKey(request);

    expect(key).toMatch(/^[a-f0-9]{64}$/);
    expect(key).not.toContain("198.51.100.44");
  });
});

describe("consumeRateLimit", () => {
  it("bloquea cuando el mismo identificador supera el limite", () => {
    const key = `test-${Date.now()}-${Math.random()}`;

    const first = consumeRateLimit(key, { limit: 2, windowMs: 10_000 });
    const second = consumeRateLimit(key, { limit: 2, windowMs: 10_000 });
    const third = consumeRateLimit(key, { limit: 2, windowMs: 10_000 });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(third.ok).toBe(false);
    expect(third.remaining).toBe(0);
  });
});
