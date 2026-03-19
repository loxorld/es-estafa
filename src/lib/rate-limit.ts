type RateLimitBucket = {
  count: number;
  resetAt: number;
};

type RateLimitResult = {
  ok: boolean;
  limit: number;
  remaining: number;
  retryAfter: number;
};

const globalForRateLimit = globalThis as typeof globalThis & {
  __esEstafaRateLimit?: Map<string, RateLimitBucket>;
};

const buckets = globalForRateLimit.__esEstafaRateLimit ?? new Map<string, RateLimitBucket>();

if (!globalForRateLimit.__esEstafaRateLimit) {
  globalForRateLimit.__esEstafaRateLimit = buckets;
}

export function getClientIp(request: Request) {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0]?.trim() || "anonymous";
  }

  return request.headers.get("x-real-ip")?.trim() || "anonymous";
}

export function consumeRateLimit(
  key: string,
  options: {
    limit?: number;
    windowMs?: number;
  } = {},
): RateLimitResult {
  const limit = options.limit ?? 8;
  const windowMs = options.windowMs ?? 10 * 60 * 1000;
  const now = Date.now();

  for (const [bucketKey, bucket] of buckets.entries()) {
    if (bucket.resetAt <= now) {
      buckets.delete(bucketKey);
    }
  }

  const currentBucket = buckets.get(key);

  if (!currentBucket || currentBucket.resetAt <= now) {
    const nextBucket = {
      count: 1,
      resetAt: now + windowMs,
    };

    buckets.set(key, nextBucket);

    return {
      ok: true,
      limit,
      remaining: limit - 1,
      retryAfter: Math.ceil(windowMs / 1000),
    };
  }

  currentBucket.count += 1;
  buckets.set(key, currentBucket);

  return {
    ok: currentBucket.count <= limit,
    limit,
    remaining: Math.max(0, limit - currentBucket.count),
    retryAfter: Math.max(1, Math.ceil((currentBucket.resetAt - now) / 1000)),
  };
}
