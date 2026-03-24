import crypto from "node:crypto";
import { isIP } from "node:net";

type RateLimitBucket = {
  count: number;
  resetAt: number;
  lastSeenAt: number;
};

type RateLimitResult = {
  ok: boolean;
  limit: number;
  remaining: number;
  retryAfter: number;
};

type RateLimitState = {
  buckets: Map<string, RateLimitBucket>;
  nextCleanupAt: number;
  salt: string;
};

const cleanupIntervalMs = 60 * 1000;
const maxRateLimitBuckets = 5_000;

const globalForRateLimit = globalThis as typeof globalThis & {
  __esEstafaRateLimitState?: RateLimitState;
};

const state =
  globalForRateLimit.__esEstafaRateLimitState ??
  ({
    buckets: new Map<string, RateLimitBucket>(),
    nextCleanupAt: 0,
    salt: crypto.randomBytes(16).toString("hex"),
  } satisfies RateLimitState);

if (!globalForRateLimit.__esEstafaRateLimitState) {
  globalForRateLimit.__esEstafaRateLimitState = state;
}

function normalizeIpCandidate(value: string | null) {
  if (!value) {
    return null;
  }

  let candidate = value.trim();

  if (!candidate) {
    return null;
  }

  if (candidate.startsWith("[")) {
    const closingBracket = candidate.indexOf("]");
    candidate = closingBracket > 0 ? candidate.slice(1, closingBracket) : candidate;
  } else if (candidate.includes(".") && candidate.includes(":") && candidate.split(":").length === 2) {
    candidate = candidate.slice(0, candidate.lastIndexOf(":"));
  }

  if (candidate.toLowerCase().startsWith("::ffff:")) {
    candidate = candidate.slice(7);
  }

  return isIP(candidate) > 0 ? candidate.toLowerCase() : null;
}

function hashIdentifier(identifier: string) {
  return crypto.createHash("sha256").update(`${state.salt}:${identifier}`).digest("hex");
}

function pruneBuckets(now: number) {
  if (state.nextCleanupAt > now && state.buckets.size <= maxRateLimitBuckets) {
    return;
  }

  if (state.nextCleanupAt <= now) {
    for (const [bucketKey, bucket] of state.buckets.entries()) {
      if (bucket.resetAt <= now) {
        state.buckets.delete(bucketKey);
      }
    }

    state.nextCleanupAt = now + cleanupIntervalMs;
  }

  if (state.buckets.size <= maxRateLimitBuckets) {
    return;
  }

  const overflow = state.buckets.size - maxRateLimitBuckets;
  const staleKeys = [...state.buckets.entries()]
    .sort((left, right) => left[1].lastSeenAt - right[1].lastSeenAt)
    .slice(0, overflow)
    .map(([bucketKey]) => bucketKey);

  for (const bucketKey of staleKeys) {
    state.buckets.delete(bucketKey);
  }
}

export function getClientIp(request: Request) {
  const directHeaders = ["cf-connecting-ip", "x-real-ip"];

  for (const headerName of directHeaders) {
    const normalizedIp = normalizeIpCandidate(request.headers.get(headerName));

    if (normalizedIp) {
      return normalizedIp;
    }
  }

  const forwardedFor = request.headers.get("x-forwarded-for");

  if (forwardedFor) {
    for (const part of forwardedFor.split(",")) {
      const normalizedIp = normalizeIpCandidate(part);

      if (normalizedIp) {
        return normalizedIp;
      }
    }
  }

  return "anonymous";
}

export function getClientRateLimitKey(request: Request) {
  return hashIdentifier(getClientIp(request));
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

  pruneBuckets(now);

  const currentBucket = state.buckets.get(key);

  if (!currentBucket || currentBucket.resetAt <= now) {
    const nextBucket = {
      count: 1,
      resetAt: now + windowMs,
      lastSeenAt: now,
    };

    state.buckets.set(key, nextBucket);

    return {
      ok: true,
      limit,
      remaining: limit - 1,
      retryAfter: Math.ceil(windowMs / 1000),
    };
  }

  currentBucket.count += 1;
  currentBucket.lastSeenAt = now;
  state.buckets.set(key, currentBucket);

  return {
    ok: currentBucket.count <= limit,
    limit,
    remaining: Math.max(0, limit - currentBucket.count),
    retryAfter: Math.max(1, Math.ceil((currentBucket.resetAt - now) / 1000)),
  };
}
