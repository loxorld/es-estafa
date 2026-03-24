export function uniqueStrings(values: readonly string[]) {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const normalized = value.trim();
    const key = normalized.toLowerCase();

    if (!normalized || seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push(normalized);
  }

  return result;
}

export function matchesAny(patterns: readonly RegExp[], value: string) {
  return patterns.some((pattern) => pattern.test(value));
}

function extractMessageChunks(message: string) {
  return message
    .split(/[\n.!?]+/)
    .map((chunk) => chunk.trim())
    .filter(Boolean);
}

export function getMatchingFragment(message: string, patterns: readonly RegExp[]) {
  return extractMessageChunks(message).find((chunk) => matchesAny(patterns, chunk)) ?? null;
}
