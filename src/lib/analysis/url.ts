import {
  clampScore,
  linkAssessmentSchema,
  linkVerdictFromScore,
  type LinkAssessment,
} from "@/lib/analysis/types";
import { brandProfiles } from "@/lib/analysis/patterns";

const directUrlPattern = /\b((?:https?:\/\/|www\.)[^\s<>"'`]+)/gi;
const shortenerDomains = new Set([
  "bit.ly",
  "cutt.ly",
  "is.gd",
  "ow.ly",
  "rb.gy",
  "rebrand.ly",
  "shorturl.at",
  "t.co",
  "tiny.cc",
  "tiny.one",
  "tinyurl.com",
]);
const trustedDomainHints = [
  "google.com",
  "gmail.com",
  "microsoft.com",
  "live.com",
  "outlook.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "paypal.com",
  "github.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "netflix.com",
  "mercadopago.com",
  "mercadopago.com.ar",
  "mercadolibre.com",
  "mercadolibre.com.ar",
  "afip.gob.ar",
  "argentina.gob.ar",
  "correoargentino.com.ar",
];
const riskyTlds = new Set(["zip", "top", "xyz", "click", "quest", "cam", "mom", "work"]);

const suspiciousKeywords = [
  "login",
  "signin",
  "verify",
  "verification",
  "verificacion",
  "update",
  "actualizacion",
  "account",
  "cuenta",
  "wallet",
  "bank",
  "banco",
  "secure",
  "seguridad",
  "gift",
  "premio",
  "invoice",
  "factura",
  "password",
  "token",
  "otp",
  "confirm",
  "recovery",
  "recuperacion",
  "crypto",
];
const dangerousNonWebSchemes = new Set(["data", "file", "javascript", "vbscript"]);

function uniqueStrings(values: string[]) {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const key = value.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      result.push(value);
    }
  }

  return result;
}

function cleanUrlCandidate(value: string) {
  return value.trim().replace(/^[<(]+/, "").replace(/[)>.,!?;:]+$/, "");
}

function detectExplicitScheme(value: string) {
  const match = value.match(/^([a-z][a-z\d+\-.]*):/i);

  if (!match) {
    return null;
  }

  const scheme = match[1].toLowerCase();
  const remainder = value.slice(match[0].length);

  if (remainder.startsWith("//")) {
    return scheme;
  }

  if (scheme === "localhost" || scheme.includes(".")) {
    return null;
  }

  if (/^\d+(?:[/?#]|$)/.test(remainder)) {
    return null;
  }

  return scheme;
}

export function normalizeWebUrlCandidate(rawUrl: string) {
  const cleaned = cleanUrlCandidate(rawUrl);

  if (!cleaned) {
    return {
      cleaned,
      parsed: null as URL | null,
      unsupportedScheme: null as string | null,
    };
  }

  const explicitScheme = detectExplicitScheme(cleaned);

  if (explicitScheme && !["http", "https"].includes(explicitScheme)) {
    return {
      cleaned,
      parsed: null as URL | null,
      unsupportedScheme: explicitScheme,
    };
  }

  const withProtocol = explicitScheme ? cleaned : `https://${cleaned}`;

  try {
    return {
      cleaned,
      parsed: new URL(withProtocol),
      unsupportedScheme: null as string | null,
    };
  } catch {
    return {
      cleaned,
      parsed: null as URL | null,
      unsupportedScheme: null as string | null,
    };
  }
}

function isIpv4(hostname: string) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function isIpv6(hostname: string) {
  return hostname.includes(":");
}

function isTrustedDomain(domain: string) {
  return trustedDomainHints.some((hint) => domain === hint || domain.endsWith(`.${hint}`));
}

function normalizeAsciiToken(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function getBrandLookalikeMatches(domain: string) {
  const normalizedDomain = domain.toLowerCase();
  const squashedDomain = normalizeAsciiToken(domain);

  return uniqueStrings(
    brandProfiles.flatMap((profile) => {
      const matchesOfficialDomain = profile.domainHints.some(
        (hint) => normalizedDomain === hint || normalizedDomain.endsWith(`.${hint}`),
      );

      if (matchesOfficialDomain) {
        return [];
      }

      const candidateTokens = uniqueStrings([
        normalizeAsciiToken(profile.name),
        ...profile.domainHints.map((hint) => normalizeAsciiToken(hint.split(".")[0] ?? "")),
      ]).filter((token) => token.length >= 4);

      return candidateTokens.some((token) => squashedDomain.includes(token)) ? [profile.name] : [];
    }),
  );
}

export function extractUrls(message: string) {
  const matches = message.match(directUrlPattern) ?? [];
  return uniqueStrings(matches.map(cleanUrlCandidate)).slice(0, 6);
}

export function analyzeUrl(rawUrl: string): LinkAssessment | null {
  const { cleaned, parsed, unsupportedScheme } = normalizeWebUrlCandidate(rawUrl);

  if (!cleaned) {
    return null;
  }

  if (unsupportedScheme) {
    const dangerousScheme = dangerousNonWebSchemes.has(unsupportedScheme);

    return linkAssessmentSchema.parse({
      rawUrl,
      normalizedUrl: cleaned,
      domain: `Esquema ${unsupportedScheme}`,
      score: dangerousScheme ? 92 : 26,
      verdict: dangerousScheme ? "sospechoso" : "precaucion",
      flags: [
        dangerousScheme
          ? "Usa un esquema ejecutable o no web, algo impropio para un link seguro."
          : "No es una URL web http/https, asi que no se pudo revisar como un sitio normal.",
      ],
    });
  }

  if (!parsed) {
    return linkAssessmentSchema.parse({
      rawUrl,
      normalizedUrl: cleaned,
      domain: "URL invalida",
      score: 78,
      verdict: "sospechoso",
      flags: ["El link no tiene un formato URL valido o le falta el dominio."],
    });
  }

  const flags: string[] = [];
  let score = 0;
  const hostname = parsed.hostname.toLowerCase();
  const domain = hostname.replace(/^www\./, "") || parsed.protocol.replace(":", "") || "desconocido";
  const trustedDomain = isTrustedDomain(domain);
  const paramCount = [...parsed.searchParams.keys()].length;
  const keywordMatches = suspiciousKeywords.filter((keyword) =>
    `${parsed.hostname}${parsed.pathname}${parsed.search}`.toLowerCase().includes(keyword),
  );
  const brandLookalikes = trustedDomain ? [] : getBrandLookalikeMatches(domain);
  const topLevelDomain = domain.includes(".") ? domain.split(".").at(-1) ?? "" : "";

  if (!["http:", "https:"].includes(parsed.protocol)) {
    score += 60;
    flags.push("Usa un protocolo poco comun para un link compartido por mensaje.");
  }

  if (parsed.protocol === "http:") {
    score += 16;
    flags.push("No usa HTTPS, asi que viaja sin cifrado moderno.");
  }

  if (parsed.username || parsed.password) {
    score += 24;
    flags.push("Incluye usuario o clave dentro de la URL, algo muy atipico.");
  }

  if (shortenerDomains.has(domain)) {
    score += 22;
    flags.push("Usa un acortador, lo que oculta el destino real del enlace.");
  }

  if (hostname.includes("xn--")) {
    score += 34;
    flags.push("El dominio usa punycode, una tecnica asociada a homografos.");
  }

  if (isIpv4(hostname) || isIpv6(hostname)) {
    score += 28;
    flags.push("El dominio es una direccion IP en lugar de un nombre reconocible.");
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    score += 12;
    flags.push("Usa un puerto poco habitual para un sitio normal.");
  }

  if (domain.split(".").length > 3) {
    score += 10;
    flags.push("Tiene muchos subdominios, algo comun en links enganosos.");
  }

  if (domain.length > 38) {
    score += 8;
    flags.push("El dominio es bastante largo y cuesta auditarlo a simple vista.");
  }

  if ((domain.match(/-/g) ?? []).length >= 3) {
    score += 10;
    flags.push("El dominio abusa de guiones, lo que puede buscar parecer legitimo.");
  }

  if (riskyTlds.has(topLevelDomain)) {
    score += 8;
    flags.push("Usa una terminacion de dominio que aparece seguido en links descartables o agresivos.");
  }

  if (cleaned.length > 120) {
    score += 8;
    flags.push("El link es inusualmente largo y dificil de auditar a simple vista.");
  }

  if (paramCount > 6) {
    score += 8;
    flags.push("Tiene demasiados parametros y seguimiento, lo que dificulta ver su destino.");
  }

  if (/%[0-9A-F]{2}/i.test(cleaned)) {
    score += 6;
    flags.push("Contiene caracteres codificados que pueden esconder partes del destino.");
  }

  if (brandLookalikes.length > 0) {
    score += 20;
    flags.push(
      `El dominio menciona ${brandLookalikes.join(", ")}, pero no coincide con un dominio oficial de esa marca.`,
    );

    if ((domain.match(/-/g) ?? []).length > 0 || keywordMatches.length > 0) {
      score += 10;
      flags.push("Combina una marca conocida con palabras extra, algo comun en links de suplantacion.");
    }
  }

  if (keywordMatches.length > 0) {
    if (!trustedDomain) {
      score += Math.min(24, keywordMatches.length * 6);
      flags.push(
        "Incluye palabras asociadas a login, verificacion, pagos o recuperacion de cuenta.",
      );

      if (keywordMatches.length >= 2) {
        score += 8;
        flags.push("Combina varias palabras sensibles en un dominio que no parece oficial.");
      }
    }
  }

  if (flags.length === 0) {
    flags.push("No aparecieron senales fuertes en la estructura del enlace.");
  }

  const finalScore = clampScore(score);

  return linkAssessmentSchema.parse({
    rawUrl,
    normalizedUrl: parsed.toString(),
    domain,
    score: finalScore,
    verdict: linkVerdictFromScore(finalScore),
    flags: flags.slice(0, 8),
  });
}

export function getPrimaryLinkAssessment(explicitLink: string, message: string) {
  const detectedUrls = uniqueStrings([
    ...(explicitLink ? [cleanUrlCandidate(explicitLink)] : []),
    ...extractUrls(message),
  ]).slice(0, 6);

  const assessments = detectedUrls
    .map((candidate) => analyzeUrl(candidate))
    .filter((value): value is LinkAssessment => Boolean(value))
    .sort((left, right) => right.score - left.score);

  return {
    detectedUrls,
    linkAssessment: assessments[0] ?? null,
  };
}
