import "server-only";

import dns from "node:dns/promises";
import { BlockList, isIP } from "node:net";

import { linkPreviewSchema, type LinkPreview } from "@/lib/analysis/types";
import { normalizeWebUrlCandidate } from "@/lib/analysis/url";

const requestHeaders = {
  "user-agent": "es-estafa-bot/1.0 (+link-preview)",
  accept: "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
};
const maxPreviewContentLengthBytes = 1_500_000;
const dangerousNonWebSchemes = new Set(["data", "file", "javascript", "vbscript"]);
const loginKeywords = ["login", "signin", "sign-in", "acceso", "ingresa", "cuenta", "account"];
const verificationKeywords = [
  "verify",
  "verification",
  "security",
  "secure",
  "update",
  "password",
  "token",
  "otp",
  "pin",
];
const paymentKeywords = ["invoice", "factura", "payment", "pago", "wallet", "crypto", "transfer"];
const rewardKeywords = ["gift", "premio", "sorteo", "winner", "claim"];

function createBlockedIpLists() {
  const blockedIpv4 = new BlockList();
  blockedIpv4.addSubnet("0.0.0.0", 8, "ipv4");
  blockedIpv4.addSubnet("10.0.0.0", 8, "ipv4");
  blockedIpv4.addSubnet("100.64.0.0", 10, "ipv4");
  blockedIpv4.addSubnet("127.0.0.0", 8, "ipv4");
  blockedIpv4.addSubnet("169.254.0.0", 16, "ipv4");
  blockedIpv4.addSubnet("172.16.0.0", 12, "ipv4");
  blockedIpv4.addSubnet("192.0.2.0", 24, "ipv4");
  blockedIpv4.addSubnet("192.168.0.0", 16, "ipv4");
  blockedIpv4.addSubnet("198.18.0.0", 15, "ipv4");
  blockedIpv4.addSubnet("198.51.100.0", 24, "ipv4");
  blockedIpv4.addSubnet("203.0.113.0", 24, "ipv4");
  blockedIpv4.addSubnet("224.0.0.0", 4, "ipv4");
  blockedIpv4.addSubnet("240.0.0.0", 4, "ipv4");

  const blockedIpv6 = new BlockList();
  blockedIpv6.addSubnet("::", 128, "ipv6");
  blockedIpv6.addSubnet("::1", 128, "ipv6");
  blockedIpv6.addSubnet("fc00::", 7, "ipv6");
  blockedIpv6.addSubnet("fe80::", 10, "ipv6");
  blockedIpv6.addSubnet("fec0::", 10, "ipv6");
  blockedIpv6.addSubnet("ff00::", 8, "ipv6");
  blockedIpv6.addSubnet("2001:db8::", 32, "ipv6");

  return {
    blockedIpv4,
    blockedIpv6,
  };
}

const { blockedIpv4, blockedIpv6 } = createBlockedIpLists();

function limitText(value: string | null | undefined, maxLength: number) {
  if (!value) {
    return null;
  }

  return value.replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function normalizeIpLiteral(value: string) {
  return value.replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
}

function decodeIpv4MappedIpv6(ip: string) {
  const normalized = normalizeIpLiteral(ip);
  const dottedMatch = normalized.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);

  if (dottedMatch) {
    return dottedMatch[1];
  }

  const hexMatch = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);

  if (!hexMatch) {
    return null;
  }

  const left = Number.parseInt(hexMatch[1], 16);
  const right = Number.parseInt(hexMatch[2], 16);

  return `${left >> 8}.${left & 255}.${right >> 8}.${right & 255}`;
}

function isPrivateOrReservedIp(ip: string) {
  const normalized = normalizeIpLiteral(ip);
  const mappedIpv4 = decodeIpv4MappedIpv6(normalized);

  if (mappedIpv4) {
    return blockedIpv4.check(mappedIpv4, "ipv4");
  }

  const family = isIP(normalized);

  if (family === 4) {
    return blockedIpv4.check(normalized, "ipv4");
  }

  if (family === 6) {
    return blockedIpv6.check(normalized, "ipv6");
  }

  return false;
}

async function assertSafeHost(url: URL) {
  const hostname = normalizeIpLiteral(url.hostname);

  if (
    hostname === "localhost" ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".lan")
  ) {
    throw new Error("El link apunta a una red privada o local.");
  }

  if (url.username || url.password) {
    throw new Error("El link incluye credenciales embebidas y se bloqueo la vista previa.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Solo se admite vista previa para URLs http o https.");
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    throw new Error("El link usa un puerto no estandar y se bloqueo la vista previa.");
  }

  let addresses: Array<{ address: string }>;

  try {
    addresses =
      isIP(hostname) > 0
        ? [{ address: hostname }]
        : await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    if (error instanceof Error && /ENOTFOUND/i.test(error.message)) {
      throw new Error("El dominio no existe o no se pudo resolver en DNS.");
    }

    throw error;
  }

  if (addresses.length === 0) {
    throw new Error("No se pudo resolver el dominio.");
  }

  for (const entry of addresses) {
    if (isPrivateOrReservedIp(entry.address)) {
      throw new Error("El dominio resuelve a una IP privada o reservada.");
    }
  }
}

function buildPreviewResult({
  status,
  requestedUrl,
  finalUrl,
  httpStatus,
  contentType,
  title,
  description,
  pageSignals,
  notes,
}: {
  status: LinkPreview["status"];
  requestedUrl: string;
  finalUrl: string | null;
  httpStatus: number | null;
  contentType: string | null;
  title: string | null;
  description: string | null;
  pageSignals: string[];
  notes: string[];
}) {
  return linkPreviewSchema.parse({
    status,
    requestedUrl,
    finalUrl,
    httpStatus,
    contentType,
    title,
    description,
    pageSignals,
    notes: notes.map((note) => note.slice(0, 180)).slice(0, 6),
  });
}

function isTextLikeContentType(contentType: string | null) {
  return Boolean(contentType && /(text\/html|application\/xhtml\+xml|text\/plain)/i.test(contentType));
}

async function requestHeadWithRedirects(startUrl: URL) {
  let currentUrl = startUrl;
  const redirectNotes: string[] = [];

  for (let redirectCount = 0; redirectCount < 4; redirectCount += 1) {
    const response = await fetch(currentUrl, {
      method: "HEAD",
      headers: requestHeaders,
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });

    const isRedirect = response.status >= 300 && response.status < 400;
    const location = response.headers.get("location");

    if (isRedirect && location) {
      const nextUrl = new URL(location, currentUrl);
      await assertSafeHost(nextUrl);
      redirectNotes.push(`Redireccion ${redirectCount + 1}: ${currentUrl.toString()} -> ${nextUrl.toString()}`);
      currentUrl = nextUrl;
      continue;
    }

    return {
      response,
      finalUrl: currentUrl,
      notes: redirectNotes,
    };
  }

  throw new Error("El link tuvo demasiadas redirecciones y se corto la vista previa.");
}

function hasKeyword(source: string, keywords: readonly string[]) {
  return keywords.some((keyword) => source.includes(keyword));
}

function buildPageSignals(finalUrl: URL, contentType: string | null) {
  const source = `${finalUrl.hostname}${finalUrl.pathname}${finalUrl.search}`.toLowerCase();
  const signals: string[] = [];

  if (hasKeyword(source, loginKeywords)) {
    signals.push("La URL final menciona login, acceso o cuenta.");
  }

  if (hasKeyword(source, verificationKeywords)) {
    signals.push("La URL final menciona verificacion, seguridad o actualizacion de credenciales.");
  }

  if (hasKeyword(source, paymentKeywords)) {
    signals.push("La URL final menciona pagos, facturas o dinero.");
  }

  if (hasKeyword(source, rewardKeywords)) {
    signals.push("La URL final menciona premios, sorteos o beneficios.");
  }

  if (contentType && /application\/pdf|application\/zip|application\/octet-stream/i.test(contentType)) {
    signals.push("El destino entrega un archivo en vez de una pagina HTML comun.");
  }

  return signals.map((signal) => signal.slice(0, 160)).slice(0, 8);
}

export async function previewLink(rawUrl: string): Promise<LinkPreview> {
  const { cleaned, parsed, unsupportedScheme } = normalizeWebUrlCandidate(rawUrl);

  if (unsupportedScheme) {
    return buildPreviewResult({
      status: "blocked",
      requestedUrl: cleaned,
      finalUrl: null,
      httpStatus: null,
      contentType: null,
      title: null,
      description: null,
      pageSignals: [],
      notes: [
        dangerousNonWebSchemes.has(unsupportedScheme)
          ? "La vista previa se bloqueo porque el link usa un esquema ejecutable o no web."
          : "Solo se admite vista previa para URLs web http o https.",
      ],
    });
  }

  const url = parsed;

  if (!url) {
    return buildPreviewResult({
      status: "failed",
      requestedUrl: cleaned || rawUrl,
      finalUrl: null,
      httpStatus: null,
      contentType: null,
      title: null,
      description: null,
      pageSignals: [],
      notes: ["La URL no se pudo normalizar para obtener una vista previa."],
    });
  }

  try {
    await assertSafeHost(url);
  } catch (error) {
    return buildPreviewResult({
      status: "blocked",
      requestedUrl: url.toString(),
      finalUrl: null,
      httpStatus: null,
      contentType: null,
      title: null,
      description: null,
      pageSignals: [],
      notes: [
        error instanceof Error
          ? error.message.slice(0, 180)
          : "La vista previa del link fue bloqueada.",
      ],
    });
  }

  try {
    const metadataResult = await requestHeadWithRedirects(url);
    const contentType = metadataResult.response.headers.get("content-type");
    const contentLength = Number(metadataResult.response.headers.get("content-length") ?? "0");
    const notes = [...metadataResult.notes];
    const pageSignals = buildPageSignals(metadataResult.finalUrl, contentType);

    notes.push("Por seguridad, solo se inspeccionaron redirecciones, URL final y headers del destino.");

    if (!metadataResult.response.ok) {
      notes.push(`La pagina respondio con estado HTTP ${metadataResult.response.status}.`);
    }

    if (!contentType) {
      notes.push("El servidor no expuso un content-type claro para identificar el destino.");
    } else if (!isTextLikeContentType(contentType)) {
      notes.push(`El contenido parece ser ${contentType} y no una pagina HTML comun.`);
    }

    if (Number.isFinite(contentLength) && contentLength > maxPreviewContentLengthBytes) {
      notes.push("El recurso declarado es grande, asi que no se intento descargar contenido.");
    }

    if (metadataResult.finalUrl.toString() !== url.toString()) {
      notes.push("El destino final no coincide con el link original compartido.");
    }

    if (metadataResult.response.status === 405 || metadataResult.response.status === 501) {
      notes.push("El servidor no permite inspeccion segura por HEAD sin descargar la pagina completa.");
    }

    if (metadataResult.response.status === 403) {
      notes.push("El servidor bloqueo la inspeccion segura del destino antes de exponer metadata util.");
    }

    return buildPreviewResult({
      status: "fetched",
      requestedUrl: limitText(url.toString(), 2048) || url.toString().slice(0, 2048),
      finalUrl: limitText(metadataResult.finalUrl.toString(), 2048),
      httpStatus: metadataResult.response.status,
      contentType: limitText(contentType, 120),
      title: null,
      description: null,
      pageSignals,
      notes,
    });
  } catch (error) {
    const note =
      error instanceof Error && /ENOTFOUND/i.test(error.message)
        ? "No se pudo inspeccionar el link porque el dominio no existe o no responde en DNS."
        : error instanceof Error
          ? `No se pudo inspeccionar el link: ${error.message}`.slice(0, 180)
          : "No se pudo inspeccionar el link.";

    return buildPreviewResult({
      status: "failed",
      requestedUrl: limitText(url.toString(), 2048) || url.toString().slice(0, 2048),
      finalUrl: limitText(url.toString(), 2048),
      httpStatus: null,
      contentType: null,
      title: null,
      description: null,
      pageSignals: [],
      notes: [note],
    });
  }
}
