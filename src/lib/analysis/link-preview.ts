import "server-only";

import dns from "node:dns/promises";
import { isIP } from "node:net";

import { linkPreviewSchema, type LinkPreview } from "@/lib/analysis/types";

const requestHeaders = {
  "user-agent": "es-estafa-bot/1.0 (+link-preview)",
  accept: "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
};
const maxPreviewBodyBytes = 1_500_000;

function limitText(value: string | null | undefined, maxLength: number) {
  if (!value) {
    return null;
  }

  return value.replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function normalizeCandidate(rawUrl: string) {
  const cleaned = rawUrl.trim();
  if (!cleaned) {
    return null;
  }

  const withProtocol =
    /^https?:\/\//i.test(cleaned) || /^[a-z]+:\/\//i.test(cleaned)
      ? cleaned
      : `https://${cleaned}`;

  try {
    return new URL(withProtocol);
  } catch {
    return null;
  }
}

function isPrivateIpv4(ip: string) {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
    return false;
  }

  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateIpv6(ip: string) {
  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

function isPrivateOrReservedIp(ip: string) {
  const family = isIP(ip);
  if (family === 4) {
    return isPrivateIpv4(ip);
  }

  if (family === 6) {
    return isPrivateIpv6(ip);
  }

  return false;
}

async function assertSafeHost(url: URL) {
  const hostname = url.hostname.toLowerCase();

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

function stripHtml(html: string) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function extractTagContent(html: string, tagName: string) {
  const match = html.match(new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)<\\/${tagName}>`, "i"));
  return match?.[1]?.replace(/\s+/g, " ").trim() || null;
}

function extractMetaDescription(html: string) {
  const match = html.match(
    /<meta[^>]+(?:name|property)=["'](?:description|og:description)["'][^>]+content=["']([^"']+)["'][^>]*>/i,
  );
  return match?.[1]?.replace(/\s+/g, " ").trim() || null;
}

function isTextLikeContentType(contentType: string | null) {
  return Boolean(contentType && /(text\/html|application\/xhtml\+xml|text\/plain)/i.test(contentType));
}

function buildPageSignals(html: string, text: string) {
  const source = `${html} ${text}`.toLowerCase();
  const signals: string[] = [];

  if (/<form[\s\S]*?<input[\s\S]*?type=["']password["']/i.test(html)) {
    signals.push("La pagina parece tener un formulario de login con campo de password.");
  }

  if (
    /(iniciar sesi[oó]n|sign in|login|accede con tu cuenta|ingresa con tu cuenta)/i.test(source)
  ) {
    signals.push("El contenido empuja a iniciar sesion o validar una cuenta.");
  }

  if (/(verify|verification|security check|update password|account locked)/i.test(source)) {
    signals.push("El contenido habla de verificar cuenta, seguridad o bloqueo.");
  }

  if (/(invoice|factura|payment|pago pendiente|wallet|crypto)/i.test(source)) {
    signals.push("La pagina empuja pagos, facturas o movimientos de dinero.");
  }

  if (/(gift|premio|sorteo|claim now|winner)/i.test(source)) {
    signals.push("El contenido promete premios o beneficios para apurarte.");
  }

  if (/(otp|token|pin|codigo de seguridad|one time password)/i.test(source)) {
    signals.push("El contenido menciona codigos de seguridad o autenticacion.");
  }

  if (/(soporte oficial|official support|chat support|centro de seguridad)/i.test(source)) {
    signals.push("La pagina intenta presentarse como soporte, seguridad o centro oficial.");
  }

  return signals.map((signal) => signal.slice(0, 160)).slice(0, 8);
}

export async function previewLink(rawUrl: string): Promise<LinkPreview> {
  const url = normalizeCandidate(rawUrl);

  if (!url) {
    return linkPreviewSchema.parse({
      status: "failed",
      requestedUrl: rawUrl,
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
    return linkPreviewSchema.parse({
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

  let currentUrl = url;
  const redirectNotes: string[] = [];

  try {
    for (let redirectCount = 0; redirectCount < 4; redirectCount += 1) {
      const response = await fetch(currentUrl, {
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

      const contentType = response.headers.get("content-type");
      const notes = [...redirectNotes];

      if (!response.ok) {
        notes.push(`La pagina respondio con estado HTTP ${response.status}.`);
      }

      if (contentType && !isTextLikeContentType(contentType)) {
        notes.push(`El contenido parece ser ${contentType} y no una pagina HTML comun.`);

        return linkPreviewSchema.parse({
          status: "fetched",
          requestedUrl: limitText(url.toString(), 2048) || url.toString().slice(0, 2048),
          finalUrl: limitText(currentUrl.toString(), 2048),
          httpStatus: response.status,
          contentType: limitText(contentType, 120),
          title: null,
          description: null,
          pageSignals: [],
          notes: notes.map((note) => note.slice(0, 180)).slice(0, 6),
        });
      }

      const contentLength = Number(response.headers.get("content-length") ?? "0");

      if (Number.isFinite(contentLength) && contentLength > maxPreviewBodyBytes) {
        notes.push("La pagina es demasiado grande para una vista previa segura y acotada.");

        return linkPreviewSchema.parse({
          status: "fetched",
          requestedUrl: limitText(url.toString(), 2048) || url.toString().slice(0, 2048),
          finalUrl: limitText(currentUrl.toString(), 2048),
          httpStatus: response.status,
          contentType: limitText(contentType, 120),
          title: null,
          description: null,
          pageSignals: [],
          notes: notes.map((note) => note.slice(0, 180)).slice(0, 6),
        });
      }

      const rawBody = (await response.text()).slice(0, 150000);
      const title = extractTagContent(rawBody, "title");
      const description = extractMetaDescription(rawBody);
      const visibleText = stripHtml(rawBody).slice(0, 1200);
      const pageSignals = buildPageSignals(rawBody, visibleText);

      if (!title && !description && visibleText.length < 40) {
        notes.push("La pagina devolvio poco contenido legible para inspeccionar.");
      }

      if (currentUrl.toString() !== url.toString()) {
        notes.push("El destino final no coincide con el link original compartido.");
      }

      return linkPreviewSchema.parse({
        status: "fetched",
        requestedUrl: limitText(url.toString(), 2048) || url.toString().slice(0, 2048),
        finalUrl: limitText(currentUrl.toString(), 2048),
        httpStatus: response.status,
        contentType: limitText(contentType, 120),
        title: limitText(title, 180),
        description: limitText(description, 260),
        pageSignals,
        notes: notes.map((note) => note.slice(0, 180)).slice(0, 6),
      });
    }

    return linkPreviewSchema.parse({
      status: "failed",
      requestedUrl: limitText(url.toString(), 2048) || url.toString().slice(0, 2048),
      finalUrl: limitText(currentUrl.toString(), 2048),
      httpStatus: null,
      contentType: null,
      title: null,
      description: null,
      pageSignals: [],
      notes: ["El link tuvo demasiadas redirecciones y se corto la vista previa."],
    });
  } catch (error) {
    const note =
      error instanceof Error && /ENOTFOUND/i.test(error.message)
        ? "No se pudo inspeccionar el link porque el dominio no existe o no responde en DNS."
        : error instanceof Error
          ? `No se pudo inspeccionar el link: ${error.message}`.slice(0, 180)
          : "No se pudo inspeccionar el link.";

    return linkPreviewSchema.parse({
      status: "failed",
      requestedUrl: limitText(url.toString(), 2048) || url.toString().slice(0, 2048),
      finalUrl: limitText(currentUrl.toString(), 2048),
      httpStatus: null,
      contentType: null,
      title: null,
      description: null,
      pageSignals: [],
      notes: [note],
    });
  }
}
