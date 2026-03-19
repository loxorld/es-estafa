import "server-only";

import { zodTextFormat } from "openai/helpers/zod";

import { previewLink } from "@/lib/analysis/link-preview";
import {
  aiAssessmentSchema,
  analysisResultSchema,
  clampScore,
  riskLevelFromScore,
  type AiAssessment,
  type AnalysisResult,
  type AnalyzeInput,
  type LinkAssessment,
  type LinkPreview,
} from "@/lib/analysis/types";
import { getPrimaryLinkAssessment } from "@/lib/analysis/url";
import { getOpenAIClient, getOpenAIModel } from "@/lib/openai";

const urgencyPatterns = [
  /\burgente\b/i,
  /\bde inmediato\b/i,
  /\bhoy mismo\b/i,
  /\bultim[ao] aviso\b/i,
  /\b24 horas\b/i,
  /\bexpira\b/i,
  /\bdentro de las proximas?\s+\d+\s*(horas?|minutos?)\b/i,
  /\bantes del cierre\b/i,
  /\bantes de que\b/i,
  /\bnow\b/i,
  /\bimmediately\b/i,
  /\bfinal notice\b/i,
];

const threatPatterns = [
  /\bbloquead[ao]\b/i,
  /\bsuspendid[ao]\b/i,
  /\bcancelad[ao]\b/i,
  /\binhabilitad[ao]\b/i,
  /\baccount locked\b/i,
  /\baccess denied\b/i,
  /\bvencid[ao]\b/i,
  /\bse desactivara\b/i,
];

const credentialPatterns = [
  /\bcontrase(?:na|\u00f1a)\b/i,
  /\bpassword\b/i,
  /\bclave\b/i,
  /\bpin\b/i,
  /\botp\b/i,
  /\bcvv\b/i,
  /\btoken\b/i,
  /\bc[o\u00f3]digo(?:\s+de)?\s+(?:verificaci[o\u00f3]n|seguridad|confirmaci[o\u00f3]n)\b/i,
  /\bverific[a\u00e1] tu cuenta\b/i,
];

const paymentPatterns = [
  /\btransfer(?:encia|ir)\b/i,
  /\bmercado pago\b/i,
  /\bpago pendiente\b/i,
  /\bwallet\b/i,
  /\bcripto\b/i,
  /\bcrypto\b/i,
  /\bdep[o\u00f3]sito\b/i,
  /\bdeposit\b/i,
  /\bfactura\b/i,
  /\binvoice\b/i,
  /\bgift card\b/i,
];

const rewardPatterns = [
  /\bganaste\b/i,
  /\bpremio\b/i,
  /\bsorteo\b/i,
  /\bbeneficio exclusivo\b/i,
  /\bwinner\b/i,
  /\bclaim now\b/i,
];

const secrecyPatterns = [
  /\bno compartas esto\b/i,
  /\bmantenelo en secreto\b/i,
  /\bno lo hables con nadie\b/i,
  /\bsolo por hoy\b/i,
  /\baprovecha ya\b/i,
];

const actionPatterns = [
  /\bhaz clic\b/i,
  /\bclick\b/i,
  /\bingresa\b/i,
  /\bentra\b/i,
  /\baccede\b/i,
  /\bverifica\b/i,
  /\bvalida\b/i,
  /\bactualiza\b/i,
  /\bconfirma\b/i,
  /\bpaga\b/i,
  /\breclama\b/i,
  /\bdescarga\b/i,
];

const impersonationPatterns = [
  /\btu banco\b/i,
  /\barea de seguridad\b/i,
  /\bafip\b/i,
  /\bcorreo argentino\b/i,
  /\bmercado libre\b/i,
  /\bmercado pago\b/i,
  /\bwhatsapp\b/i,
  /\bnetflix\b/i,
  /\bpaypal\b/i,
  /\bamazon\b/i,
  /\bapple\b/i,
  /\bgmail\b/i,
  /\bgoogle\b/i,
];

const brandProfiles = [
  {
    name: "Mercado Pago",
    patterns: [/\bmercado pago\b/i],
    domainHints: ["mercadopago"],
  },
  {
    name: "Mercado Libre",
    patterns: [/\bmercado libre\b/i],
    domainHints: ["mercadolibre"],
  },
  {
    name: "WhatsApp",
    patterns: [/\bwhatsapp\b/i],
    domainHints: ["whatsapp"],
  },
  {
    name: "Netflix",
    patterns: [/\bnetflix\b/i],
    domainHints: ["netflix"],
  },
  {
    name: "PayPal",
    patterns: [/\bpaypal\b/i],
    domainHints: ["paypal"],
  },
  {
    name: "Amazon",
    patterns: [/\bamazon\b/i],
    domainHints: ["amazon"],
  },
  {
    name: "Apple",
    patterns: [/\bapple\b/i, /\bicloud\b/i],
    domainHints: ["apple", "icloud"],
  },
  {
    name: "Google",
    patterns: [/\bgoogle\b/i, /\bgmail\b/i],
    domainHints: ["google", "gmail"],
  },
  {
    name: "Microsoft",
    patterns: [/\bmicrosoft\b/i, /\boutlook\b/i, /\bhotmail\b/i],
    domainHints: ["microsoft", "outlook", "hotmail", "live"],
  },
  {
    name: "AFIP",
    patterns: [/\bafip\b/i],
    domainHints: ["afip"],
  },
  {
    name: "Correo Argentino",
    patterns: [/\bcorreo argentino\b/i],
    domainHints: ["correoargentino"],
  },
];

function uniqueStrings(values: string[]) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function matchesAny(patterns: RegExp[], value: string) {
  return patterns.some((pattern) => pattern.test(value));
}

function extractMessageChunks(message: string) {
  return message
    .split(/[\n.!?]+/)
    .map((chunk) => chunk.trim())
    .filter(Boolean);
}

function getMatchingFragment(message: string, patterns: RegExp[]) {
  return extractMessageChunks(message).find((chunk) => matchesAny(patterns, chunk)) ?? null;
}

function getDominantSource(textScore: number, linkScore: number, previewScore: number) {
  const ranked = [
    { source: "texto", score: textScore },
    { source: "link", score: linkScore },
    { source: "destino", score: previewScore },
  ].sort((left, right) => right.score - left.score);

  if (ranked[0].score === 0) {
    return "ninguno";
  }

  if (ranked[1].score >= ranked[0].score - 6 && ranked[1].score > 0) {
    return "mixto";
  }

  return ranked[0].source;
}

function findMentionedBrands(source: string) {
  return brandProfiles.filter((profile) =>
    profile.patterns.some((pattern) => pattern.test(source)),
  );
}

function domainMatchesBrand(domain: string, domainHints: string[]) {
  const normalized = domain.toLowerCase();
  return domainHints.some((hint) => normalized.includes(hint));
}

function detectTextSignals(message: string) {
  const signals: string[] = [];
  const evidence: string[] = [];
  let score = 0;

  if (!message) {
    return { score, signals, evidence };
  }

  const hasUrgency = matchesAny(urgencyPatterns, message);
  const hasThreat = matchesAny(threatPatterns, message);
  const hasCredentialRequest = matchesAny(credentialPatterns, message);
  const hasPaymentRequest = matchesAny(paymentPatterns, message);
  const hasReward = matchesAny(rewardPatterns, message);
  const hasSecrecy = matchesAny(secrecyPatterns, message);
  const hasImpersonation = matchesAny(impersonationPatterns, message);
  const hasAction = matchesAny(actionPatterns, message);
  const hasAlarmistFormatting =
    (message.match(/!/g) ?? []).length >= 3 || /\b[A-Z]{6,}\b/.test(message);

  if (hasUrgency) {
    score += 14;
    signals.push("Usa urgencia o limite de tiempo para empujarte a actuar rapido.");
  }

  if (hasThreat) {
    score += 16;
    signals.push("Habla de bloqueo, suspension o perdida de acceso para meterte presion.");
  }

  if (hasCredentialRequest) {
    score += 28;
    signals.push("Pide datos sensibles como claves, codigos de seguridad, PIN, OTP o token.");
  }

  if (hasPaymentRequest) {
    score += 20;
    signals.push("Menciona pagos, transferencias, facturas o dinero como parte del pedido.");
  }

  if (hasReward || hasSecrecy) {
    score += 14;
    signals.push("Usa premio, secreto o exclusividad para bajar defensas.");
  }

  if (hasImpersonation) {
    score += 10;
    signals.push("Podria intentar hacerse pasar por una marca, banco u organismo conocido.");
  }

  if (hasAction && (hasUrgency || hasThreat || hasCredentialRequest || hasPaymentRequest || hasReward)) {
    score += 8;
    signals.push("No solo informa: empuja a hacer clic, validar, pagar o reclamar algo.");
  }

  if (hasAlarmistFormatting) {
    score += 6;
    signals.push("El tono es exagerado o alarmista, algo frecuente en mensajes de fraude.");
  }

  if (
    message.length < 60 &&
    hasAction &&
    (hasUrgency || hasThreat || hasCredentialRequest || hasPaymentRequest)
  ) {
    score += 8;
    signals.push("El mensaje es corto y va directo a la accion, sin dar contexto real.");
  }

  const evidenceCandidates = [
    getMatchingFragment(message, credentialPatterns),
    getMatchingFragment(message, threatPatterns),
    getMatchingFragment(message, urgencyPatterns),
    getMatchingFragment(message, paymentPatterns),
    getMatchingFragment(message, rewardPatterns),
  ].filter((value): value is string => Boolean(value));

  for (const fragment of evidenceCandidates) {
    evidence.push(`Fragmento del mensaje: "${fragment.slice(0, 140)}"`);
  }

  return {
    score: clampScore(score),
    signals: uniqueStrings(signals).slice(0, 8),
    evidence: uniqueStrings(evidence).slice(0, 4),
  };
}

function detectBrandMismatchSignals(
  message: string,
  linkAssessment: LinkAssessment | null,
  linkPreview: LinkPreview | null,
) {
  const domain = linkAssessment?.domain ?? "";
  const previewSource = `${linkPreview?.title ?? ""} ${linkPreview?.description ?? ""}`;
  const messageBrands = findMentionedBrands(message);
  const previewBrands = findMentionedBrands(previewSource);
  const signals: string[] = [];
  const evidence: string[] = [];
  let linkScore = 0;
  let previewScore = 0;

  if (!domain) {
    return { linkScore, previewScore, signals, evidence };
  }

  const mismatchedMessageBrands = messageBrands.filter(
    (profile) => !domainMatchesBrand(domain, profile.domainHints),
  );

  if (mismatchedMessageBrands.length > 0) {
    const names = uniqueStrings(mismatchedMessageBrands.map((brand) => brand.name)).join(", ");
    linkScore += 18;
    signals.push(`El mensaje menciona ${names}, pero el dominio no parece oficial para esa marca.`);
    evidence.push(`Marca mencionada: ${names}. Dominio observado: ${domain}.`);
  }

  const mismatchedPreviewBrands = previewBrands.filter(
    (profile) => !domainMatchesBrand(domain, profile.domainHints),
  );

  if (mismatchedPreviewBrands.length > 0) {
    const names = uniqueStrings(mismatchedPreviewBrands.map((brand) => brand.name)).join(", ");
    previewScore += 22;
    signals.push(`La pagina se presenta como ${names}, pero el dominio no coincide con esa marca.`);
    evidence.push(`La vista previa sugiere ${names}, pero el dominio final es ${domain}.`);
  }

  return {
    linkScore: clampScore(linkScore),
    previewScore: clampScore(previewScore),
    signals: uniqueStrings(signals).slice(0, 4),
    evidence: uniqueStrings(evidence).slice(0, 4),
  };
}

function buildLocalChecks() {
  return [
    "Se reviso si el texto usa urgencia, bloqueo, premios o presion para forzarte a actuar.",
    "Se busco si el mensaje pide claves, codigos, dinero o validaciones sensibles.",
    "Se analizo la estructura del link: dominio, protocolo, puertos, acortadores y palabras de riesgo.",
    "Si fue seguro, se abrio una vista previa acotada del destino para buscar login, pagos o verificacion.",
    "Se bloquearon destinos locales, privados, credenciales embebidas y puertos fuera de lo comun.",
  ];
}

function buildHeuristicSummary(
  score: number,
  textScore: number,
  linkScore: number,
  previewScore: number,
  hasLink: boolean,
) {
  const dominantSource = getDominantSource(textScore, linkScore, previewScore);

  if (score >= 70) {
    if (dominantSource === "texto") {
      return "El mensaje muestra varias senales fuertes de fraude o phishing.";
    }

    if (dominantSource === "link") {
      return "El link muestra varias senales fuertes de riesgo.";
    }

    if (dominantSource === "destino") {
      return "El destino del link mostro varias senales tipicas de phishing.";
    }

    return "El caso combina varias alertas fuertes entre mensaje, link y destino.";
  }

  if (score >= 40) {
    if (dominantSource === "texto") {
      return "El mensaje deja varias dudas y conviene verificar antes de responder.";
    }

    if (dominantSource === "link") {
      return "El link tiene detalles raros y conviene revisarlo con cuidado.";
    }

    if (dominantSource === "destino") {
      return "La pagina de destino deja dudas y conviene no confiar de entrada.";
    }

    return "Hay varios detalles que llaman la atencion y conviene mirar con calma.";
  }

  if (!hasLink) {
    return score === 0
      ? "No vi alertas claras en este texto."
      : "No aparece una alarma fuerte, pero igual conviene confirmar antes de responder.";
  }

  return score === 0
    ? "No vi alertas claras en el mensaje ni en el link revisado."
    : "No aparece una alarma fuerte, pero igual conviene revisar antes de confiar.";
}

function buildHeuristicExplanation(
  score: number,
  textScore: number,
  linkScore: number,
  previewScore: number,
  findings: string[],
) {
  const dominantSource = getDominantSource(textScore, linkScore, previewScore);
  const topFindings = uniqueStrings(findings).slice(0, 3);

  if (score === 0) {
    return "En esta pasada local no aparecieron pedidos de claves, presion fuerte, rarezas claras en el dominio ni senales tipicas de phishing en la vista previa.";
  }

  if (score < 40 && topFindings.length > 0) {
    return `Aparecieron detalles menores, pero no alcanzan por si solos para hablar de una estafa clara. Lo principal fue: ${topFindings.join(" ")}`.slice(
      0,
      420,
    );
  }

  const dominantLabel =
    dominantSource === "texto"
      ? "el mensaje"
      : dominantSource === "link"
        ? "la estructura del link"
        : dominantSource === "destino"
          ? "la pagina de destino"
          : "la combinacion de mensaje y link";

  return `El score local se apoya sobre todo en ${dominantLabel}. Lo mas relevante fue: ${topFindings.join(" ")}`.slice(
    0,
    420,
  );
}

function buildRecommendations(
  input: AnalyzeInput,
  linkAssessment: LinkAssessment | null,
  linkPreview: LinkPreview | null,
  score: number,
) {
  const recommendations = [
    "No compartas claves, codigos, OTP, PIN ni datos bancarios por ese canal.",
    "Si el mensaje te apura, frena un segundo y verifica por otra via.",
    "Confirma el pedido desde un canal oficial: app, pagina escrita a mano o telefono conocido.",
  ];

  if (input.link || linkAssessment) {
    recommendations.push(
      "Si vas a entrar al sitio, escribe la direccion a mano o entra desde la app oficial en vez de tocar el link.",
    );
  }

  if (
    matchesAny(paymentPatterns, input.message) ||
    linkPreview?.pageSignals.some((signal) => /pagos|facturas|dinero/i.test(signal))
  ) {
    recommendations.push("No envies dinero ni confirmes pagos hasta validar la solicitud por otra via.");
  }

  if (
    matchesAny(credentialPatterns, input.message) ||
    linkPreview?.pageSignals.some((signal) => /login|cuenta|autenticacion/i.test(signal))
  ) {
    recommendations.push("No inicies sesion ni cargues claves en una pagina abierta desde un mensaje inesperado.");
  }

  if (score < 25) {
    recommendations.push("Aunque salga bajo, si el pedido te parece raro revisalo igual con alguien o por soporte oficial.");
  }

  return uniqueStrings(recommendations).slice(0, 6);
}

function inferFraudType(
  input: AnalyzeInput,
  linkAssessment: LinkAssessment | null,
  linkPreview: LinkPreview | null,
  score: number,
) {
  const source =
    `${input.message} ${input.link} ${linkPreview?.title ?? ""} ${linkPreview?.description ?? ""}`.toLowerCase();

  if (
    matchesAny(credentialPatterns, source) ||
    linkPreview?.pageSignals.some((signal) => /login|cuenta|autenticacion/i.test(signal))
  ) {
    return "robo de cuenta";
  }

  if (matchesAny(paymentPatterns, source)) {
    return "pedido de dinero";
  }

  if (matchesAny(rewardPatterns, source)) {
    return "premio falso";
  }

  if (matchesAny(impersonationPatterns, source) && matchesAny(threatPatterns, source)) {
    return "suplantacion";
  }

  if ((linkAssessment?.score ?? 0) >= 55 || (linkPreview?.pageSignals.length ?? 0) >= 2) {
    return "link sospechoso";
  }

  return score < 20 ? "sin senales claras" : "mensaje dudoso";
}

function extractEvidence(
  textEvidence: string[],
  linkAssessment: LinkAssessment | null,
  linkPreview: LinkPreview | null,
  extraEvidence: string[],
) {
  const evidence = [...textEvidence, ...extraEvidence];

  if (linkAssessment) {
    evidence.push(`Dominio observado: ${linkAssessment.domain}`);
  }

  if (linkPreview?.finalUrl && linkPreview.finalUrl !== linkPreview.requestedUrl) {
    evidence.push(`El link termina en: ${linkPreview.finalUrl}`);
  }

  if (linkPreview?.title) {
    evidence.push(`Titulo de la pagina: "${linkPreview.title}"`);
  }

  return uniqueStrings(evidence).slice(0, 6);
}

function combineHeuristicScore(textScore: number, linkScore: number, previewScore: number) {
  const ranked = [textScore, linkScore, previewScore].sort((left, right) => right - left);
  const strongest = ranked[0] ?? 0;
  let bonus = 0;

  if ((ranked[1] ?? 0) >= 12) {
    bonus += Math.round((ranked[1] ?? 0) * 0.45);
  }

  if ((ranked[2] ?? 0) >= 12) {
    bonus += Math.round((ranked[2] ?? 0) * 0.25);
  }

  return clampScore(strongest + Math.min(20, bonus));
}

function estimatePreviewScore(linkPreview: LinkPreview | null) {
  if (!linkPreview) {
    return 0;
  }

  let score = 0;

  if (linkPreview.status === "blocked") {
    if (
      linkPreview.notes.some((note) =>
        /red privada|puerto no estandar|credenciales embebidas|ip privada/i.test(note),
      )
    ) {
      score += 24;
    } else {
      score += 14;
    }
  }

  if (linkPreview.status === "failed") {
    if (linkPreview.notes.some((note) => /dns|dominio no existe/i.test(note))) {
      score += 14;
    } else if (linkPreview.notes.some((note) => /redirecciones/i.test(note))) {
      score += 10;
    } else {
      score += 4;
    }
  }

  score += Math.min(28, linkPreview.pageSignals.length * 7);

  if (linkPreview.notes.some((note) => note.toLowerCase().includes("destino final no coincide"))) {
    score += 14;
  }

  if ((linkPreview.httpStatus ?? 0) >= 400) {
    score += 6;
  }

  return clampScore(score);
}

function estimateConfidence(
  score: number,
  evidenceCount: number,
  linkAssessment: LinkAssessment | null,
  linkPreview: LinkPreview | null,
) {
  let base = score >= 70 ? 76 : score >= 40 ? 64 : 50;

  if (linkAssessment) {
    base += 6;
  }

  if (linkPreview?.status === "fetched") {
    base += 10;
  }

  if (linkPreview?.status === "blocked" || linkPreview?.status === "failed") {
    base += 4;
  }

  base += Math.min(12, evidenceCount * 3);

  return clampScore(base);
}

async function createHeuristicResult(input: AnalyzeInput): Promise<AnalysisResult> {
  const { detectedUrls, linkAssessment } = getPrimaryLinkAssessment(input.link, input.message);
  const textAnalysis = detectTextSignals(input.message);
  const primaryUrl = linkAssessment?.normalizedUrl ?? detectedUrls[0] ?? "";
  const linkPreview = primaryUrl ? await previewLink(primaryUrl) : null;
  const previewScore = estimatePreviewScore(linkPreview);
  const brandMismatch = detectBrandMismatchSignals(input.message, linkAssessment, linkPreview);
  const textScore = textAnalysis.score;
  const linkScore = clampScore((linkAssessment?.score ?? 0) + brandMismatch.linkScore);
  const enrichedPreviewScore = clampScore(previewScore + brandMismatch.previewScore);
  const heuristicSignals = uniqueStrings([
    ...textAnalysis.signals,
    ...brandMismatch.signals,
    ...(linkAssessment?.flags ?? []),
    ...(linkPreview?.pageSignals ?? []),
  ]).slice(0, 8);
  const heuristicScore = combineHeuristicScore(textScore, linkScore, enrichedPreviewScore);
  const inputTypes = uniqueStrings([
    input.message ? "texto" : "",
    input.link || detectedUrls.length > 0 ? "link" : "",
  ]) as Array<"texto" | "link">;
  const evidence = extractEvidence(
    textAnalysis.evidence,
    linkAssessment,
    linkPreview,
    brandMismatch.evidence,
  );
  const allFindings = uniqueStrings([
    ...textAnalysis.signals,
    ...brandMismatch.signals,
    ...(linkAssessment?.flags ?? []),
    ...(linkPreview?.pageSignals ?? []),
  ]);

  return analysisResultSchema.parse({
    mode: "reglas",
    aiStatus: "no_configurada",
    aiMessage: "La capa de IA no esta activa en este analisis.",
    riskLevel: riskLevelFromScore(heuristicScore),
    riskScore: heuristicScore,
    summary: buildHeuristicSummary(
      heuristicScore,
      textScore,
      linkScore,
      enrichedPreviewScore,
      Boolean(linkAssessment),
    ),
    explanation: buildHeuristicExplanation(
      heuristicScore,
      textScore,
      linkScore,
      enrichedPreviewScore,
      allFindings,
    ),
    fraudType: inferFraudType(input, linkAssessment, linkPreview, heuristicScore),
    confidence: estimateConfidence(heuristicScore, evidence.length, linkAssessment, linkPreview),
    suspiciousSignals:
      heuristicSignals.length > 0
        ? heuristicSignals
        : ["No se detectaron senales fuertes con las reglas locales."],
    evidence:
      evidence.length > 0
        ? evidence
        : ["No hay evidencia suficiente en la entrada para sostener una conclusion fuerte."],
    recommendations: buildRecommendations(input, linkAssessment, linkPreview, heuristicScore),
    heuristicSignals,
    localChecks: buildLocalChecks(),
    scoreBreakdown: {
      text: textScore,
      link: linkScore,
      preview: enrichedPreviewScore,
      final: heuristicScore,
    },
    detectedUrls,
    inputTypes: inputTypes.length > 0 ? inputTypes : ["texto"],
    linkAssessment,
    linkPreview,
    warnings: [],
    disclaimer:
      "Analisis orientativo: no reemplaza soporte oficial, peritaje tecnico ni verificacion humana.",
    generatedAt: new Date().toISOString(),
  });
}

async function generateAiAssessment(input: AnalyzeInput, heuristicResult: AnalysisResult) {
  const client = getOpenAIClient();

  if (!client) {
    return null;
  }

  const response = await client.responses.parse({
    model: getOpenAIModel(),
    instructions:
      "Sos un analista antifraude senior para usuarios finales. Evalua el caso completo, no solo reformules heuristicas. Usa el mensaje original, el link y la vista previa del destino cuando exista. Tu trabajo es decidir si hay senales de phishing, suplantacion, fraude de pago, premio falso u otro engano digital. Debes citar evidencia concreta del mensaje o de la vista previa del link. Nunca des instrucciones para cometer fraude ni para mejorar un ataque.",
    input: JSON.stringify(
      {
        mensajeOriginal: input.message || "(sin mensaje adicional)",
        linkOriginal: input.link || null,
        tiposDetectados: heuristicResult.inputTypes,
        urlsDetectadas: heuristicResult.detectedUrls,
        hallazgosPorReglas: {
          score: heuristicResult.riskScore,
          tipoTentativo: heuristicResult.fraudType,
          senales: heuristicResult.heuristicSignals,
          evidencia: heuristicResult.evidence,
          desglose: heuristicResult.scoreBreakdown,
          analisisDelLink: heuristicResult.linkAssessment,
          vistaPreviaDelLink: heuristicResult.linkPreview,
        },
        consigna:
          "Haz tu propio juicio. Si la evidencia es insuficiente, dilo. Si el link parece normal pero el mensaje es sospechoso, explicalo. Si el mensaje parece normal pero el link o la pagina muestran senales de phishing, explicalo tambien.",
      },
      null,
      2,
    ),
    max_output_tokens: 1000,
    temperature: 0.1,
    store: false,
    text: {
      format: zodTextFormat(aiAssessmentSchema, "full_scam_analysis"),
      verbosity: "medium",
    },
  });

  const parsed = response.output_parsed;

  if (!parsed) {
    throw new Error("OpenAI no devolvio un objeto parseable.");
  }

  return aiAssessmentSchema.parse(parsed);
}

function mergeWithAi(
  heuristicResult: AnalysisResult,
  aiAssessment: AiAssessment,
  warnings: string[],
) {
  const mergedScore = clampScore(
    Math.round(aiAssessment.riskScore * 0.8 + heuristicResult.riskScore * 0.2),
  );

  return analysisResultSchema.parse({
    ...heuristicResult,
    mode: "ia+reglas",
    aiStatus: "usada",
    aiMessage: "Se sumo una segunda lectura con IA.",
    riskLevel: riskLevelFromScore(mergedScore),
    riskScore: mergedScore,
    summary: aiAssessment.summary,
    explanation: aiAssessment.explanation,
    fraudType: aiAssessment.fraudType,
    confidence: aiAssessment.confidence,
    suspiciousSignals: uniqueStrings([
      ...aiAssessment.suspiciousSignals,
      ...heuristicResult.heuristicSignals,
    ]).slice(0, 8),
    evidence: uniqueStrings([
      ...aiAssessment.evidence,
      ...heuristicResult.evidence,
    ]).slice(0, 6),
    recommendations: uniqueStrings([
      ...aiAssessment.recommendations,
      ...heuristicResult.recommendations,
    ]).slice(0, 6),
    warnings,
    generatedAt: new Date().toISOString(),
  });
}

function getAiFallbackState(error: unknown) {
  if (
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    (error as { status?: number }).status === 429
  ) {
    return {
      status: "cuota" as const,
      message: "La IA no se pudo usar por un problema de cuota o facturacion. Se aplico el modo local.",
    };
  }

  if (
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    (error as { status?: number }).status === 401
  ) {
    return {
      status: "error" as const,
      message: "La API key de OpenAI no fue aceptada. Se aplico el modo local.",
    };
  }

  if (error instanceof Error) {
    return {
      status: "error" as const,
      message: `No se pudo sumar la capa extra de IA: ${error.message}`.slice(0, 180),
    };
  }

  return {
    status: "error" as const,
    message: "No se pudo sumar la capa extra de IA.",
  };
}

export async function analyzeSubmission(input: AnalyzeInput) {
  const heuristicResult = await createHeuristicResult(input);
  const warnings = [...heuristicResult.warnings];
  const client = getOpenAIClient();

  try {
    if (!client) {
      return analysisResultSchema.parse({
        ...heuristicResult,
        aiStatus: "no_configurada",
        aiMessage: "Este analisis se hizo solo con reglas locales.",
        warnings,
      });
    }

    const aiAssessment = await generateAiAssessment(input, heuristicResult);

    if (!aiAssessment) {
      return analysisResultSchema.parse({
        ...heuristicResult,
        aiStatus: "error",
        aiMessage: "La IA no devolvio una respuesta util. Se aplico el modo local.",
        warnings,
      });
    }

    return mergeWithAi(heuristicResult, aiAssessment, warnings);
  } catch (error) {
    console.error("Fallo el analisis con OpenAI, se aplica fallback heuristico.", error);
    const aiFallback = getAiFallbackState(error);
    warnings.push(aiFallback.message);

    return analysisResultSchema.parse({
      ...heuristicResult,
      aiStatus: aiFallback.status,
      aiMessage: aiFallback.message,
      warnings: uniqueStrings(warnings).slice(0, 4),
    });
  }
}
