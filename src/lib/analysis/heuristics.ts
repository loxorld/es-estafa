import {
  clampScore,
  type AnalyzeInput,
  type LinkAssessment,
  type LinkPreview,
} from "@/lib/analysis/types";
import { getMatchingFragment, matchesAny, uniqueStrings } from "@/lib/analysis/helpers";
import {
  actionPatterns,
  brandProfiles,
  credentialPatterns,
  impersonationPatterns,
  paymentPatterns,
  rewardPatterns,
  secrecyPatterns,
  threatPatterns,
  urgencyPatterns,
} from "@/lib/analysis/patterns";
import { getDominantSource } from "@/lib/analysis/scoring";

function findMentionedBrands(source: string) {
  return brandProfiles.filter((profile) =>
    profile.patterns.some((pattern) => pattern.test(source)),
  );
}

function domainMatchesBrand(domain: string, domainHints: readonly string[]) {
  const normalized = domain.toLowerCase();
  return domainHints.some((hint) => normalized === hint || normalized.endsWith(`.${hint}`));
}

export function detectTextSignals(message: string) {
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

export function detectBrandMismatchSignals(
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

export function buildLocalChecks() {
  return [
    "Se miro si el texto mete urgencia, bloqueo, premios o presion para hacerte actuar.",
    "Se reviso si el mensaje pide claves, codigos, dinero o validaciones sensibles.",
    "Se chequeo la estructura del link: dominio, protocolo, puertos, acortadores y palabras de riesgo.",
    "Si era seguro, se siguieron redirecciones y se revisaron URL final y headers del destino.",
    "Se bloquearon destinos privados, credenciales embebidas y puertos fuera de lo comun.",
  ];
}

export function buildHeuristicSummary(
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
      : "No salta una alerta fuerte, pero igual conviene confirmar antes de responder.";
  }

  return score === 0
    ? "No vi alertas claras en el mensaje ni en el link revisado."
    : "No salta una alerta fuerte, pero igual conviene revisar antes de confiar.";
}

export function buildHeuristicExplanation(
  score: number,
  textScore: number,
  linkScore: number,
  previewScore: number,
  findings: string[],
) {
  const dominantSource = getDominantSource(textScore, linkScore, previewScore);
  const topFindings = uniqueStrings(findings).slice(0, 3);

  if (score === 0) {
    return "En esta revision no aparecieron pedidos de claves, presion fuerte, rarezas claras en el dominio ni senales tipicas en la inspeccion segura del destino.";
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

  return `El puntaje se apoya sobre todo en ${dominantLabel}. Lo mas relevante fue: ${topFindings.join(" ")}`.slice(
    0,
    420,
  );
}

export function buildRecommendations(
  input: AnalyzeInput,
  linkAssessment: LinkAssessment | null,
  linkPreview: LinkPreview | null,
  score: number,
) {
  if (score < 25) {
    const lowRiskRecommendations = [
      "No salta una alerta fuerte, pero si el contexto te resulta raro conviene confirmarlo igual.",
      input.link || linkAssessment
        ? "Si vas a entrar, revisa el dominio y fijate si el contexto coincide con lo que esperabas."
        : "Si el mensaje te llego de la nada y te descoloca, confirmalo por otro canal.",
      "Si mas adelante te pidieran claves, codigos o plata, ahi si frena y verificalo antes de seguir.",
    ];

    return uniqueStrings(lowRiskRecommendations).slice(0, 6);
  }

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

  return uniqueStrings(recommendations).slice(0, 6);
}

export function inferFraudType(
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

export function extractEvidence(
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
