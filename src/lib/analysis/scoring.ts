import { clampScore, type LinkAssessment, type LinkPreview } from "@/lib/analysis/types";

export function getDominantSource(textScore: number, linkScore: number, previewScore: number) {
  const ranked = [
    { source: "texto", score: textScore },
    { source: "link", score: linkScore },
    { source: "destino", score: previewScore },
  ].sort((left, right) => right.score - left.score);

  if ((ranked[0]?.score ?? 0) === 0) {
    return "ninguno";
  }

  if ((ranked[1]?.score ?? 0) >= (ranked[0]?.score ?? 0) - 6 && (ranked[1]?.score ?? 0) > 0) {
    return "mixto";
  }

  return ranked[0]?.source ?? "ninguno";
}

export function combineHeuristicScore(textScore: number, linkScore: number, previewScore: number) {
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

export function estimatePreviewScore(linkPreview: LinkPreview | null) {
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

export function estimateConfidence(
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
