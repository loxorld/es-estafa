import "server-only";

import {
  generateAiAssessment,
  getAiFallbackState,
  getAiTemporaryPauseState,
  mergeWithAi,
  rememberAiFallbackState,
} from "@/lib/analysis/ai";
import { uniqueStrings } from "@/lib/analysis/helpers";
import {
  buildHeuristicExplanation,
  buildHeuristicSummary,
  buildLocalChecks,
  buildRecommendations,
  detectBrandMismatchSignals,
  detectTextSignals,
  extractEvidence,
  inferFraudType,
} from "@/lib/analysis/heuristics";
import { previewLink } from "@/lib/analysis/link-preview";
import {
  combineHeuristicScore,
  estimateConfidence,
  estimatePreviewScore,
} from "@/lib/analysis/scoring";
import {
  analysisResultSchema,
  clampScore,
  riskLevelFromScore,
  type AnalysisResult,
  type AnalyzeInput,
} from "@/lib/analysis/types";
import { getPrimaryLinkAssessment } from "@/lib/analysis/url";
import { getOpenAIClient } from "@/lib/openai";

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

  return analysisResultSchema.parse({
    mode: "reglas",
    aiStatus: "no_configurada",
    aiMessage: "La lectura con IA no esta disponible en este momento.",
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
      heuristicSignals,
    ),
    fraudType: inferFraudType(input, linkAssessment, linkPreview, heuristicScore),
    confidence: estimateConfidence(heuristicScore, evidence.length, linkAssessment, linkPreview),
    suspiciousSignals:
      heuristicSignals.length > 0
        ? heuristicSignals
        : ["No se detectaron senales fuertes en esta revision."],
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
      "Tomalo como una guia rapida, no como una confirmacion definitiva.",
    generatedAt: new Date().toISOString(),
  });
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
        aiMessage: "Este resultado sale de la revision base.",
        warnings,
      });
    }

    const aiTemporaryPause = getAiTemporaryPauseState();

    if (aiTemporaryPause) {
      return analysisResultSchema.parse({
        ...heuristicResult,
        aiStatus: aiTemporaryPause.status,
        aiMessage: aiTemporaryPause.message,
        warnings: uniqueStrings([...warnings, aiTemporaryPause.message]).slice(0, 4),
      });
    }

    const aiAssessment = await generateAiAssessment(input, heuristicResult);

    if (!aiAssessment) {
      return analysisResultSchema.parse({
        ...heuristicResult,
        aiStatus: "error",
        aiMessage: "La lectura con IA no devolvio algo util. Se muestra la revision base.",
        warnings,
      });
    }

    return mergeWithAi(heuristicResult, aiAssessment, warnings);
  } catch (error) {
    console.error("Fallo la lectura con OpenAI. Se usa la revision base.", error);
    const aiFallback = getAiFallbackState(error);
    rememberAiFallbackState(aiFallback);
    warnings.push(aiFallback.message);

    return analysisResultSchema.parse({
      ...heuristicResult,
      aiStatus: aiFallback.status,
      aiMessage: aiFallback.message,
      warnings: uniqueStrings(warnings).slice(0, 4),
    });
  }
}
