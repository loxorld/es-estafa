import { z } from "zod";

const stringField = (maxLength: number) =>
  z.preprocess(
    (value) => (typeof value === "string" ? value.trim() : ""),
    z.string().max(maxLength),
  );

export const analyzeInputSchema = z
  .object({
    message: stringField(4000),
    link: stringField(2048),
  })
  .superRefine(({ message, link }, ctx) => {
    if (!message && !link) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Ingresa un mensaje, un link o ambos para poder analizar.",
        path: ["message"],
      });
    }
  });

export const riskLevelSchema = z.enum(["alto", "medio", "bajo"]);
export const inputTypeSchema = z.enum(["texto", "link"]);
export const linkVerdictSchema = z.enum(["sospechoso", "precaucion", "limpio"]);
export const linkPreviewStatusSchema = z.enum(["skipped", "fetched", "blocked", "failed"]);
export const aiStatusSchema = z.enum(["usada", "no_configurada", "cuota", "error"]);
export const scoreBreakdownSchema = z.object({
  text: z.number().int().min(0).max(100),
  link: z.number().int().min(0).max(100),
  preview: z.number().int().min(0).max(100),
  final: z.number().int().min(0).max(100),
});

export const linkAssessmentSchema = z.object({
  rawUrl: z.string().min(1).max(2048),
  normalizedUrl: z.string().min(1).max(2048),
  domain: z.string().min(1).max(255),
  score: z.number().int().min(0).max(100),
  verdict: linkVerdictSchema,
  flags: z.array(z.string().min(1).max(160)).max(8),
});

export const linkPreviewSchema = z.object({
  status: linkPreviewStatusSchema,
  requestedUrl: z.string().min(1).max(2048),
  finalUrl: z.string().max(2048).nullable(),
  httpStatus: z.number().int().min(100).max(599).nullable(),
  contentType: z.string().max(120).nullable(),
  title: z.string().max(180).nullable(),
  description: z.string().max(260).nullable(),
  pageSignals: z.array(z.string().min(1).max(160)).max(8),
  notes: z.array(z.string().min(1).max(180)).max(6),
});

export const aiAssessmentSchema = z.object({
  summary: z.string().min(1).max(180),
  explanation: z.string().min(1).max(420),
  riskScore: z.number().int().min(0).max(100),
  fraudType: z.string().min(1).max(80),
  confidence: z.number().int().min(0).max(100),
  suspiciousSignals: z.array(z.string().min(1).max(160)).min(2).max(6),
  evidence: z.array(z.string().min(1).max(220)).min(2).max(5),
  recommendations: z.array(z.string().min(1).max(180)).min(3).max(5),
});

export const analysisResultSchema = z.object({
  mode: z.enum(["reglas", "ia+reglas"]),
  aiStatus: aiStatusSchema,
  aiMessage: z.string().min(1).max(180).nullable(),
  riskLevel: riskLevelSchema,
  riskScore: z.number().int().min(0).max(100),
  summary: z.string().min(1).max(180),
  explanation: z.string().min(1).max(420),
  fraudType: z.string().min(1).max(80),
  confidence: z.number().int().min(0).max(100).nullable(),
  suspiciousSignals: z.array(z.string().min(1).max(160)).max(8),
  evidence: z.array(z.string().min(1).max(220)).max(6),
  recommendations: z.array(z.string().min(1).max(180)).max(6),
  heuristicSignals: z.array(z.string().min(1).max(160)).max(8),
  localChecks: z.array(z.string().min(1).max(180)).min(3).max(6),
  scoreBreakdown: scoreBreakdownSchema,
  detectedUrls: z.array(z.string().min(1).max(2048)).max(6),
  inputTypes: z.array(inputTypeSchema).min(1).max(2),
  linkAssessment: linkAssessmentSchema.nullable(),
  linkPreview: linkPreviewSchema.nullable(),
  warnings: z.array(z.string().min(1).max(180)).max(4),
  disclaimer: z.string().min(1).max(220),
  generatedAt: z.string().datetime(),
});

export type AnalyzeInput = z.infer<typeof analyzeInputSchema>;
export type RiskLevel = z.infer<typeof riskLevelSchema>;
export type InputType = z.infer<typeof inputTypeSchema>;
export type LinkVerdict = z.infer<typeof linkVerdictSchema>;
export type LinkPreviewStatus = z.infer<typeof linkPreviewStatusSchema>;
export type AiStatus = z.infer<typeof aiStatusSchema>;
export type ScoreBreakdown = z.infer<typeof scoreBreakdownSchema>;
export type LinkAssessment = z.infer<typeof linkAssessmentSchema>;
export type LinkPreview = z.infer<typeof linkPreviewSchema>;
export type AiAssessment = z.infer<typeof aiAssessmentSchema>;
export type AnalysisResult = z.infer<typeof analysisResultSchema>;

export function clampScore(score: number) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 70) {
    return "alto";
  }

  if (score >= 40) {
    return "medio";
  }

  return "bajo";
}

export function linkVerdictFromScore(score: number): LinkVerdict {
  if (score >= 65) {
    return "sospechoso";
  }

  if (score >= 25) {
    return "precaucion";
  }

  return "limpio";
}
