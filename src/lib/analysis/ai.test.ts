import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

const parseMock = vi.fn();

vi.mock("@/lib/openai", () => ({
  getOpenAIClient: () => ({
    responses: {
      parse: parseMock,
    },
  }),
  getOpenAIModel: () => "gpt-4.1-mini",
}));

import {
  buildAiRequestPayload,
  clearAiAssessmentCache,
  generateAiAssessment,
} from "@/lib/analysis/ai";
import { analysisResultSchema, type AnalysisResult, type AnalyzeInput } from "@/lib/analysis/types";

function buildHeuristicResult(overrides: Partial<AnalysisResult> = {}) {
  return analysisResultSchema.parse({
    mode: "reglas",
    aiStatus: "no_configurada",
    aiMessage: "Solo reglas.",
    riskLevel: "medio",
    riskScore: 48,
    summary: "Hay detalles que conviene revisar.",
    explanation: "El caso mezcla urgencia, pedidos sensibles y un link para verificar.",
    fraudType: "robo de cuenta",
    confidence: 82,
    suspiciousSignals: [
      "Pide validar la cuenta.",
      "Mete presion con un supuesto bloqueo.",
    ],
    evidence: [
      'Fragmento del mensaje: "Tu codigo es 123456".',
      "El dominio no coincide con la marca mencionada.",
    ],
    recommendations: [
      "No compartas claves ni codigos.",
      "Confirma el pedido desde un canal oficial.",
      "No entres al sitio desde ese link.",
    ],
    heuristicSignals: [
      "Pide datos sensibles como claves, codigos de seguridad, PIN, OTP o token.",
      "El dominio menciona una marca conocida, pero no coincide con un dominio oficial.",
    ],
    localChecks: [
      "Se miro la urgencia del texto.",
      "Se revisaron pedidos de datos sensibles.",
      "Se chequeo la estructura del link.",
    ],
    scoreBreakdown: {
      text: 42,
      link: 55,
      preview: 0,
      final: 48,
    },
    detectedUrls: ["https://banco-ejemplo.com/reset?token=abc123"],
    inputTypes: ["texto", "link"],
    linkAssessment: {
      rawUrl: "https://banco-ejemplo.com/reset?token=abc123",
      normalizedUrl: "https://banco-ejemplo.com/reset?token=abc123",
      domain: "banco-ejemplo.com",
      score: 55,
      verdict: "precaucion",
      flags: [
        "El dominio menciona una marca conocida, pero no coincide con un dominio oficial.",
      ],
    },
    linkPreview: null,
    warnings: [],
    disclaimer: "Tomalo como una guia rapida.",
    generatedAt: new Date().toISOString(),
    ...overrides,
  });
}

describe("buildAiRequestPayload", () => {
  it("redacta datos sensibles antes de enviarlos a OpenAI", () => {
    const input: AnalyzeInput = {
      message:
        "Tu codigo es 123456. Escribinos a persona@correo.com o llama al +54 11 1234-5678. Entra en https://banco-ejemplo.com/reset?token=abc123&mail=persona@correo.com",
      link: "https://banco-ejemplo.com/reset?token=abc123&mail=persona@correo.com",
    };
    const payload = buildAiRequestPayload(input, buildHeuristicResult());
    const serializedPayload = JSON.stringify(payload);

    expect(serializedPayload).not.toContain("123456");
    expect(serializedPayload).not.toContain("persona@correo.com");
    expect(serializedPayload).not.toContain("abc123");
    expect(serializedPayload).toContain("[email_redactado]");
    expect(serializedPayload).toContain("[telefono_redactado]");
    expect(serializedPayload).toContain("%5Bredactado%5D");
  });
});

describe("generateAiAssessment", () => {
  beforeEach(() => {
    parseMock.mockReset();
    clearAiAssessmentCache();
  });

  it("reutiliza un analisis identico sin volver a llamar a OpenAI", async () => {
    parseMock.mockResolvedValue({
      output_parsed: {
        summary: "El caso tiene senales de phishing.",
        explanation:
          "La combinacion de urgencia, pedido de validar la cuenta y dominio raro apunta a un intento de robo de cuenta.",
        riskScore: 74,
        fraudType: "robo de cuenta",
        confidence: 88,
        suspiciousSignals: [
          "Empuja a validar una cuenta con urgencia.",
          "El dominio no coincide con la marca mencionada.",
        ],
        evidence: [
          "El mensaje dice que la cuenta sera bloqueada si no actuas ahora.",
          "El link usa un dominio distinto del oficial.",
        ],
        recommendations: [
          "No compartas codigos ni claves.",
          "Entra solo desde la app oficial.",
          "Confirma el aviso por otro canal.",
        ],
      },
    });

    const input: AnalyzeInput = {
      message: "Banco ejemplo: tu cuenta sera bloqueada. Valida el codigo 123456 ahora.",
      link: "https://banco-ejemplo.com/reset?token=abc123",
    };
    const heuristicResult = buildHeuristicResult();

    const first = await generateAiAssessment(input, heuristicResult);
    const second = await generateAiAssessment(input, heuristicResult);

    expect(first).toEqual(second);
    expect(parseMock).toHaveBeenCalledTimes(1);
    expect(parseMock).toHaveBeenCalledWith(
      expect.objectContaining({
        prompt_cache_retention: "in_memory",
        store: false,
      }),
      expect.objectContaining({
        timeout: 8_000,
      }),
    );
  });

  it("normaliza el summary sin pasarse del limite final", async () => {
    parseMock.mockResolvedValue({
      output_parsed: {
        summary: "a".repeat(180),
        explanation:
          "La combinacion de urgencia, pedido de validar la cuenta y dominio raro apunta a un intento de robo de cuenta.",
        riskScore: 74,
        fraudType: "robo de cuenta",
        confidence: 88,
        suspiciousSignals: [
          "Empuja a validar una cuenta con urgencia.",
          "El dominio no coincide con la marca mencionada.",
        ],
        evidence: [
          "El mensaje dice que la cuenta sera bloqueada si no actuas ahora.",
          "El link usa un dominio distinto del oficial.",
        ],
        recommendations: [
          "No compartas codigos ni claves.",
          "Entra solo desde la app oficial.",
          "Confirma el aviso por otro canal.",
        ],
      },
    });

    const assessment = await generateAiAssessment(
      {
        message: "Banco ejemplo: tu cuenta sera bloqueada. Valida ahora.",
        link: "https://banco-ejemplo.com/reset?token=abc123",
      },
      buildHeuristicResult(),
    );

    expect(assessment?.summary.length).toBeLessThanOrEqual(180);
  });
});
