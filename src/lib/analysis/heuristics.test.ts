import { describe, expect, it } from "vitest";

import {
  buildRecommendations,
  detectBrandMismatchSignals,
  detectTextSignals,
  inferFraudType,
} from "@/lib/analysis/heuristics";
import type { AnalyzeInput, LinkAssessment, LinkPreview } from "@/lib/analysis/types";

describe("detectTextSignals", () => {
  it("sube fuerte el score cuando hay urgencia, bloqueo y pedido de credenciales", () => {
    const result = detectTextSignals(
      "Urgente: tu banco detecto un problema. Verifica tu cuenta hoy mismo o sera suspendida. Ingresa tu codigo OTP ahora.",
    );

    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.signals).toContain(
      "Usa urgencia o limite de tiempo para empujarte a actuar rapido.",
    );
    expect(result.signals).toContain(
      "Pide datos sensibles como claves, codigos de seguridad, PIN, OTP o token.",
    );
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it("deja score neutro cuando el mensaje no tiene rasgos tipicos de fraude", () => {
    const result = detectTextSignals(
      "Hola, te paso la direccion del restaurante para ver el menu antes de ir a cenar.",
    );

    expect(result.score).toBe(0);
    expect(result.signals).toHaveLength(0);
  });
});

describe("detectBrandMismatchSignals", () => {
  it("detecta cuando el mensaje menciona una marca pero el dominio no coincide", () => {
    const linkAssessment: LinkAssessment = {
      rawUrl: "https://pagos-seguros-ejemplo.com",
      normalizedUrl: "https://pagos-seguros-ejemplo.com/",
      domain: "pagos-seguros-ejemplo.com",
      score: 30,
      verdict: "precaucion",
      flags: [],
    };

    const result = detectBrandMismatchSignals(
      "Mercado Pago detecto un problema con tu cuenta",
      linkAssessment,
      null,
    );

    expect(result.linkScore).toBeGreaterThan(0);
    expect(result.signals[0]).toContain("Mercado Pago");
  });

  it("no toma como oficial un dominio que solo incrusta la marca dentro del nombre", () => {
    const linkAssessment: LinkAssessment = {
      rawUrl: "https://mercadopago-seguro.com",
      normalizedUrl: "https://mercadopago-seguro.com/",
      domain: "mercadopago-seguro.com",
      score: 42,
      verdict: "precaucion",
      flags: [],
    };

    const result = detectBrandMismatchSignals(
      "Mercado Pago necesita que confirmes tu cuenta",
      linkAssessment,
      null,
    );

    expect(result.linkScore).toBeGreaterThan(0);
    expect(result.signals[0]).toContain("Mercado Pago");
  });

  it("mantiene como valido un subdominio oficial real", () => {
    const linkAssessment: LinkAssessment = {
      rawUrl: "https://accounts.google.com",
      normalizedUrl: "https://accounts.google.com/",
      domain: "accounts.google.com",
      score: 0,
      verdict: "limpio",
      flags: [],
    };

    const result = detectBrandMismatchSignals("Google te envio un aviso", linkAssessment, null);

    expect(result.linkScore).toBe(0);
    expect(result.signals).toHaveLength(0);
  });
});

describe("buildRecommendations e inferFraudType", () => {
  it("refuerza recomendaciones de no iniciar sesion cuando el caso parece phishing", () => {
    const input: AnalyzeInput = {
      message: "Ingresa tu clave y tu OTP para validar la cuenta",
      link: "https://phishing.test/login",
    };
    const linkAssessment: LinkAssessment = {
      rawUrl: input.link,
      normalizedUrl: `${input.link}/`,
      domain: "phishing.test",
      score: 78,
      verdict: "sospechoso",
      flags: ["Incluye palabras asociadas a login, verificacion, pagos o recuperacion de cuenta."],
    };
    const linkPreview: LinkPreview = {
      status: "fetched",
      requestedUrl: input.link,
      finalUrl: input.link,
      httpStatus: 200,
      contentType: "text/html",
      title: "Login",
      description: "Verifica tu cuenta",
      pageSignals: ["El contenido empuja a iniciar sesion o validar una cuenta."],
      notes: [],
    };

    const recommendations = buildRecommendations(input, linkAssessment, linkPreview, 82);

    expect(
      recommendations.some((item) => item.includes("No inicies sesion ni cargues claves")),
    ).toBe(true);
    expect(inferFraudType(input, linkAssessment, linkPreview, 82)).toBe("robo de cuenta");
  });

  it("usa recomendaciones mas tranquilas cuando el riesgo es bajo", () => {
    const recommendations = buildRecommendations(
      {
        message: "Hola, te paso el link del restaurante para ver el menu.",
        link: "https://www.google.com",
      },
      null,
      null,
      0,
    );

    expect(recommendations.some((item) => item.includes("No compartas claves"))).toBe(false);
    expect(recommendations[0]).toContain("No salta una alerta fuerte");
  });
});
