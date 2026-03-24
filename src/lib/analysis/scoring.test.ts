import { describe, expect, it } from "vitest";

import {
  combineHeuristicScore,
  estimateConfidence,
  estimatePreviewScore,
  getDominantSource,
} from "@/lib/analysis/scoring";
import type { LinkAssessment, LinkPreview } from "@/lib/analysis/types";

describe("combineHeuristicScore", () => {
  it("combina la senal dominante con bonus moderados del resto de las fuentes", () => {
    expect(combineHeuristicScore(60, 30, 20)).toBe(79);
  });
});

describe("getDominantSource", () => {
  it("devuelve mixto cuando dos fuentes quedan muy cerca", () => {
    expect(getDominantSource(42, 38, 0)).toBe("mixto");
  });
});

describe("estimatePreviewScore", () => {
  it("sube el score cuando la vista previa fue bloqueada por motivos de red privada", () => {
    const linkPreview: LinkPreview = {
      status: "blocked",
      requestedUrl: "https://interna.test",
      finalUrl: null,
      httpStatus: null,
      contentType: null,
      title: null,
      description: null,
      pageSignals: [],
      notes: ["El dominio resuelve a una IP privada o reservada."],
    };

    expect(estimatePreviewScore(linkPreview)).toBeGreaterThanOrEqual(24);
  });
});

describe("estimateConfidence", () => {
  it("sube la confianza cuando hay link, preview util y evidencia suficiente", () => {
    const linkAssessment: LinkAssessment = {
      rawUrl: "https://ejemplo.test",
      normalizedUrl: "https://ejemplo.test/",
      domain: "ejemplo.test",
      score: 70,
      verdict: "sospechoso",
      flags: [],
    };
    const linkPreview: LinkPreview = {
      status: "fetched",
      requestedUrl: "https://ejemplo.test",
      finalUrl: "https://ejemplo.test",
      httpStatus: 200,
      contentType: "text/html",
      title: "Verificacion",
      description: "Confirma tu cuenta",
      pageSignals: ["El contenido empuja a iniciar sesion o validar una cuenta."],
      notes: [],
    };

    expect(estimateConfidence(74, 3, linkAssessment, linkPreview)).toBeGreaterThanOrEqual(90);
  });
});
