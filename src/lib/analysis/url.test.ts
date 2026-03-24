import { describe, expect, it } from "vitest";

import { analyzeUrl, extractUrls } from "@/lib/analysis/url";

describe("extractUrls", () => {
  it("deduplica y limpia links detectados dentro del mensaje", () => {
    const urls = extractUrls(
      "Mira https://example.com/login y tambien https://example.com/login, o www.acortado.com/test.",
    );

    expect(urls).toEqual(["https://example.com/login", "www.acortado.com/test"]);
  });
});

describe("analyzeUrl", () => {
  it("marca como riesgoso un link con varias senales tipicas de phishing", () => {
    const result = analyzeUrl("http://bit.ly/reset-password?token=abc123&account=locked");

    expect(result).not.toBeNull();
    expect(result?.verdict).toBe("precaucion");
    expect(result?.score).toBeGreaterThanOrEqual(25);
    expect(result?.flags).toContain("No usa HTTPS, asi que viaja sin cifrado moderno.");
  });

  it("evita penalizar de mas un dominio confiable con palabras sensibles en la ruta", () => {
    const result = analyzeUrl("https://google.com/account/security");

    expect(result).not.toBeNull();
    expect(result?.domain).toBe("google.com");
    expect(result?.score).toBeLessThan(25);
  });

  it("marca como sospechoso un dominio que incrusta una marca conocida aunque llegue sin mensaje", () => {
    const result = analyzeUrl("https://mercadopago-seguro.com/verificacion");

    expect(result).not.toBeNull();
    expect(result?.verdict).toBe("precaucion");
    expect(result?.score).toBeGreaterThanOrEqual(30);
    expect(
      result?.flags.some((flag) =>
        flag.includes("El dominio menciona Mercado Pago, pero no coincide con un dominio oficial"),
      ),
    ).toBe(true);
  });

  it("no reinterpreta esquemas no web como si fueran sitios http", () => {
    const result = analyzeUrl("mailto:soporte@banco.com");

    expect(result).not.toBeNull();
    expect(result?.normalizedUrl).toBe("mailto:soporte@banco.com");
    expect(result?.domain).toBe("Esquema mailto");
    expect(result?.verdict).toBe("precaucion");
    expect(result?.flags).toContain(
      "No es una URL web http/https, asi que no se pudo revisar como un sitio normal.",
    );
  });
});
