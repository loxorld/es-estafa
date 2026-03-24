import dns from "node:dns/promises";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("node:dns/promises", () => ({
  default: {
    lookup: vi.fn(),
  },
}));
vi.mock("server-only", () => ({}));

import { previewLink } from "@/lib/analysis/link-preview";

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("previewLink", () => {
  it("bloquea IPs privadas aunque lleguen como IPv4 mapeada en IPv6", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);

    const result = await previewLink("http://[::ffff:192.168.0.1]");

    expect(result.status).toBe("blocked");
    expect(result.notes[0]).toContain("IP privada o reservada");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("se queda en HEAD incluso cuando el destino parece un HTML normal", async () => {
    vi.mocked(dns.lookup).mockResolvedValue([{ address: "93.184.216.34" }] as never);

    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 200,
          headers: {
            "content-type": "text/html; charset=utf-8",
          },
        }),
      );

    vi.stubGlobal("fetch", fetchMock);

    const result = await previewLink("https://example.com/archivo.pdf");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.any(URL),
      expect.objectContaining({ method: "HEAD" }),
    );
    expect(result.status).toBe("fetched");
    expect(result.contentType).toBe("text/html; charset=utf-8");
    expect(result.notes.some((note) => note.includes("solo se inspeccionaron"))).toBe(true);
  });

  it("no cae a GET aunque el servidor no soporte HEAD", async () => {
    vi.mocked(dns.lookup).mockResolvedValue([{ address: "93.184.216.34" }] as never);

    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 405 }));

    vi.stubGlobal("fetch", fetchMock);

    const result = await previewLink("https://example.com/solo-head");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.any(URL),
      expect.objectContaining({ method: "HEAD" }),
    );
    expect(result.status).toBe("fetched");
    expect(
      result.notes.some((note) =>
        note.includes("no permite inspeccion segura por HEAD sin descargar la pagina completa"),
      ),
    ).toBe(true);
  });

  it("no intenta abrir esquemas no web", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);

    const result = await previewLink("mailto:soporte@banco.com");

    expect(result.status).toBe("blocked");
    expect(result.notes[0]).toContain("http o https");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
