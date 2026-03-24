import { NextResponse } from "next/server";

import { analyzeSubmission } from "@/lib/analysis/scam";
import { analyzeInputSchema } from "@/lib/analysis/types";
import { consumeRateLimit, getClientRateLimitKey } from "@/lib/rate-limit";

export const runtime = "nodejs";

const maxAnalyzeBodyBytes = 16_000;

function buildRateLimitHeaders(result: ReturnType<typeof consumeRateLimit>) {
  return {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-RateLimit-Limit": String(result.limit),
    "X-RateLimit-Remaining": String(result.remaining),
    "Retry-After": String(result.retryAfter),
  };
}

export async function POST(request: Request) {
  const rateLimit = consumeRateLimit(getClientRateLimitKey(request));
  const headers = buildRateLimitHeaders(rateLimit);
  const declaredBodyLength = Number(request.headers.get("content-length") ?? "0");

  if (!rateLimit.ok) {
    return NextResponse.json(
      {
        error: "Demasiadas solicitudes. Espera unos minutos antes de volver a intentar.",
      },
      {
        status: 429,
        headers,
      },
    );
  }

  if (Number.isFinite(declaredBodyLength) && declaredBodyLength > maxAnalyzeBodyBytes) {
    return NextResponse.json(
      {
        error: "La solicitud es demasiado grande para este analisis.",
      },
      {
        status: 413,
        headers,
      },
    );
  }

  let body: unknown;

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      {
        error: "El cuerpo de la solicitud no tiene JSON valido.",
      },
      {
        status: 400,
        headers,
      },
    );
  }

  const parsedInput = analyzeInputSchema.safeParse(body);

  if (!parsedInput.success) {
    const firstIssue = parsedInput.error.issues[0];

    return NextResponse.json(
      {
        error: firstIssue?.message || "La entrada no es valida.",
      },
      {
        status: 400,
        headers,
      },
    );
  }

  try {
    const result = await analyzeSubmission(parsedInput.data);

    return NextResponse.json(result, {
      status: 200,
      headers,
    });
  } catch (error) {
    console.error("No se pudo completar el analisis.", error);

    return NextResponse.json(
      {
        error: "No pudimos analizar el caso en este momento. Intenta nuevamente en unos minutos.",
      },
      {
        status: 500,
        headers,
      },
    );
  }
}
