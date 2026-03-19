'use client';

import { useState } from "react";

import type { AnalysisResult, LinkPreview } from "@/lib/analysis/types";

type ExampleCase = {
  title: string;
  message: string;
  link: string;
};

const exampleCases: ExampleCase[] = [
  {
    title: "Banco con apuro",
    message:
      "Hola, te escribimos del area de seguridad de tu banco. Detectamos un acceso no autorizado. Verifica tu cuenta dentro de las proximas 2 horas o sera suspendida.",
    link: "",
  },
  {
    title: "Premio con link",
    message:
      "Felicitaciones. Ganaste un beneficio exclusivo. Reclama hoy mismo completando tus datos y un codigo de validacion.",
    link: "https://example.com/login",
  },
  {
    title: "Caso tranquilo",
    message:
      "Hola, te paso el link del restaurante para ver el menu antes de ir esta noche. Si podes, confirma despues si te gusta.",
    link: "https://www.google.com",
  },
];

function formatDate(value: string) {
  return new Intl.DateTimeFormat("es-AR", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function riskCopy(riskLevel: AnalysisResult["riskLevel"]) {
  if (riskLevel === "alto") {
    return {
      label: "Alerta alta",
      eyebrow: "Yo frenaria antes de seguir",
      border: "border-red-500/80",
      bar: "bg-red-500",
      text: "text-red-300",
    };
  }

  if (riskLevel === "medio") {
    return {
      label: "Alerta media",
      eyebrow: "Hay motivos para revisar con cuidado",
      border: "border-amber-400/80",
      bar: "bg-amber-400",
      text: "text-amber-200",
    };
  }

  return {
    label: "Alerta baja",
    eyebrow: "No aparece una senal fuerte",
    border: "border-emerald-500/80",
    bar: "bg-emerald-500",
    text: "text-emerald-300",
  };
}

function aiStatusCopy(result: AnalysisResult) {
  if (result.aiStatus === "usada") {
    return {
      label: "Modo local + IA",
      description: result.aiMessage ?? "Se sumo una segunda lectura sobre el analisis local.",
      classes: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
    };
  }

  if (result.aiStatus === "cuota") {
    return {
      label: "Modo local",
      description:
        result.aiMessage ?? "La segunda lectura no estuvo disponible. Se muestra el resultado local.",
      classes: "border-amber-400/30 bg-amber-400/10 text-amber-100",
    };
  }

  if (result.aiStatus === "error") {
    return {
      label: "Modo local",
      description:
        result.aiMessage ?? "La segunda lectura fallo. Se muestra el resultado local.",
      classes: "border-red-500/30 bg-red-500/10 text-red-100",
    };
  }

  return {
    label: "Modo local",
    description: result.aiMessage ?? "Este resultado se hizo solo con el analisis local.",
    classes: "border-stone-700 bg-stone-900 text-stone-200",
  };
}

function verdictLabel(result: NonNullable<AnalysisResult["linkAssessment"]>) {
  if (result.verdict === "sospechoso") {
    return "Muy sospechoso";
  }

  if (result.verdict === "precaucion") {
    return "Para revisar";
  }

  return "Sin alertas fuertes";
}

function previewStatusLabel(preview: LinkPreview) {
  if (preview.status === "fetched") {
    return "Se pudo revisar el destino del link.";
  }

  if (preview.status === "blocked") {
    return "La vista previa se bloqueo por seguridad.";
  }

  if (preview.status === "failed") {
    return "No se pudo revisar el destino del link.";
  }

  return "No se intento abrir el destino.";
}

function breakdownLabel(key: "text" | "link" | "preview" | "final") {
  if (key === "text") {
    return "Texto";
  }

  if (key === "link") {
    return "Link";
  }

  if (key === "preview") {
    return "Destino";
  }

  return "Final";
}

export function ScamDetectorApp() {
  const [message, setMessage] = useState("");
  const [link, setLink] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message,
          link,
        }),
      });

      const payload = (await response.json()) as AnalysisResult | { error?: string };

      if (!response.ok) {
        setResult(null);
        setError(
          payload && "error" in payload ? payload.error || "No se pudo analizar." : "No se pudo analizar.",
        );
        return;
      }

      setResult(payload as AnalysisResult);
    } catch {
      setResult(null);
      setError("Error de red. Revisa que el servidor este corriendo e intenta de nuevo.");
    } finally {
      setIsSubmitting(false);
    }
  }

  function loadExample(example: ExampleCase) {
    setMessage(example.message);
    setLink(example.link);
    setError("");
    setResult(null);
  }

  function clearForm() {
    setMessage("");
    setLink("");
    setResult(null);
    setError("");
  }

  const activeRisk = result ? riskCopy(result.riskLevel) : null;
  const aiInfo = result ? aiStatusCopy(result) : null;
  const visibleWarnings = result
    ? result.warnings.filter(
        (warning, index, list) =>
          warning !== result.aiMessage &&
          list.findIndex((entry) => entry === warning) === index,
      )
    : [];

  return (
    <section className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_18rem]">
      <div className="border border-stone-800 bg-[#151311] shadow-[0_30px_80px_rgba(0,0,0,0.22)]">
        <div className="border-b border-stone-800 px-5 py-6 sm:px-8">
          <p className="text-xs font-mono uppercase tracking-[0.24em] text-stone-500">
            Analizador
          </p>
          <h2 className="mt-3 text-2xl font-semibold tracking-tight text-stone-100 sm:text-3xl">
            Pega un mensaje o un link y revisalo antes de confiar
          </h2>
          <p className="mt-3 max-w-2xl text-sm leading-7 text-stone-400 sm:text-base">
            El analisis base funciona con reglas locales y chequeos seguros del link. Si hay una
            segunda lectura disponible, se suma aparte. Si no, el resultado local igual queda
            completo y explicado.
          </p>
        </div>

        <div className="px-5 py-6 sm:px-8">
          <div className="border-b border-stone-800 pb-6">
            <p className="text-sm font-medium text-stone-100">Casos rapidos para probar</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {exampleCases.map((example) => (
                <button
                  key={example.title}
                  className="border border-stone-700 bg-[#1d1916] px-3 py-2 text-sm text-stone-300 transition hover:border-stone-500 hover:bg-[#26211d] hover:text-stone-100"
                  onClick={() => loadExample(example)}
                  type="button"
                >
                  {example.title}
                </button>
              ))}
            </div>
          </div>

          <form className="space-y-6 pt-6" onSubmit={handleSubmit}>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-100" htmlFor="message">
                Mensaje
              </label>
              <textarea
                className="min-h-44 w-full border border-stone-700 bg-[#0f0d0c] px-4 py-3 text-base text-stone-100 outline-none transition placeholder:text-stone-500 focus:border-amber-400 focus:bg-[#14110f]"
                id="message"
                maxLength={4000}
                onChange={(event) => setMessage(event.target.value)}
                placeholder="Ejemplo: detectamos un problema con tu cuenta. Entra al link y valida tus datos..."
                value={message}
              />
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-stone-500">
                <span>Puedes pegar un mail, SMS, chat o transcripcion.</span>
                <span>{message.length}/4000</span>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-100" htmlFor="link">
                Link
              </label>
              <input
                className="w-full border border-stone-700 bg-[#0f0d0c] px-4 py-3 text-base text-stone-100 outline-none transition placeholder:text-stone-500 focus:border-amber-400 focus:bg-[#14110f]"
                id="link"
                maxLength={2048}
                onChange={(event) => setLink(event.target.value)}
                placeholder="https://sitio-a-revisar.com"
                value={link}
              />
              <p className="text-xs leading-6 text-stone-500">
                Si dejas este campo vacio, igual se revisan los links que esten adentro del
                mensaje.
              </p>
            </div>

            <div className="flex flex-wrap gap-3">
              <button
                className="bg-amber-400 px-5 py-3 text-sm font-medium text-stone-950 transition hover:bg-amber-300 disabled:cursor-not-allowed disabled:bg-stone-600 disabled:text-stone-300"
                disabled={isSubmitting}
                type="submit"
              >
                {isSubmitting ? "Analizando..." : "Analizar"}
              </button>
              <button
                className="border border-stone-700 bg-[#1b1815] px-5 py-3 text-sm text-stone-300 transition hover:border-stone-500 hover:text-stone-100"
                onClick={clearForm}
                type="button"
              >
                Limpiar
              </button>
            </div>
          </form>

          {error ? (
            <div className="mt-6 border-l-2 border-red-500 bg-red-500/10 px-4 py-3 text-sm text-red-100">
              {error}
            </div>
          ) : null}

          {isSubmitting ? (
            <div className="mt-8 border border-stone-800 bg-[#0f0d0c] px-5 py-5">
              <div className="flex items-center gap-3">
                <span className="relative inline-flex h-3 w-3">
                  <span className="absolute inline-flex h-full w-full animate-ping bg-amber-400/60" />
                  <span className="relative inline-flex h-3 w-3 bg-amber-400" />
                </span>
                <p className="text-sm font-medium text-stone-100">Analizando el caso...</p>
              </div>
              <div className="mt-4 overflow-hidden border border-stone-800 bg-[#181513]">
                <div className="scan-line h-1.5 w-24 bg-amber-400" />
              </div>
              <div className="mt-4 grid gap-2 text-xs uppercase tracking-[0.18em] text-stone-500">
                <span>Revisando el texto</span>
                <span>Chequeando el link</span>
                <span>Armando el resultado</span>
              </div>
            </div>
          ) : null}

          {result && activeRisk && aiInfo ? (
            <div className="mt-8 border-t border-stone-800 pt-8">
              <div className={`border-l-4 px-4 ${activeRisk.border}`}>
                <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_13rem]">
                  <div className="max-w-3xl">
                    <p className={`text-xs font-mono uppercase tracking-[0.24em] ${activeRisk.text}`}>
                      {activeRisk.eyebrow}
                    </p>
                    <h3 className="mt-3 text-2xl font-semibold tracking-tight text-stone-100 sm:text-3xl">
                      {result.summary}
                    </h3>
                    <p className="mt-3 text-sm leading-7 text-stone-400 sm:text-base">
                      {result.explanation}
                    </p>
                  </div>

                  <div className="border border-stone-800 bg-[#11100f] px-4 py-4 text-right">
                    <p className="text-xs uppercase tracking-[0.18em] text-stone-500">Puntaje</p>
                    <p className="mt-2 text-3xl font-semibold text-stone-100">{result.riskScore}</p>
                  </div>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-xs leading-6 text-stone-500">
                <span>{activeRisk.label}</span>
                {result.riskScore >= 40 ? <span>Posible modalidad: {result.fraudType}</span> : null}
                {result.confidence !== null ? <span>Confianza del analisis: {result.confidence}%</span> : null}
                <span>Actualizado: {formatDate(result.generatedAt)}</span>
                <span>Entrada: {result.inputTypes.join(" + ")}</span>
              </div>

              <div className="mt-4 h-2 bg-stone-800">
                <div className={activeRisk.bar} style={{ height: "100%", width: `${result.riskScore}%` }} />
              </div>

              <div className={`mt-6 border px-4 py-4 text-sm ${aiInfo.classes}`}>
                <p className="font-medium">{aiInfo.label}</p>
                <p className="mt-2 leading-7">{aiInfo.description}</p>
              </div>

              <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,1fr)_18rem]">
                <section>
                  <h4 className="text-sm font-semibold text-stone-100">Por que levanto alerta</h4>
                  <ul className="mt-4 space-y-3 border-t border-stone-800 pt-4 text-sm leading-7 text-stone-300">
                    {result.suspiciousSignals.map((signal) => (
                      <li key={signal}>{signal}</li>
                    ))}
                  </ul>
                </section>

                <section>
                  <h4 className="text-sm font-semibold text-stone-100">Desglose del puntaje local</h4>
                  <dl className="mt-4 border-t border-stone-800 pt-4 text-sm text-stone-300">
                    {(["text", "link", "preview", "final"] as const).map((item) => (
                      <div
                        key={item}
                        className="flex items-center justify-between border-b border-stone-800/80 py-3 last:border-b-0"
                      >
                        <dt className="text-stone-400">{breakdownLabel(item)}</dt>
                        <dd className="font-medium text-stone-100">
                          {result.scoreBreakdown[item]}/100
                        </dd>
                      </div>
                    ))}
                  </dl>
                </section>
              </div>

              <section className="mt-8 border-t border-stone-800 pt-6">
                <h4 className="text-sm font-semibold text-stone-100">Que haria antes de seguir</h4>
                <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-300">
                  {result.recommendations.map((recommendation) => (
                    <li key={recommendation}>{recommendation}</li>
                  ))}
                </ul>
              </section>

              <section className="mt-8 border-t border-stone-800 pt-6">
                <h4 className="text-sm font-semibold text-stone-100">Evidencia usada</h4>
                <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-300">
                  {result.evidence.map((evidence) => (
                    <li key={evidence}>{evidence}</li>
                  ))}
                </ul>
              </section>

              {result.linkAssessment ? (
                <section className="mt-8 border-t border-stone-800 pt-6">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <h4 className="text-sm font-semibold text-stone-100">Chequeo del link</h4>
                      <p className="mt-2 max-w-3xl break-all font-mono text-xs leading-6 text-stone-500">
                        {result.linkAssessment.normalizedUrl}
                      </p>
                    </div>
                    <p className="text-sm text-stone-300">{verdictLabel(result.linkAssessment)}</p>
                  </div>

                  <dl className="mt-4 grid gap-4 border-t border-stone-800 pt-4 text-sm text-stone-300 sm:grid-cols-3">
                    <div>
                      <dt className="text-xs uppercase tracking-[0.18em] text-stone-500">Dominio</dt>
                      <dd className="mt-2 break-all">{result.linkAssessment.domain}</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-[0.18em] text-stone-500">Puntaje del link</dt>
                      <dd className="mt-2">{result.linkAssessment.score}/100</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-[0.18em] text-stone-500">Veredicto</dt>
                      <dd className="mt-2">{verdictLabel(result.linkAssessment)}</dd>
                    </div>
                  </dl>

                  {result.linkAssessment.flags.length > 0 ? (
                    <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-300">
                      {result.linkAssessment.flags.map((flag) => (
                        <li key={flag}>{flag}</li>
                      ))}
                    </ul>
                  ) : null}
                </section>
              ) : null}

              {result.linkPreview ? (
                <section className="mt-8 border-t border-stone-800 pt-6">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <h4 className="text-sm font-semibold text-stone-100">
                        Lo que se pudo ver del destino
                      </h4>
                      <p className="mt-2 text-sm text-stone-400">
                        {previewStatusLabel(result.linkPreview)}
                      </p>
                    </div>
                    {result.linkPreview.httpStatus ? (
                      <p className="text-sm text-stone-300">HTTP {result.linkPreview.httpStatus}</p>
                    ) : null}
                  </div>

                  {result.linkPreview.finalUrl ? (
                    <p className="mt-3 break-all font-mono text-xs leading-6 text-stone-500">
                      {result.linkPreview.finalUrl}
                    </p>
                  ) : null}

                  {result.linkPreview.title ? (
                    <p className="mt-4 text-sm font-medium text-stone-100">{result.linkPreview.title}</p>
                  ) : null}

                  {result.linkPreview.description ? (
                    <p className="mt-2 max-w-3xl text-sm leading-7 text-stone-300">
                      {result.linkPreview.description}
                    </p>
                  ) : null}

                  {result.linkPreview.pageSignals.length > 0 ? (
                    <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-300">
                      {result.linkPreview.pageSignals.map((signal) => (
                        <li key={signal}>{signal}</li>
                      ))}
                    </ul>
                  ) : null}

                  {result.linkPreview.notes.length > 0 ? (
                    <div className="mt-4 border-l-2 border-stone-700 pl-4">
                      <p className="text-xs uppercase tracking-[0.18em] text-stone-500">
                        Notas de la revision
                      </p>
                      <ul className="mt-3 space-y-3 text-sm leading-7 text-stone-300">
                        {result.linkPreview.notes.map((note) => (
                          <li key={note}>{note}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </section>
              ) : null}

              {result.detectedUrls.length > 0 ? (
                <section className="mt-8 border-t border-stone-800 pt-6">
                  <h4 className="text-sm font-semibold text-stone-100">Links detectados en la entrada</h4>
                  <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-300">
                    {result.detectedUrls.map((url) => (
                      <li key={url} className="break-all font-mono text-xs text-stone-500 sm:text-sm">
                        {url}
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}

              <section className="mt-8 border-t border-stone-800 pt-6">
                <h4 className="text-sm font-semibold text-stone-100">
                  Que chequeos hizo el sistema local
                </h4>
                <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-300">
                  {result.localChecks.map((check) => (
                    <li key={check}>{check}</li>
                  ))}
                </ul>
              </section>

              {visibleWarnings.length > 0 ? (
                <div className="mt-8 border-l-2 border-amber-400 bg-amber-400/10 px-4 py-3 text-sm text-amber-100">
                  {visibleWarnings.map((warning) => (
                    <p key={warning}>{warning}</p>
                  ))}
                </div>
              ) : null}

              <p className="mt-8 border-t border-stone-800 pt-4 text-xs leading-6 text-stone-500">
                {result.disclaimer}
              </p>
            </div>
          ) : null}
        </div>
      </div>

      <aside className="space-y-8 text-stone-300">
        <section className="border-t border-stone-600 pt-4">
          <p className="text-sm font-semibold text-stone-100">Como leer el resultado</p>
          <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-400">
            <li>El puntaje no es una sentencia: sirve para decidir si frenar y verificar.</li>
            <li>Lo mas importante no es el numero, sino de donde sale: texto, link y destino.</li>
            <li>Si algo parece real, igual conviene confirmar por un canal oficial aparte.</li>
          </ul>
        </section>

        <section className="border-t border-stone-800 pt-4">
          <p className="text-sm font-semibold text-stone-100">Que revisa en modo local</p>
          <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-400">
            <li>Urgencia real, premios, pedidos de claves, pagos y tono alarmista.</li>
            <li>Dominios raros, acortadores, HTTP, parametros sospechosos y links largos.</li>
            <li>Cuando es seguro, intenta mirar el destino del link para sumar contexto.</li>
            <li>Si una marca aparece en el texto o en la pagina, compara si el dominio coincide.</li>
          </ul>
        </section>

        <section className="border-t border-stone-800 pt-4">
          <p className="text-sm font-semibold text-stone-100">Que significa cada tramo</p>
          <ul className="mt-4 space-y-3 text-sm leading-7 text-stone-400">
            <li>`0-24`: no aparecieron alertas claras en esta pasada local.</li>
            <li>`25-39`: hay detalles menores y conviene revisar antes de confiar.</li>
            <li>`40-69`: ya hay suficientes señales para desconfiar y validar por otro canal.</li>
            <li>`70-100`: el caso junta varias señales fuertes de fraude o phishing.</li>
          </ul>
        </section>

        <section className="border-t border-stone-800 pt-4">
          <p className="text-sm font-semibold text-stone-100">Consejo rapido</p>
          <p className="mt-4 text-sm leading-7 text-stone-400">
            Si un mensaje te apura, te pide codigos, te habla de bloqueo o te manda a iniciar
            sesion desde un link, ya hay motivo suficiente para desconfiar un poco mas.
          </p>
        </section>
      </aside>
    </section>
  );
}
