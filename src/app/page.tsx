import { ScamDetectorApp } from "@/components/scam-detector-app";

const notes = [
  {
    title: "Texto o link",
    description: "Puedes analizar un mensaje, un link o las dos cosas juntas, y ver por separado que aporto cada parte.",
  },
  {
    title: "Base local",
    description: "La app ya funciona con reglas propias aunque no haya API key, con foco en que el analisis local sea util de verdad.",
  },
  {
    title: "Modo visible",
    description: "El resultado indica si fue solo local o si se sumo una segunda lectura.",
  },
];

export default function Home() {
  return (
    <main className="min-h-screen">
      <div className="mx-auto w-full max-w-6xl px-4 py-10 sm:px-6 lg:px-8 lg:py-14">
        <header className="max-w-4xl border-b border-stone-800 pb-8">
          <p className="text-xs font-mono uppercase tracking-[0.24em] text-stone-500">
            Es Estafa?
          </p>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight text-stone-100 sm:text-5xl">
            Revisa mensajes y links sospechosos antes de responder, pagar o hacer clic.
          </h1>
          <p className="mt-4 max-w-3xl text-base leading-8 text-stone-400 sm:text-lg">
            La pagina prioriza una lectura clara desde el analisis local. Revisa el texto, la
            estructura del dominio, la vista previa segura del destino y la coherencia entre la
            marca mencionada y el dominio real. Si despues se suma una segunda lectura, queda
            indicada aparte en el resultado.
          </p>
        </header>

        <section className="grid gap-5 border-b border-stone-800 py-6 sm:grid-cols-3">
          {notes.map((note) => (
            <div key={note.title}>
              <p className="text-sm font-semibold text-stone-100">{note.title}</p>
              <p className="mt-2 text-sm leading-7 text-stone-400">{note.description}</p>
            </div>
          ))}
        </section>

        <div className="pt-8">
          <ScamDetectorApp />
        </div>
      </div>
    </main>
  );
}
