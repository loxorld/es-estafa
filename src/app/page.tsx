import { ScamDetectorApp } from "@/components/scam-detector-app";

const notes = [
  {
    title: "Texto o link",
    description: "Puedes pegar un mensaje, un link o las dos cosas, y ver que peso tuvo cada parte.",
  },
  {
    title: "Doble lectura",
    description: "Hace una primera pasada propia y, si OpenAI responde, suma una lectura extra sobre el mismo caso.",
  },
  {
    title: "Rastro claro",
    description: "El resultado muestra de donde sale la alerta: texto, dominio, destino y evidencia concreta.",
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
            La app cruza lo que dice el mensaje, como esta armado el link y que devuelve el
            destino sin descargar la pagina completa. La idea es ayudarte a frenar a tiempo con un
            resultado entendible, no con humo.
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
