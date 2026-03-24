# Es Estafa?

App web para revisar mensajes y links sospechosos antes de responder, pagar o hacer clic.

La idea es simple: hacer una primera pasada propia sobre el texto y el link, y cuando OpenAI esta disponible, sumar una lectura extra sobre ese mismo caso. El foco no esta en tirar un numero porque si, sino en mostrar por que algo levanta alerta.

## Que hace

- acepta mensaje, link o ambos
- detecta senales tipicas de phishing, urgencia, premios falsos, pedidos de claves y pagos
- revisa la estructura del link: dominio, protocolo, acortadores, parametros y palabras sensibles
- hace una inspeccion segura del destino usando redirects controlados y `HEAD`, sin bajar la pagina completa
- compara la marca que aparece en el texto o en el destino con el dominio real
- devuelve puntaje, explicacion, evidencia y recomendaciones
- indica si el resultado quedo solo con la revision base o si se sumo la lectura con IA

## Stack

- Next.js 16
- React 19
- TypeScript
- Tailwind CSS 4
- Zod
- OpenAI SDK
- Vitest

## Como corre

```bash
npm install
npm run dev
```

Luego abre [http://localhost:3000](http://localhost:3000).

## Variables de entorno

La app puede funcionar sin variables de entorno, pero para activar la lectura con OpenAI necesitas un `.env.local` con esto:

```env
OPENAI_API_KEY=tu_api_key
OPENAI_MODEL=gpt-4.1-mini
```

La base esta en [`.env.example`](./.env.example).

## Scripts

```bash
npm run dev
npm run build
npm run start
npm run lint
npm run typecheck
npm run test
```

## Seguridad

La vista previa del link no abre cualquier cosa sin control. Se bloquean:

- `localhost`
- redes privadas o reservadas
- dominios internos como `.local`, `.internal` o `.lan`
- URLs con credenciales embebidas
- puertos no estandar
- esquemas no web o ejecutables

La inspeccion segura no descarga el body remoto. Solo mira redirecciones, URL final y headers expuestos por `HEAD`.

## API

`POST /api/analyze`

```json
{
  "message": "texto opcional",
  "link": "link opcional"
}
```

Reglas:

- al menos uno de los dos campos tiene que estar presente
- si ambos vienen vacios, devuelve `400`
- si se supera el limite de solicitudes, devuelve `429`

## Notas

- si OpenAI no responde, el sistema cae a la revision base
- el rate limiting sigue siendo en memoria
- no hay reputacion externa de dominios ni integracion con Safe Browsing o VirusTotal

## Estado

Es un proyecto personal, pensado para resolver un problema concreto y explicarlo bien. La parte de OpenAI esta integrada en la app, pero la revision base tambien se banca sola cuando la API no esta disponible.
