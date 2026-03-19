# Es Estafa?

Aplicación web hecha con Next.js para revisar mensajes y links sospechosos antes de responder, pagar o hacer clic.

La idea principal del proyecto es usar IA para analizar el caso completo y devolver una lectura clara del riesgo. Además, la app incluye una base local de heurísticas y chequeos seguros para que el sistema siga siendo útil si la API no está disponible o falla.

## Qué hace

- Recibe un caso compuesto por mensaje, link o ambos.
- Cuando está configurada la API, envía el caso completo a OpenAI para obtener una evaluación estructurada.
- Analiza texto sospechoso: urgencia, amenazas de bloqueo, premios falsos, pedidos de claves, pagos y tono alarmista.
- Analiza links: protocolo, dominio, acortadores, puertos, guiones, TLDs de riesgo, parámetros y palabras sensibles.
- Intenta obtener una vista previa segura del destino cuando corresponde.
- Compara la marca mencionada en el mensaje o en la página con el dominio real.
- Devuelve un resultado explicado: puntaje, señales detectadas, evidencia, recomendaciones y desglose del score.
- Indica si el resultado salió solo del modo local o si se combinó con la capa de IA.

## Stack

- Next.js 16
- React 19
- TypeScript
- Tailwind CSS 4
- Zod
- OpenAI SDK para la capa de análisis con IA

## Enfoque del proyecto

El objetivo principal es que la app funcione con IA.

La capa de OpenAI ya está implementada en el proyecto y está pensada para:

- analizar el caso completo, no solo reformular heurísticas
- usar el mensaje original, el link y la vista previa segura del destino
- clasificar el tipo de fraude
- devolver explicación, evidencia, recomendaciones y score estructurado

El análisis local no reemplaza esa idea principal. Su rol es:

- servir como respaldo cuando no hay API key, cuota o respuesta válida
- aportar señales concretas y chequeos de seguridad sobre links
- darle base al sistema incluso cuando la capa externa no responde

## Modo local

El análisis local actúa como respaldo y soporte del sistema. No reemplaza la capa de IA, pero permite que la app siga funcionando y explicando el caso cuando la API no está disponible.

Actualmente revisa:

- urgencia real y presión para actuar rápido
- pedidos de contraseña, PIN, OTP, token, CVV o códigos
- intentos de suplantación de marcas o servicios conocidos
- pagos, transferencias, facturas, wallets y cripto
- dominios raros o poco confiables
- diferencias entre la marca mencionada y el dominio real
- señales básicas de phishing en la vista previa del destino

## Seguridad

La vista previa del link no abre cualquier cosa sin control. El sistema bloquea:

- `localhost`
- redes privadas o reservadas
- dominios internos como `.local`, `.internal` o `.lan`
- URLs con credenciales embebidas
- puertos no estándar
- contenido no textual cuando no aporta una vista previa útil

Además, la API incluye rate limiting simple en memoria para evitar abuso básico.

## Instalación

```bash
npm install
```

## Variables de entorno

La app funciona sin variables de entorno usando solo el análisis local, pero para activar la capa de IA necesitas configurar OpenAI.

Si quieres activar el análisis con IA, crea un archivo `.env.local`:

```env
OPENAI_API_KEY=tu_api_key
OPENAI_MODEL=gpt-4.1-mini
```

Puedes copiar la base desde [`.env.example`](./.env.example).

## Estado actual de la capa IA

La integración con OpenAI ya está implementada.

Incluye:

- cliente configurado desde variables de entorno
- envío estructurado del caso a OpenAI
- parseo tipado de la respuesta con Zod
- combinación del resultado de IA con señales locales
- fallback automático al modo local si no hay key, cuota o respuesta válida

En esta versión, la capa de IA no quedó validada a fondo con cuota real activa porque el proyecto se estuvo trabajando sin consumo pago, pero la estructura necesaria ya está en el código.

## Desarrollo

```bash
npm run dev
```

Luego abre [http://localhost:3000](http://localhost:3000).

## Scripts

```bash
npm run dev
npm run build
npm run start
npm run lint
```

## Estructura

```txt
src/
  app/
    api/analyze/route.ts
    globals.css
    layout.tsx
    page.tsx
  components/
    scam-detector-app.tsx
  lib/
    openai.ts
    rate-limit.ts
    analysis/
      link-preview.ts
      scam.ts
      types.ts
      url.ts
```

## API

### `POST /api/analyze`

Entrada:

```json
{
  "message": "texto opcional",
  "link": "link opcional"
}
```

Reglas:

- al menos uno de los dos campos debe estar presente
- si ambos están vacíos, devuelve error `400`
- si se supera el límite de solicitudes, devuelve `429`

## Cómo interpretar el resultado

- `riskScore`: puntaje final de 0 a 100
- `riskLevel`: `bajo`, `medio` o `alto`
- `suspiciousSignals`: señales que hicieron subir el riesgo
- `evidence`: fragmentos o datos concretos usados para decidir
- `recommendations`: pasos sugeridos antes de seguir
- `scoreBreakdown`: cuánto aportó el texto, el link y la vista previa del destino
- `aiStatus`: indica si se usó la capa de IA o si el sistema cayó al modo local

## Limitaciones actuales

- No consulta reputación externa de dominios.
- No integra Safe Browsing, VirusTotal ni bases de phishing.
- El rate limiting es en memoria, útil para desarrollo o demos, pero no para producción seria.
- La vista previa del destino es deliberadamente acotada para priorizar seguridad.

## Ideas para seguir

- historial de análisis
- exportar resultados
- más casos de prueba
- reputación externa de dominios
- análisis de capturas o imágenes
- deploy con Vercel

## Estado del proyecto

Versión inicial enfocada en portfolio y mi abuela, con la capa de IA ya integrada en la arquitectura y un modo local sólido como fallback para no depender por completo de la disponibilidad externa.
