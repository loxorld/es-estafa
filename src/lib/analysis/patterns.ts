export const urgencyPatterns = [
  /\burgente\b/i,
  /\bde inmediato\b/i,
  /\bhoy mismo\b/i,
  /\bultim[ao] aviso\b/i,
  /\b24 horas\b/i,
  /\bexpira\b/i,
  /\bdentro de las proximas?\s+\d+\s*(horas?|minutos?)\b/i,
  /\bantes del cierre\b/i,
  /\bantes de que\b/i,
  /\bnow\b/i,
  /\bimmediately\b/i,
  /\bfinal notice\b/i,
];

export const threatPatterns = [
  /\bbloquead[ao]\b/i,
  /\bsuspendid[ao]\b/i,
  /\bcancelad[ao]\b/i,
  /\binhabilitad[ao]\b/i,
  /\baccount locked\b/i,
  /\baccess denied\b/i,
  /\bvencid[ao]\b/i,
  /\bse desactivara\b/i,
];

export const credentialPatterns = [
  /\bcontrase(?:na|\u00f1a)\b/i,
  /\bpassword\b/i,
  /\bclave\b/i,
  /\bpin\b/i,
  /\botp\b/i,
  /\bcvv\b/i,
  /\btoken\b/i,
  /\bc[o\u00f3]digo(?:\s+de)?\s+(?:verificaci[o\u00f3]n|seguridad|confirmaci[o\u00f3]n)\b/i,
  /\bverific[a\u00e1] tu cuenta\b/i,
];

export const paymentPatterns = [
  /\btransfer(?:encia|ir)\b/i,
  /\bmercado pago\b/i,
  /\bpago pendiente\b/i,
  /\bwallet\b/i,
  /\bcripto\b/i,
  /\bcrypto\b/i,
  /\bdep[o\u00f3]sito\b/i,
  /\bdeposit\b/i,
  /\bfactura\b/i,
  /\binvoice\b/i,
  /\bgift card\b/i,
];

export const rewardPatterns = [
  /\bganaste\b/i,
  /\bpremio\b/i,
  /\bsorteo\b/i,
  /\bbeneficio exclusivo\b/i,
  /\bwinner\b/i,
  /\bclaim now\b/i,
];

export const secrecyPatterns = [
  /\bno compartas esto\b/i,
  /\bmantenelo en secreto\b/i,
  /\bno lo hables con nadie\b/i,
  /\bsolo por hoy\b/i,
  /\baprovecha ya\b/i,
];

export const actionPatterns = [
  /\bhaz clic\b/i,
  /\bclick\b/i,
  /\bingresa\b/i,
  /\bentra\b/i,
  /\baccede\b/i,
  /\bverifica\b/i,
  /\bvalida\b/i,
  /\bactualiza\b/i,
  /\bconfirma\b/i,
  /\bpaga\b/i,
  /\breclama\b/i,
  /\bdescarga\b/i,
];

export const impersonationPatterns = [
  /\btu banco\b/i,
  /\barea de seguridad\b/i,
  /\bafip\b/i,
  /\bcorreo argentino\b/i,
  /\bmercado libre\b/i,
  /\bmercado pago\b/i,
  /\bwhatsapp\b/i,
  /\bnetflix\b/i,
  /\bpaypal\b/i,
  /\bamazon\b/i,
  /\bapple\b/i,
  /\bgmail\b/i,
  /\bgoogle\b/i,
];

export type BrandProfile = {
  name: string;
  patterns: RegExp[];
  domainHints: string[];
};

export const brandProfiles: BrandProfile[] = [
  {
    name: "Mercado Pago",
    patterns: [/\bmercado pago\b/i],
    domainHints: ["mercadopago.com", "mercadopago.com.ar"],
  },
  {
    name: "Mercado Libre",
    patterns: [/\bmercado libre\b/i],
    domainHints: ["mercadolibre.com", "mercadolibre.com.ar"],
  },
  {
    name: "WhatsApp",
    patterns: [/\bwhatsapp\b/i],
    domainHints: ["whatsapp.com"],
  },
  {
    name: "Netflix",
    patterns: [/\bnetflix\b/i],
    domainHints: ["netflix.com"],
  },
  {
    name: "PayPal",
    patterns: [/\bpaypal\b/i],
    domainHints: ["paypal.com"],
  },
  {
    name: "Amazon",
    patterns: [/\bamazon\b/i],
    domainHints: ["amazon.com"],
  },
  {
    name: "Apple",
    patterns: [/\bapple\b/i, /\bicloud\b/i],
    domainHints: ["apple.com", "icloud.com"],
  },
  {
    name: "Google",
    patterns: [/\bgoogle\b/i, /\bgmail\b/i],
    domainHints: ["google.com", "gmail.com"],
  },
  {
    name: "Microsoft",
    patterns: [/\bmicrosoft\b/i, /\boutlook\b/i, /\bhotmail\b/i],
    domainHints: ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
  },
  {
    name: "AFIP",
    patterns: [/\bafip\b/i],
    domainHints: ["afip.gob.ar"],
  },
  {
    name: "Correo Argentino",
    patterns: [/\bcorreo argentino\b/i],
    domainHints: ["correoargentino.com.ar"],
  },
];
