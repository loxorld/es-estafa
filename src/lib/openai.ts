import OpenAI from "openai";

const apiKey = process.env.OPENAI_API_KEY;

const client = apiKey
  ? new OpenAI({
      apiKey,
    })
  : null;

export function getOpenAIClient() {
  return client;
}

export function getOpenAIModel() {
  const configuredModel = process.env.OPENAI_MODEL?.trim();
  return configuredModel || "gpt-4.1-mini";
}
