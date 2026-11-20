import { P, S, V, type CatalogEntry } from "../types";

/**
 * AI products. An entry with `f` is one of the product families of
 * lib/products.ts: records and KEV entries whose product name maps to the
 * family belong to it, and its key is the family label's slug, the key those
 * picks have always had. The catalog adds any family this list misses
 * (lib/catalog/index.ts), so a new family rule cannot fall out of My stack.
 */
export const AI: CatalogEntry[] = [
  /* ---------- model makers and assistants ---------- */
  V("openai", "OpenAI", "ai", { pop: true, t: ["(?<!azure )openai"], was: ["openai-models", "gpt-5-6", "openai-operator"] }),
  P("chatgpt", "ChatGPT", "openai", "ai", { pop: true, t: ["chatgpt"] }),
  P("openai-api", "OpenAI API and models", "openai", "ai", { t: ["openai api", "openai models?", "openai assistants api", "openai operator", "gpt-\\d[a-z0-9.]*"], aka: ["gpt"] }),
  P("openai-codex", "OpenAI Codex", "openai", "ai", { f: "OpenAI Codex", x: ["openai codex", "codex cli"] }),
  V("anthropic", "Anthropic", "ai", { pop: true }),
  P("claude", "Claude", "anthropic", "ai", { pop: true, t: ["claude(?! code)"] }),
  P("claude-code-sdks", "Claude Code and SDKs", "anthropic", "ai", { pop: true, f: "Claude Code + SDKs", was: ["claude-code-extension"], x: ["claude code"], c: ["claude code (?:is|before|\\d+)", "^claude code"] }),
  S("claude-code-ui", "Claude Code UI (CloudCLI)", "siteboon", "ai", { f: "Claude Code UI" }),
  S("mistral", "Mistral AI", "Mistral AI", "ai", { t: ["mistral ai", "mistral (?:large|small|medium|api)", "le chat"] }),
  S("deepseek", "DeepSeek", "DeepSeek", "ai"),
  S("grok", "Grok (xAI)", "xAI", "ai", { t: ["grok", "xai"] }),
  S("perplexity", "Perplexity", "Perplexity", "ai", { t: ["perplexity"], x: ["perplexity (?:ai|comet|browser|assistant)", "perplexity's"] }),
  S("cohere", "Cohere", "Cohere", "ai", { t: ["cohere"], x: ["cohere (?:ai|api|models?|command)"] }),
  S("elevenlabs", "ElevenLabs", "ElevenLabs", "ai"),
  S("fireworks-ai", "Fireworks AI", "Fireworks AI", "ai", { t: ["fireworks ai", "fireworks\\.ai"] }),
  S("openrouter", "OpenRouter", "OpenRouter", "ai"),
  S("replicate", "Replicate", "Replicate", "ai", { t: ["^replicate$", "replicate\\.com"], x: ["replicate\\.com"] }),

  /* ---------- coding assistants and agents ---------- */
  S("cursor", "Cursor", "Anysphere", "ai", { pop: true, t: ["cursor ai", "cursor ide", "cursor editor", "^cursor$"], x: ["cursor (?:ai|ide|editor|agent)"], c: ["^cursor is a code editor", "cursor (?:ide|editor) (?:before|\\d+)"] }),
  S("windsurf", "Windsurf", "Windsurf", "ai", { f: "Windsurf" }),
  S("opencode", "OpenCode", "OpenCode", "ai", { was: ["opencode-console"], t: ["opencode"] }),
  S("cline", "Cline and Roo Code", "Cline", "ai", { t: ["^cline$", "roo[- ]code", "cline (?:extension|agent)"], x: ["roo[- ]code", "cline (?:extension|agent)"] }),
  S("openclaw", "OpenClaw", "OpenClaw", "ai", { t: ["openclaw", "clawdbot", "moltbot"] }),
  S("warp", "Warp", "Warp", "ai", { was: ["warp-agentic-development-environment"], t: ["^warp$", "warp terminal", "warp agentic development environment"], x: ["warp terminal"] }),
  S("replit", "Replit", "Replit", "ai"),
  S("lovable", "Lovable", "Lovable", "ai", { t: ["^lovable$", "lovable\\.dev"], x: ["lovable\\.dev", "lovable (?:ai|apps?|platform)"] }),
  S("browser-use", "Browser Use", "Browser Use", "ai", { f: "Browser Use" }),
  S("crewai", "CrewAI", "CrewAI", "ai", { t: ["crewai", "crew ai"] }),
  S("agno", "Agno", "Agno", "ai", { f: "Agno" }),
  S("5ire", "5ire", "5ire", "ai", { f: "5ire" }),

  /* ---------- Model Context Protocol ---------- */
  S("mcp-servers-tools", "MCP servers and tools", "various", "ai", { pop: true, f: "MCP servers & tools", x: ["mcp servers?", "model context protocol"], aka: ["model context protocol", "mcp"] }),
  S("mcp-sdks", "MCP SDKs", "Model Context Protocol", "ai", { f: "MCP SDKs" }),
  S("fastmcp", "FastMCP", "FastMCP", "ai", { f: "FastMCP" }),

  /* ---------- running and serving models ---------- */
  S("ollama", "Ollama", "Ollama", "ai", { pop: true, f: "Ollama", x: ["ollama"] }),
  S("llama-cpp", "llama.cpp", "ggml", "ai", { f: "llama.cpp", x: ["llama\\.cpp"] }),
  S("vllm", "vLLM", "vLLM", "ai", { f: "vLLM", x: ["vllm(?!-orchestrator)"] }),
  S("sglang", "SGLang", "SGLang", "ai"),
  S("gpustack", "GPUStack", "GPUStack", "ai", { kv: ["GPUStack"], t: ["gpustack"] }),
  S("lm-studio", "LM Studio", "LM Studio", "ai"),
  S("localai", "LocalAI", "LocalAI", "ai"),
  S("litellm", "LiteLLM", "BerriAI", "ai", { pop: true, f: "LiteLLM", kv: ["BerriAI"], was: ["berriai"], x: ["litellm"] }),
  S("hugging-face-libraries", "Hugging Face", "Hugging Face", "ai", { pop: true, f: "Hugging Face libraries", x: ["hugging ?face"], aka: ["transformers", "huggingface"] }),
  S("mlflow", "MLflow", "MLflow", "ai", { kv: ["MLflow"], t: ["mlflow"] }),
  S("ray", "Ray (Anyscale)", "Anyscale", "ai", { kv: ["Ray-Project"], was: ["ray-project"], t: ["^ray$", "ray framework", "anyscale", "shadowray"], x: ["anyscale", "ray (?:framework|cluster|dashboard)", "shadowray"] }),
  S("kubeflow", "Kubeflow", "Kubeflow", "ai"),
  S("bentoml", "BentoML", "BentoML", "ai"),
  S("onnx", "ONNX", "ONNX", "ai", { t: ["onnx"] }),
  S("h2o", "H2O.ai", "H2O.ai", "ai", { t: ["h2o\\.ai", "h2o-3", "h2ogpt"] }),
  S("clearml", "ClearML", "ClearML", "ai"),
  S("marimo", "marimo", "marimo", "ai", { kv: ["Marimo"], t: ["marimo"] }),

  /* ---------- chat front ends and app builders ---------- */
  S("open-webui", "Open WebUI", "Open WebUI", "ai", { pop: true, f: "Open WebUI", x: ["open[- ]?webui"] }),
  S("anythingllm", "AnythingLLM", "Mintplex Labs", "ai", { f: "AnythingLLM", x: ["anything-?llm"] }),
  S("librechat", "LibreChat", "LibreChat", "ai"),
  S("lobe-chat", "Lobe Chat", "LobeHub", "ai", { f: "Lobe Chat", x: ["lobe[- ]?chat", "lobehub"] }),
  S("nextchat", "NextChat", "NextChat", "ai", { t: ["nextchat", "chatgpt-next-web"] }),
  S("lollms", "LoLLMs", "LoLLMs", "ai", { f: "LoLLMs" }),
  S("chuanhuchatgpt", "ChuanhuChatGPT", "ChuanhuChatGPT", "ai", { f: "ChuanhuChatGPT" }),
  S("gpt-academic", "GPT Academic", "GPT Academic", "ai", { f: "GPT Academic" }),
  S("dify", "Dify", "LangGenius", "ai", { f: "Dify", x: ["dify"] }),
  S("flowise", "Flowise", "FlowiseAI", "ai", { f: "Flowise", x: ["flowise"] }),
  S("langflow", "Langflow", "Langflow", "ai", { pop: true, f: "Langflow", x: ["langflow"] }),
  S("ragflow", "RAGFlow", "InfiniFlow", "ai"),
  S("fastgpt", "FastGPT", "FastGPT", "ai"),
  S("gradio", "Gradio", "Hugging Face", "ai", { f: "Gradio" }),
  S("streamlit", "Streamlit", "Snowflake", "ai"),
  S("comfyui-custom-nodes", "ComfyUI", "ComfyUI", "ai", { f: "ComfyUI + custom nodes", x: ["comfyui"] }),
  S("stable-diffusion-webui", "Stable Diffusion WebUI", "AUTOMATIC1111", "ai", { f: "Stable Diffusion WebUI", aka: ["automatic1111"] }),

  /* ---------- frameworks and stores ---------- */
  S("langchain-family", "LangChain, LangGraph and LangSmith", "LangChain", "ai", { pop: true, f: "LangChain family", x: ["langchain(?!4j|go|-chatchat)", "langgraph", "langsmith"], aka: ["langgraph", "langsmith"] }),
  S("langchain4j", "LangChain4j", "LangChain4j", "ai", { f: "LangChain4j" }),
  S("langchain-chatchat", "Langchain-Chatchat", "Chatchat", "ai", { f: "Langchain-Chatchat" }),
  S("llamaindex", "LlamaIndex", "LlamaIndex", "ai", { f: "LlamaIndex", x: ["llama[-_ ]?index"] }),
  S("guardrails-ai", "Guardrails AI", "Guardrails AI", "ai", { f: "Guardrails AI" }),
  S("langfuse", "Langfuse", "Langfuse", "ai"),
  S("weaviate", "Weaviate", "Weaviate", "ai", { f: "Weaviate" }),
  S("qdrant", "Qdrant", "Qdrant", "ai"),
  S("milvus", "Milvus", "Zilliz", "ai"),
  S("chromadb", "Chroma", "Chroma", "ai", { t: ["chromadb", "chroma db", "^chroma$"], x: ["chromadb", "chroma db"] }),
  S("pinecone", "Pinecone", "Pinecone", "ai"),
];
