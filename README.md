# Patch Finder

Patch Finder is an LLM-assisted workflow that locates upstream fix commits for CVEs by orchestrating public data sources such as GitHub Security Advisories, OSV, and NVD. The agent relies on a local vLLM deployment of the `openai/gpt-oss-20b` model and enriches LLM output with targeted web and HTML scraping helpers.

## Prerequisites

- Python 3.12+ environment with the following packages installed:
  - `openai`
  - `httpx`
  - `beautifulsoup4`
  - `readability-lxml`
  - `pydantic`
- A local vLLM server hosting `openai/gpt-oss-20b`. This server need to have at least RTX 4090 or more powerful GPU. 

## Environment variables

Set the variables below before running the agent. Without these variable the agent won't work correctly! 

```bash
export OPENAI_API_KEY="local"               # arbitrary value; vLLM ignores it but the SDK requires one
export OPENAI_BASE_URL="http://localhost:8000/v1"  # matches the vLLM OpenAI-compatible endpoint
export GOOGLE_CSE_ID="<your Google CSE ID>"
export GOOGLE_API_KEY="<your Google API key>"
```

Optional overrides:

- `PATCH_FINDER_MODEL` (default `openai/gpt-oss-20b`)
- `PATCH_FINDER_MAX_STEPS` (default `30`)
- `PATCH_FINDER_MAX_TOKENS` (default `1024`)
- `PATCH_FINDER_TOP_P` (default `1.0`)
- `PATCH_FINDER_MAX_CONTEXT_CHARS` (default `48000`)

## Run vLLM with GPT-OSS

Launch vLLM with the OpenAI-compatible server so the agent can reach it through the standard OpenAI SDK. Example command (run in WSL or Linux shell):

```bash
vllm serve openai/gpt-oss-20b \
  --dtype auto \
  --enforce-eager \
  --host 0.0.0.0 \
  --port 8000 \
  --tool-call-parser openai \
  --reasoning-parser openai_gptoss \
  --enable-auto-tool-choice
```

Adjust `--host`/`--port` as needed and ensure the server matches the URL set in `OPENAI_BASE_URL`.

## Usage

Run the CLI to triage a CVE:

```bash
python agent.py CVE-2025-0762 --steps 40 --debug
```

- `--steps` controls the maximum number of LLM/tool interaction rounds (defaults to 30).
- `--debug` prints detailed tool and retry diagnostics; omit it for quieter output.

The agent prints either a validated success payload (`SuccessOut`) with commit coordinates or a structured error payload (`ErrorOut`).
