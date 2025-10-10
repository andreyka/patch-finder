# Patch Finder

Patch Finder is an LLM-assisted workflow that locates upstream fix commits for CVEs by orchestrating public data sources such as GitHub Security Advisories, OSV, and NVD. The agent relies on a local vLLM deployment of the `openai/gpt-oss-20b` model and enriches LLM output with targeted web and HTML scraping helpers.

## How It Works

The agent uses a multi-step approach to find CVE fix commits:

1. **Bootstrap Phase**: Automatically fetches key sources (NVD, CVE.org, OSV, GHSA, Debian tracker) and extracts initial evidence including bug IDs, references, and potential commit URLs.

2. **Iterative Search**: The LLM agent analyzes the evidence and performs targeted web searches and URL fetches to locate:
   - Official bug tracker entries (GitHub Issues, Chromium bugs, kernel.org)
   - Security advisories and commit references
   - Source repository commits (GitHub, chromium.googlesource.com, git.kernel.org)

3. **Verification**: Cross-references findings across multiple authoritative sources to ensure accuracy.

4. **Extraction**: Extracts the full 40-character commit SHA-1 hash and constructs the complete commit URL.

The agent can handle CVEs from various ecosystems:
- **GitHub-based projects** (most npm, pip, Ruby packages)
- **Chromium/Chrome** (googlesource.com repositories)
- **Linux Kernel** (git.kernel.org, kernel mirrors)
- **OpenSSL and other projects** (git.openssl.org, GitLab, etc.)

## Important Limitations

**Success is not guaranteed** and depends on several factors:

1. **Information Availability**: The fix commit must be publicly documented in at least one of the checked sources (NVD, CVE.org, OSV, GHSA, vendor advisories, or search results).

2. **AI Model Behavior**: The agent is a thin client to an AI model with probabilistic behavior. The same CVE may succeed or fail across different runs depending on:
   - Information available in the internet 
   - Quality of search results returned by Google
   - Tool calling decisions made by the model
   - Hallucinations and any other potential mistakes that a model can make 

3. **Data Quality Issues**:
   - CVE records may lack commit references
   - Bug trackers may not link to commits
   - Commits may not mention the CVE identifier
   - Proprietary fixes may not be publicly disclosed

4. **Network Dependencies**: Requires access to external services (NVD, Google Custom Search API, GitHub, etc.). Network issues or rate limits may cause failures.

5. **Complex Repository Structures**: Some projects use non-standard workflows, mirrors, or private security fixes that are difficult to trace automatically.

**Recommendation**: Always manually verify the returned commit by reviewing the diff and confirming it addresses the vulnerability described in the CVE.

## Prerequisites

- Python 3.12+ with dependencies installed from `requirements.txt`
- A local vLLM server hosting `openai/gpt-oss-20b` (requires at least RTX 4090 or more powerful GPU)
- Google Cloud project with the Custom Search API enabled (for web search queries), there is a number of requests available free of charge every day.  

## How to use

1. Create a new Python environment and install all needed dependencies:

```bash
uv venv --python 3.12
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -r requirements.txt
```

2. Set the required environment variables:

```bash
export OPENAI_API_KEY="local"                      # arbitrary value; vLLM ignores it but the SDK requires one
export OPENAI_BASE_URL="http://localhost:8000/v1"  # matches the vLLM OpenAI-compatible endpoint
export GOOGLE_CSE_ID="<your Google CSE ID>"        # you can find it at https://programmablesearchengine.google.com/controlpanel/all
export GOOGLE_API_KEY="<your Google API key>"      # Google Cloud API Key for your project
export GITLAB_TOKEN="<your GitLab personal access token>"  # GitLab Personal Access Token with read_api scope
```
**Without these variables the agent won't work correctly!**

Optional overrides:

- `PATCH_FINDER_MODEL` (default `openai/gpt-oss-20b`)
- `PATCH_FINDER_MAX_STEPS` (default `60`)
- `PATCH_FINDER_MAX_TOKENS` (default `1024`)
- `PATCH_FINDER_TOP_P` (default `1.0`)
- `PATCH_FINDER_MAX_CONTEXT_CHARS` (default `48000`)


3. Launch vLLM with the OpenAI-compatible server so the agent can reach it through the standard OpenAI SDK. Example command (run in WSL or Linux shell):

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
   
   The provided `requirements.txt` already has all needed dependencies. If you want to configure your vLLM serving API on a different machine, install the server dependencies:
   
   ```bash
   uv pip install vllm openai httpx python-dotenv readability-lxml beautifulsoup4 lxml rapidfuzz pydantic tiktoken
   ``` 

4. Run the agent and request a patch for a vulnerability with CVE identifier:

```bash
python agent_runner.py CVE-2025-50182 --debug
```

- `--steps` controls the maximum number of LLM/tool interaction rounds (defaults to 60).
- `--debug` prints detailed tool and retry diagnostics; omit it for quieter output.

The agent prints either a validated success payload (`SuccessOut`) with commit coordinates or a structured error payload (`ErrorOut`).
