# Debugging Improvements for Tool Call Errors

## Changes Made

### 1. Enhanced Tool Call Error Logging

Added detailed logging when tool calls fail due to malformed or missing arguments:

#### For `web_search` with empty query:
- Logs when empty query is detected
- Shows the parsed arguments dictionary
- Shows the raw JSON arguments string

#### For `fetch_url` with empty URL:
- Logs when empty URL is detected  
- Shows the parsed arguments dictionary
- Shows the raw JSON arguments string

#### For JSON parsing failures:
- Catches and logs JSON parse exceptions
- Shows the raw arguments that failed to parse

#### For unknown tools:
- Logs when an unrecognized tool is called
- Shows the raw arguments passed to the unknown tool

### 2. Improved Progress Display

Enhanced the `[progress]` log output to be more readable:

**Before:**
```
[progress] sig='web_search:ERROR: empty query.|web_search:1. GitHub Action tj-actions/changed-files, Supply-Chai', stalls=0
```

**After:**
```
[progress] recent_tools=[web_search:❌ERROR: empty query., web_search:✓, fetch_url:✓] stalls=0
[progress] signature='web_search:ERROR: empty query.|web_search:1. GitHub Action tj-actions/changed-files, Supply-Chain Attacks...|fetch_url:Title: ...'
```

### Benefits

1. **Root Cause Analysis**: When you see empty query errors, you can now see exactly what the LLM sent
2. **Pattern Detection**: Easier to spot if the LLM is consistently making the same mistake
3. **Visual Clarity**: Check marks (✓) and X marks (❌) make it easy to see which tools succeeded vs failed
4. **Full Context**: Both summarized and full signature views help understand the tool call sequence

### Usage

These improvements only appear when running with debug mode enabled (typically via `--debug` flag or `debug=True` parameter).

## Example Output

When a malformed tool call occurs, you'll now see:

```
[tool_call_error] web_search called with empty query
[tool_call_error] Parsed args: {}
[tool_call_error] Raw arguments: '{}'
[progress] recent_tools=[web_search:❌ERROR: empty query., fetch_url:✓, web_search:✓] stalls=0
[progress] signature='web_search:ERROR: empty query.|fetch_url:Title: CVE-2023-1234|web_search:1. Github Advisory'
```

This clearly shows:
- The tool that failed (`web_search`)
- Why it failed (empty query)
- What arguments were sent (empty JSON object)
- The sequence of recent tool calls
- Whether the agent is stalling (making repeated failed calls)
