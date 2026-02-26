# capa Rule Generation Agent — PoC

A proof-of-concept autonomous agent that generates [capa](https://github.com/mandiant/capa) rules from GitHub issues.
Built as a GSoC 2026 proposal demonstrator for Mandiant FLARE.

[![CI](https://github.com/reyyanxahmed/capa-rule-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/reyyanxahmed/capa-rule-agent/actions)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent Pipeline                          │
│                                                              │
│  ┌──────────┐  ┌───────────┐  ┌────────────┐  ┌──────────┐ │
│  │  Trigger  │─▶│ Grounding │─▶│ Generator  │─▶│Validator │ │
│  │  (Issue   │  │ (RAG over │  │ (Gemini +  │  │(Lint +   │ │
│  │  Parser)  │  │ capa-rules│  │ Few-shot)  │  │ Format)  │ │
│  └──────────┘  └───────────┘  └────────────┘  └──────────┘ │
│        │              │              │              │         │
│        ▼              ▼              ▼              ▼         │
│  Context from   Top-K similar   Generated      Validated     │
│  GitHub Issue   rules as        YAML rule      rule + PR     │
│  + ATT&CK map   grounding                     description    │
│                                      ▲              │         │
│                                      └──────────────┘         │
│                                    Self-correction loop       │
└─────────────────────────────────────────────────────────────┘
```

## Components

| Module | File | Description |
|--------|------|-------------|
| **Trigger** | `src/trigger.py` | Parses capa-rules GitHub issues → structured `IssueContext` (ATT&CK IDs, hashes, references, decompilation) |
| **Grounding** | `src/grounding.py` | **RAG over 650+ capa rules** — indexes by namespace, ATT&CK ID, and keywords; retrieves top-K similar rules as few-shot context |
| **Generator** | `src/generator.py` | Gemini-powered rule generation with system prompt teaching capa rule format, grounded by retrieved examples |
| **Validator** | `src/validator.py` | Multi-stage validation: YAML syntax → schema check → capa linter → capa formatter |
| **Pipeline** | `src/pipeline.py` | Orchestrates trigger → ground → generate → validate → self-correct loop |

## Quick Start

```bash
# Clone with capa-rules for grounding
git clone https://github.com/mandiant/capa-rules.git ../capa-rules

# Install dependencies
pip install -r requirements.txt

# Run with Gemini (set API key)
export GOOGLE_API_KEY="your-key-here"
python -m src.pipeline --issue-url https://github.com/mandiant/capa-rules/issues/1114

# Run offline (template generation, no API call)
python -m src.pipeline --description "Detect persistence via ShellServiceObjectDelayLoad" --offline
```

## Demo: RAG Grounding in Action

When given the query "Detect persistence via Windows service creation T1543.003", the grounding module retrieves:

```
Top 5 results for 'Windows service persistence':
  [12.5] persistence/service/persist via Windows service
  [ 6.5] persistence/service/persist via rc script
  [ 6.0] host-interaction/service/continue service
  [ 6.0] host-interaction/service/create/create service
  [ 6.0] host-interaction/service/delete/delete service
```

These real rules are injected into the LLM prompt as few-shot examples, ensuring generated rules follow the exact capa syntax and style conventions.

## Example Output

See `examples/` for generated rules. Here's a sample for [issue #1114](https://github.com/mandiant/capa-rules/issues/1114):

```yaml
rule:
  meta:
    name: persist via ShellServiceObjectDelayLoad
    namespace: persistence/registry
    authors:
      - gsoc-agent@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]
    references:
      - https://blog.virustotal.com/2024/03/com-objects-hijacking.html
  features:
    - and:
      - or:
        - match: set registry value
        - number: 0x80000002 = HKEY_LOCAL_MACHINE
      - string: /Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad/i
```

## Testing

```bash
# Run all tests (35 tests)
python -m pytest tests/ -v

# Unit tests only
python -m pytest tests/test_agent.py -v

# Integration tests (requires capa-rules clone at ../capa-rules)
python -m pytest tests/test_integration.py -v
```

## How It Works

1. **Parse Issue**: Extract technique name, ATT&CK IDs, references, decompilation context from GitHub issue
2. **Ground with RAG**: Index 650+ existing capa rules → retrieve top-K most similar rules as few-shot examples
3. **Generate Rule**: Prompt Gemini with system instruction (capa format spec) + retrieved examples + issue context
4. **Validate**: Run `capa lint` and `capafmt` against the generated rule
5. **Self-Correct**: If validation fails, parse error messages and re-prompt with specific fix instructions
6. **Output**: Produce the final validated rule + formatted PR description

## Status

This is a working PoC demonstrating the core pipeline. The full GSoC project would extend this with:
- **Google ADK agent framework** integration (tool-use, multi-step reasoning)
- **Proactive triggers** — threat intel feed ingestion (MALPEDIA, MalwareBazaar) to identify uncovered techniques
- **Automated GitHub PR creation** — end-to-end from issue to merged PR
- **Semantic RAG** — vector embeddings over rules + ATT&CK descriptions for deeper retrieval
- **Sample analysis integration** — run capa on samples to validate generated rules against real malware
