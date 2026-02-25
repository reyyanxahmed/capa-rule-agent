# capa Rule Generation Agent — PoC

A proof-of-concept autonomous agent that generates [capa](https://github.com/mandiant/capa) rules from GitHub issues.
Built as a GSoC 2026 proposal demonstrator for Mandiant FLARE.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Pipeline                         │
│                                                           │
│  ┌──────────┐   ┌────────────┐   ┌──────────────────┐   │
│  │  Trigger  │──▶│ Generator  │──▶│   Validator       │   │
│  │  (Issue   │   │ (LLM +    │   │   (Lint + Test    │   │
│  │  Parser)  │   │ Grounding) │   │   + Self-Correct) │   │
│  └──────────┘   └────────────┘   └──────────────────┘   │
│        │                                    │             │
│        ▼                                    ▼             │
│  Context from                        Valid YAML Rule      │
│  GitHub Issue                        + PR Description     │
│  + ATT&CK Mapping                                        │
└─────────────────────────────────────────────────────────┘
```

## Components

1. **Trigger** (`src/trigger.py`): Parses capa-rules GitHub issues to extract context (technique description, ATT&CK IDs, references, sample hashes)
2. **Generator** (`src/generator.py`): Uses Gemini via Google ADK to generate valid capa YAML rules, grounded with API documentation
3. **Validator** (`src/validator.py`): Runs capa linter/formatter, parses errors, and feeds corrections back to the generator
4. **Pipeline** (`src/pipeline.py`): Orchestrates the end-to-end flow with retry logic

## Quick Start

```bash
# Set your Gemini API key
export GOOGLE_API_KEY="your-key-here"

# Install dependencies
pip install -r requirements.txt

# Run against a capa-rules issue
python -m src.pipeline --issue-url https://github.com/mandiant/capa-rules/issues/1114

# Run with a local issue description
python -m src.pipeline --description "Detect persistence via ShellServiceObjectDelayLoad registry key"
```

## How It Works

1. **Parse Issue**: Extract technique name, ATT&CK IDs, references, and any decompilation/sample context
2. **Ground with Knowledge**: Use RAG over capa rule examples + Google Search for API documentation
3. **Generate Rule**: Prompt Gemini to produce a valid capa YAML rule following the official format
4. **Validate**: Run `capa lint` and `capafmt` against the generated rule
5. **Self-Correct**: If validation fails, parse error messages and re-prompt with specific fixes
6. **Output**: Produce the final rule + a formatted PR description

## Status

This is a minimal PoC demonstrating the core pipeline. The full GSoC project would extend this with:
- Google ADK agent framework integration
- Proactive triggers (threat intel feed ingestion)
- Automated GitHub PR creation
- Comprehensive grounding with RAG over ATT&CK, MSDN, and existing capa-rules
