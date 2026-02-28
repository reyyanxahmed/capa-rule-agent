# future/

Modules moved here are scaffolded but not end-to-end tested. They exist to show
planned architecture, not to inflate the PoC scope.

| Module | Purpose | Status |
|--------|---------|--------|
| `adk_agent.py` | Google ADK agent with tool-use orchestration | Tool declarations exist, orchestration loop not tested |
| `backlog.py` | Fetch and classify open issues by tractability | Working, but pipeline --process-backlog mode removed to simplify scope |
| `proactive.py` | Threat intel feed scanning for coverage gaps | Deprioritized per mentor feedback: focus on issue backlog first |
| `search_grounding.py` | Google Search API for verifying API names and registry paths | Stubbed with fallback data, no live API integration |

These will be integrated into the main pipeline after the core loop
(issue -> rule -> validate -> quality gate) is solid.
