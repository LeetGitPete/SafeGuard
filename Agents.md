# Agents.md - SafeGuard Development Journey

## Project Overview
SafeGuard is an MCP server designed to protect AI coding agents from indirect prompt injection attacks. Developed for the "Workshop on Usable Security and Privacy" (Spring 2025).

## AI Agent Integration
This project was developed with the assistance of **Gemini CLI**, an agentic development tool.

### Role of the AI Agent
- **Architectural Design:** Assisted in mapping the 3-layer defense system (Threat Intel, Structural, Semantic) based on the project requirements.
- **Scaffolding:** Rapidly generated the MCP server structure using the `mcp` Python SDK.
- **Implementation:** Wrote the core logic for the BeautifulSoup-based structural analyzer and the Anthropic-powered semantic scanner.
- **Demo Assets:** Created mock malicious HTML files to simulate various attack vectors for the mid-semester presentation.

### Design Decisions Influenced by AI
- **Hybrid to Local-Only Shift:** Decided to build the MVP as a local-only system to minimize deployment friction for the June 9th demo, while maintaining the architecture for a future AWS migration.
- **Human-in-the-Loop via Stderr:** Used `rich` and `sys.stderr` for terminal alerts to ensure the interactive prompts do not interfere with the MCP stdio protocol.

### Limitations Encountered
- **Protocol Interference:** Initial plans for terminal input had to be adjusted to avoid breaking the MCP communication channel.
- **Environment Constraints:** Local PowerShell execution policies required manual verification of dependency installation.

## Development Timeline
- **2026-05-20:** Project initialization, requirements analysis, and MVP architecture design.
- **2026-05-20:** Implementation of 3-layer defense (URLhaus, BeautifulSoup, Claude Haiku).
- **2026-05-20:** Integration of Decision Engine and creation of demo assets.
