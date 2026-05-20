import asyncio
import os
import logging
import sys
from mcp.server.fastmcp import FastMCP
from typing import Optional
from dotenv import load_dotenv

from threat_intel import ThreatIntel
from structural_analyzer import StructuralAnalyzer
from semantic_scanner import SemanticScanner
from decision_engine import DecisionEngine

# Redirect all standard logging to stderr to prevent interference with MCP JSON-RPC on stdout
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("SafeGuard")

# Load environment variables (ANTHROPIC_API_KEY, GEMINI_API_KEY)
load_dotenv()

# Initialize FastMCP server
# We use stdio transport by default which is compatible with Claude Code and Gemini CLI
server = FastMCP("SafeGuard")

# Initialize modules
threat_intel = ThreatIntel()
structural_analyzer = StructuralAnalyzer()
semantic_scanner = SemanticScanner()
decision_engine = DecisionEngine()

@server.tool()
async def safe_fetch(url: str) -> str:
    """
    Safely fetches a URL after scanning for prompt injections and malicious content.
    Use this instead of standard fetch tools when security is a concern.
    
    Args:
        url: The URL to fetch and scan.
    """
    logger.info(f"SafeGuard: Intercepting fetch request for {url}")
    
    # Layer 1: Threat Intel (Pre-fetch)
    layer1_result = threat_intel.scan(url)
    
    # Layer 2: Structural Analysis (Post-fetch)
    layer2_result = structural_analyzer.fetch_and_analyze(url)
    
    if not layer2_result.get("success"):
        return f"Error fetching {url}: {layer2_result.get('error')}"

    # Layer 3: Semantic Analysis (LLM-as-judge)
    layer3_result = semantic_scanner.scan(layer2_result["cleaned_text"])
    
    # Decision Engine (HITL)
    # This will print the alert to stderr (visible in the agent's terminal) 
    # and wait for user input.
    approved = decision_engine.evaluate_and_prompt(
        url, 
        layer1_result, 
        layer2_result, 
        layer3_result
    )
    
    if approved:
        logger.info(f"SafeGuard: Fetch approved for {url}")
        return layer2_result["cleaned_text"]
    else:
        logger.warning(f"SafeGuard: Fetch BLOCKED for {url}")
        return f"ACCESS BLOCKED: SafeGuard detected potential prompt injection or malicious content at {url}. The user was alerted and denied access to protect the system."

if __name__ == "__main__":
    server.run()
