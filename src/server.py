import asyncio
import os
from mcp.server.fastmcp import FastMCP
from typing import Optional
from dotenv import load_dotenv

from threat_intel import ThreatIntel
from structural_analyzer import StructuralAnalyzer
from semantic_scanner import SemanticScanner
from decision_engine import DecisionEngine

# Load environment variables (ANTHROPIC_API_KEY)
load_dotenv()

# Initialize FastMCP server
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
    
    Args:
        url: The URL to fetch and scan.
    """
    # Layer 1: Threat Intel (Pre-fetch)
    layer1_result = threat_intel.scan(url)
    
    # Layer 2: Structural Analysis (Post-fetch)
    # This also performs the actual fetch
    layer2_result = structural_analyzer.fetch_and_analyze(url)
    
    if not layer2_result.get("success"):
        return f"Error fetching {url}: {layer2_result.get('error')}"

    # Layer 3: Semantic Analysis (LLM-as-judge)
    layer3_result = semantic_scanner.scan(layer2_result["cleaned_text"])
    
    # Decision Engine (HITL)
    approved = decision_engine.evaluate_and_prompt(
        url, 
        layer1_result, 
        layer2_result, 
        layer3_result
    )
    
    if approved:
        # Return the cleaned text to the agent
        return layer2_result["cleaned_text"]
    else:
        return f"ACCESS BLOCKED: SafeGuard detected potential prompt injection or malicious content at {url} and the user denied access."

if __name__ == "__main__":
    server.run()
