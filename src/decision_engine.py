import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm

console = Console(stderr=True) # Use stderr to not interfere with MCP stdio protocol

class DecisionEngine:
    """
    Integrates results from all 3 layers and handles the HITL interaction.
    """
    
    RISK_THRESHOLD = 5

    def evaluate_and_prompt(self, url: str, layer1: dict, layer2: dict, layer3: dict) -> bool:
        """
        Evaluates risk and prompts user if necessary.
        Returns True if approved, False if blocked.
        """
        max_risk = 0
        reasons = []

        if layer1.get("malicious"):
            max_risk = 10
            reasons.append(f"[red]Layer 1 (Threat Intel):[/] {layer1['reason']}")

        if layer2.get("findings"):
            # Assign risk based on number of structural findings
            structural_risk = min(len(layer2["findings"]) * 2, 8)
            max_risk = max(max_risk, structural_risk)
            for f in layer2["findings"]:
                reasons.append(f"[yellow]Layer 2 (Structural):[/] {f['type']} - {f['reason']}")

        l3_score = layer3.get("risk_score", 0)
        max_risk = max(max_risk, l3_score)
        if l3_score > 0:
            reasons.append(f"[blue]Layer 3 (Semantic):[/] Score {l3_score} - {layer3['reason']}")

        # If risk is low, auto-approve
        if max_risk < self.RISK_THRESHOLD:
            console.print(f"[green]✔[/] SafeGuard: {url} passed scanning (Risk: {max_risk})")
            return True

        # Alert the user
        console.print("\n" + "="*60)
        alert_panel = Panel(
            "\n".join(reasons),
            title=f"[bold red]SECURITY ALERT:[/] Suspicious content detected at {url}",
            subtitle=f"[bold]Total Risk Score: {max_risk}/10[/]",
            border_style="red"
        )
        console.print(alert_panel)

        # Prompt for approval
        # Note: In a real MCP server over stdio, this is tricky. 
        # For the demo, we assume the user can see the terminal.
        choice = Confirm.ask(f"[bold]Do you want to allow this content to be passed to the AI agent?[/]", default=False)
        
        if choice:
            console.print("[green]✔[/] User approved fetch.")
        else:
            console.print("[red]✘[/] User blocked fetch.")
            
        return choice
