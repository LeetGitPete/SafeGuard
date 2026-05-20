import requests
from bs4 import BeautifulSoup
import re
import logging

logger = logging.getLogger(__name__)

class StructuralAnalyzer:
    """
    Layer 2: Structural Analysis (Post-fetch)
    Detects hidden content and suspicious HTML patterns.
    """

    HIDDEN_CSS_PATTERNS = [
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'font-size\s*:\s*0',
        r'opacity\s*:\s*0',
        r'left\s*:\s*-\d{3,}px',
        r'top\s*:\s*-\d{3,}px',
    ]

    def fetch_and_analyze(self, url: str) -> dict:
        """
        Fetches the URL and scans for hidden content.
        Returns a dict with 'findings' (list) and 'cleaned_text' (str).
        """
        try:
            response = requests.get(url, timeout=10, headers={"User-Agent": "SafeGuard-MCP/1.0"})
            response.raise_for_status()
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            
            findings = []
            
            # 1. Check for hidden elements via style attribute
            for tag in soup.find_all(style=True):
                style = tag['style'].lower()
                for pattern in self.HIDDEN_CSS_PATTERNS:
                    if re.search(pattern, style):
                        findings.append({
                            "type": "hidden_element",
                            "tag": tag.name,
                            "reason": f"Matches hidden pattern: {pattern}",
                            "content": tag.get_text(strip=True)[:100]
                        })

            # 2. Check for hidden iframes
            for iframe in soup.find_all('iframe'):
                if iframe.get('width') == '0' or iframe.get('height') == '0':
                    findings.append({
                        "type": "hidden_iframe",
                        "tag": "iframe",
                        "reason": "Zero-size iframe detected",
                        "src": iframe.get('src')
                    })

            # 3. Check for meta refreshes (can be used for redirection)
            for meta in soup.find_all('meta', attrs={"http-equiv": "refresh"}):
                findings.append({
                    "type": "meta_refresh",
                    "tag": "meta",
                    "reason": "Automatic refresh/redirect detected",
                    "content": meta.get('content')
                })

            # Cleaned text (for Layer 3) - removing scripts and styles
            for script_or_style in soup(["script", "style"]):
                script_or_style.decompose()
            
            cleaned_text = soup.get_text(separator=' ', strip=True)

            return {
                "success": True,
                "findings": findings,
                "cleaned_text": cleaned_text,
                "raw_html": html
            }
        except Exception as e:
            logger.error(f"Error in structural analysis: {e}")
            return {"success": False, "error": str(e)}
