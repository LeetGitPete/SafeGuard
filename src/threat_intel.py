import requests
import logging

logger = logging.getLogger(__name__)

class ThreatIntel:
    """
    Layer 1: Threat Intelligence (Pre-fetch)
    Checks URLs against known malicious databases.
    """
    
    URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    @staticmethod
    def check_urlhaus(url: str) -> dict:
        """
        Checks a URL against URLhaus API.
        Returns a dict with 'malicious' (bool) and 'reason' (str).
        """
        try:
            response = requests.post(
                ThreatIntel.URLHAUS_API_URL,
                data={"url": url},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {
                        "malicious": True,
                        "reason": f"URLhaus: {data.get('url_status', 'malicious')}",
                        "details": data
                    }
            return {"malicious": False, "reason": "Not found in URLhaus"}
        except Exception as e:
            logger.error(f"Error checking URLhaus: {e}")
            return {"malicious": False, "reason": f"Error: {e}"}

    def scan(self, url: str) -> dict:
        """
        Runs all threat intel checks.
        """
        # For MVP, we use URLhaus. Can add PhishTank, Google Safe Browsing here.
        return self.check_urlhaus(url)
