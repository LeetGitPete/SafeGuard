import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def run_demo():
    server_params = StdioServerParameters(
        command="python",
        args=["src/server.py"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # List of URLs to test
            test_urls = [
                "http://localhost:8000/clean.html",
                "http://localhost:8000/structural_injection.html",
                "http://localhost:8000/semantic_injection.html"
            ]

            for url in test_urls:
                print(f"\n[Agent] Attempting to fetch: {url}")
                result = await session.call_tool("safe_fetch", {"url": url})
                print(f"[Agent] Received Content: {result.content[0].text[:200]}...")

if __name__ == "__main__":
    asyncio.run(run_demo())
