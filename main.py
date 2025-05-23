import asyncio
from funalyzer.llm.mcp_client import MCPClient
from pathlib import Path

# Example usage (for testing, not for production plugin code)
if __name__ == "__main__":
    async def main():
        client = MCPClient()
        current_fpath = Path(__file__).resolve()
        server_fpath = current_fpath.parent / 'funalyzer/llm/mcp_gemini_server.py'
        await client.connect(server_fpath)
        tools = await client.list_tools()
        print("Available tools:", [t.name for t in tools])
        # Example: call a tool (replace 'tool_name' and args as appropriate)
        result = await client.call_tool("tool_name", {"arg1": "value"})
        print("Tool result:", result)
        await client.close()

    asyncio.run(main())

