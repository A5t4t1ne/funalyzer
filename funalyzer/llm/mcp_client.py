from binaryninja.log import log_info
from mcp import ClientSession, StdioServerParameters, Tool
from mcp.client.stdio import stdio_client
from pathlib import Path


async def run(server_path: Path):
    log_info("in run")
    if not server_path.suffix == ".py":
        raise ValueError("Server script must be a .py file")
    if not server_path.exists():
        raise ValueError(f"File {server_path.resolve()} does not exist")
    server_params = StdioServerParameters(
        command="python",
        args=[str(server_path)]
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            log_info(f"Available tools: {[t.name for t in tools.tools]}")

            # Call the Gemini tool
            prompt = "Explain the Model Context Protocol in one sentence."
            result = await session.call_tool("ask_gemini", {"prompt": prompt})
            log_info(f"Gemini says: {result.content}")
