import asyncio
from enum import Enum, auto
from types import CoroutineType
from typing import List, Optional, Any, Dict
from contextlib import AsyncExitStack
from pathlib import Path

from binaryninja.log import log_debug, log_info
from mcp import ClientSession, StdioServerParameters, Tool
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult


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


# class MCPClient:
#     def __init__(self):
#         self.session: Optional[ClientSession] = None
#         self.exit_stack = AsyncExitStack()
#         self.stdio = None
#         self.write = None
# 
#     async def connect(self, server_path: Path):
#         """
#         Connect to an MCP server via stdio.
#         Args:
#             server_script_path: Path to the server script (e.g., 'example_server.py')
#         """
#         if not server_path.suffix == ".py":
#             raise ValueError("Server script must be a .py file")
#         if not server_path.exists():
#             raise ValueError(f"File {server_path.resolve()} does not exist")
#         # server_params = StdioServerParameters(
#         #     command="python",
#         #     args=[str(server_path)],
#         #     env=None
#         # )
#         log_debug("connecting to MCP server")
#         proc = await asyncio.create_subprocess_exec(
#             "python", str(server_path),
#             stdin=asyncio.subprocess.PIPE,
#             stdout=asyncio.subprocess.PIPE,
#         )
#         self.stdio = proc.stdout
#         self.write = proc.stdin
#         self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
#         # stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
#         # log_info("here 2")
#         # self.stdio, self.write = stdio_transport
#         # self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
#         log_info("here 3")
#         await self.session.initialize()
#         log_info("here 4")
#         tools = await self.session.list_tools()
#         log_info("here 5")
#         log_info(f"Connected to server with tools: {[tool.name for tool in tools.tools]}")
# 
#     async def list_tools(self) -> List[Tool]:
#         """
#         List available tools from the MCP server.
#         """
#         if self.session is None:
#             raise RuntimeError("Not connected to MCP server")
#         tools = await self.session.list_tools()
#         return tools.tools
# 
#     async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> CallToolResult:
#         """
#         Call a tool exposed by the MCP server.
#         Args:
#             tool_name: Name of the tool to call.
#             arguments: Arguments for the tool.
#         """
#         if self.session is None:
#             raise RuntimeError("Not connected to MCP server")
#         return await self.session.call_tool(tool_name, arguments=arguments)
# 
#     async def close(self):
#         """
#         Cleanly close the MCP client session and resources.
#         """
#         await self.exit_stack.aclose()



