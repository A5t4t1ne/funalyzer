from typing import List
from binaryninja.log import log_error, log_info
from google import genai
from google.genai.types import GenerateContentResponse

from funalyzer.config.llm_config import Prompts, GEMINI_API_KEY
from funalyzer.llm.llm import LLM_REQUEST_TYPE

# from mcp import types as mcp_types
# import mcp.server.stdio
# from mcp.server.lowlevel import Server, NotificationOptions
# from mcp.server.models import InitializationOptions

from mcp.server.fastmcp import FastMCP

server = FastMCP("gemini-server")
client = genai.Client(api_key=GEMINI_API_KEY)


@server.tool(
    name="ask_gemini",
    description="Send a prompt to Gemini and return the response.",
)
def ask_gemini(prompt: str):
    try:
        response = client.models.generate_content(model="gemini-2.0-flash", contents=[prompt])
        if response and response.text:
            return response.text
    except Exception as e:
        log_error(f"Request to LLM failed {e}")

    return ""


if __name__ == "__main__":
    server.run()


# @server.list_tools()
# async def list_tools() -> list[mcp_types.Tool]:
#     return [
#         mcp_types.Tool(
#             name="request",
#             description="Add two numbers",
#             inputSchema={
#                 "req_type": {"type": "LLM_REQUEST_TYPE", "description": "The request type"},
#                 "payload": {"type": "payload", "description": "The prompt payload"},
#             },
#         )
#     ]
# 
# 
# @server.call_tool()
# async def request(req_type: LLM_REQUEST_TYPE, payload: str) -> List[mcp_types.TextContent]:
#     response: GenerateContentResponse | None = None
# 
#     prompt = ""
#     if req_type == LLM_REQUEST_TYPE.COMPARE:
#         log_error("LLM comparing not implemented yet")
#     elif req_type is LLM_REQUEST_TYPE.ANALYZE_FUNC:
#         log_info("Starting LLM API request")
#         prompt = Prompts.ANALYZE_FUNCTION.replace("[LLIL_CODE]", payload)
#     elif req_type == LLM_REQUEST_TYPE.RENAME_FUNC:
#         prompt = Prompts.RENAME_FUNCTION.replace("[LLIL_CODE]", payload)
#     elif req_type == LLM_REQUEST_TYPE.RENAME_VAR:
#         log_error("LLM rename var not implemented yet")
#         return [mcp_types.TextContent(type="text", text="")]
# 
#     try:
#         response = client.models.generate_content(model="gemini-2.0-flash", contents=[prompt])
#         if response and response.text:
#             return [mcp_types.TextContent(type="text", text=response.text)]
#     except Exception as e:
#         log_error(f"Request to LLM failed {e}")
#     
#     return [mcp_types.TextContent(type="text", text="")]
# 
# 
# async def run():
#     # Start the server, listening on stdio for MCP clients
#     async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
#         await server.run(
#             read_stream,
#             write_stream,
#             InitializationOptions(
#                 server_name="example-server",
#                 server_version="0.1.0",
#                 capabilities=server.get_capabilities(
#                     notification_options=NotificationOptions(),
#                     experimental_capabilities={},
#                 ),
#             ),
#         )


