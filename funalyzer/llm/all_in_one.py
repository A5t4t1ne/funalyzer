import os
import asyncio
from datetime import datetime
from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

# Set up Gemini client with API key
# client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
# 
# # MCP server parameters (adjust as needed for your tool)
# server_params = StdioServerParameters(
#     command="npx",
#     args=["-y", "@philschmid/weather-mcp"],  # Example MCP server
#     env=None,
# )
# 
# async def run():
#     async with stdio_client(server_params) as (read, write):
#         async with ClientSession(read, write) as session:
#             await session.initialize()
#             mcp_tools = await session.list_tools()
#             tools = [
#                 types.Tool(
#                     function_declarations=[
#                         {
#                             "name": tool.name,
#                             "description": tool.description,
#                             "parameters": {
#                                 k: v
#                                 for k, v in tool.inputSchema.items()
#                                 if k not in ["additionalProperties", "$schema"]
#                             },
#                         }
#                         for tool in mcp_tools.tools
#                     ]
#                 )
#             ]
#             prompt = f"What is the weather in London in {datetime.now().strftime('%Y-%m-%d')}?"
#             response = client.models.generate_content(
#                 model="gemini-2.0-flash",
#                 contents=prompt,
#                 config=types.GenerateContentConfig(
#                     temperature=0,
#                     tools=tools,
#                 ),
#             )
#             if response.candidates.content.parts.function_call:
#                 function_call = response.candidates.content.parts.function_call
#                 result = await session.call_tool(
#                     function_call.name, arguments=function_call.args
#                 )
#                 print(str(result.content[0]))
#             else:
#                 print("No function call found in the response.")
#                 print(response.text)
# 
# # To run in a plugin, schedule this with asyncio in a thread-safe way
# asyncio.run(run())

