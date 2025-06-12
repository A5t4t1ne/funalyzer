import binaryninja as bn
from binaryninja.log import log_info, log_error
from google import genai
from google.genai.types import GenerateContentResponse
from funalyzer.config.llm_config import Prompts, GEMINI_API_KEY, PromptVars
from funalyzer.llm.mcp_client import run
from enum import Enum, auto
from pathlib import Path

local_path = Path(__file__).parent

class LLM_REQUEST_TYPE(Enum):
    COMPARE = auto()
    ANALYZE_FUNC = auto()
    RENAME_FUNC = auto()
    RENAME_VAR = auto()


async def llm_request(bv: bn.BinaryView, func: bn.function.Function, req_type: LLM_REQUEST_TYPE, variable: str | None =
                      None, mcp_path: str = "") -> str:
    target_func_llil_str = ""
    for bb in func.low_level_il:
        target_func_llil_str += "\n".join(str(instr) for instr in bb)


    client = genai.Client(api_key=GEMINI_API_KEY)
    response: GenerateContentResponse | None = None

    if req_type == LLM_REQUEST_TYPE.COMPARE:
        log_error("LLM comparing not implemented yet")
    elif req_type is LLM_REQUEST_TYPE.ANALYZE_FUNC:
        log_info("Starting LLM API request")
        try:
            prompt = Prompts.ANALYZE_FUNCTION
            prompt = prompt.replace(str(PromptVars.LLIL_FUNC_CODE), target_func_llil_str)
            prompt = prompt.replace(str(PromptVars.LIBRARY_NAME), '"arm-none-eabi"')

            if mcp_path != "":
                try:
                    server_path = local_path / mcp_path
                    response = await run(server_path)
                except Exception as e:
                    log_error(f"Connection to MCP server failed {e}")
                    
            else:
                response = client.models.generate_content(model="gemini-2.0-flash", contents=[prompt])
            log_info("end task")
        except Exception as e:
            log_error(f"Request to LLM failed: {e}")
            return "Request to LLM failed"
    elif req_type == LLM_REQUEST_TYPE.RENAME_FUNC:
        prompt = Prompts.RENAME_FUNCTION.replace("[LLIL_CODE]", target_func_llil_str)
        log_info(prompt)
        response = client.models.generate_content(model="gemini-2.0-flash", contents=[prompt])
    elif req_type == LLM_REQUEST_TYPE.RENAME_VAR:
        if variable:
            pass
        else:
            pass
        log_error("LLM rename var not implemented yet")

    if response and response.text:
        return response.text
    else:
        return ""
