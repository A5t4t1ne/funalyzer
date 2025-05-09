import binaryninja as bn
from binaryninja.log import log_info, log_error
from enum import Enum, auto
from google import genai
from google.genai.chats import GenerateContentResponse
from funalyzer.config.llm_config import Prompts, GEMINI_API_KEY



class LLM_REQUEST_TYPE(Enum):
    COMPARE = auto()
    ANALYZE_FUNC = auto()
    RENAME_FUNC = auto()
    RENAME_VAR = auto()


def llm_request(req_type: LLM_REQUEST_TYPE, func: bn.function.Function, variable: str | None = None) -> str:
    func_il = func.low_level_il
    func_str = ""
    for bb in func_il:
        func_str += "\n".join(str(instr) for instr in bb)

    client = genai.Client(api_key=GEMINI_API_KEY)
    response: GenerateContentResponse | None = None

    if req_type == LLM_REQUEST_TYPE.COMPARE:
        log_error("LLM comparing not implemented yet")
    elif req_type is LLM_REQUEST_TYPE.ANALYZE_FUNC:
        log_info("Starting LLM API request")
        try:
            prompt = Prompts.ANALYZE_FUNCTION.replace("[LLIL_CODE]", func_str)
            response = client.models.generate_content(model="gemini-2.0-flash", contents=[prompt])
        except Exception as e:
            log_error(f"Request to LLM failed: {e}")
            return "Request to LLM failed"
    elif req_type == LLM_REQUEST_TYPE.RENAME_FUNC:
        prompt = Prompts.RENAME_FUNCTION.replace("[LLIL_CODE]", func_str)
        log_info(prompt)
        response = client.models.generate_content(model="gemini-2.0-flash", contents=[prompt])
    elif req_type == LLM_REQUEST_TYPE.RENAME_VAR:
        if variable:
            pass
        else:
            pass
        log_error("LLM rename var not implemented yet")
    else:
        log_error("non-valid LLM request type submitted")
    
    if response:
        return response.text or ""
