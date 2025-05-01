from binaryninja import log_info, log_error
from enum import Enum
from google import genai
from ..core.parser import UniformedFunction


PROMPT = "Along with this message I send you low level intermediary instructions from disassembled code. The code was disassembled with binary ninja. Can you try to guess what the code does and describe it very briefly. If you recognize the function from a library, tell me the function name, otherwise try to guess it. Please put your brief description and/or guess of the function name at the top of your response followed by reasoning. Please exclude any markdown formatting symbols.\n\n"
API_KEY = "AIzaSyBO4nlCdN0yDklPhLpa2V8Y5nns5KX7gDI"


class LLM_REQUEST_TYPE(Enum):
    COMPARE = 1
    ANALYZE = 2


def llm_request(req_type: LLM_REQUEST_TYPE, func: UniformedFunction) -> str:
    func_il = func.low_level_il
    func_str = ""
    for bb in func_il:
        func_str = "\n".join(str(instr) for instr in bb)


    if req_type == LLM_REQUEST_TYPE.COMPARE:
        log_error("LLM comparing not implemented yet")
    elif req_type is LLM_REQUEST_TYPE.ANALYZE:
        log_info("Starting LLM API request")
        try:
            client = genai.Client(api_key=API_KEY)
            response = client.models.generate_content(model="gemini-2.0-flash", contents=[PROMPT + func_str])
            return response.text
        except Exception as e:
            log_error(f"Request to LLM failed: {e}")
            return "Request to LLM failed"
    else:
        raise ValueError(f"{req_type} is not a valid option")
