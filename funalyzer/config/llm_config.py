from enum import Enum, auto
from dotenv import load_dotenv
from pathlib import Path
import os

fpath = Path(__file__)
env_path =  fpath.parent / ".env"
load_dotenv(env_path)


class PromptVars(Enum):
    LLIL_FUNC_CODE = auto()
    LLIL_FILE_CODE = auto()
    HLIL_FUNC_CODE = auto()
    LIBRARY_NAME = auto()

    def __str__(self) -> str:
        return f"{self.__class__.__name__}.{str(self.name)}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}.{str(self.name)}"



class Prompts:

    ANALYZE_FUNCTION = (
        "Along with this message I send you low level intermediary (LLIL) instructions from a disassembled function. "
        "The code was disassembled with Binary Ninja. Can you try to guess what the code does and describe "
        "it very briefly. If you recognize the function from a library, tell me the function name, otherwise try "
        "to guess it. Please put your brief description and/or guess of the function name at the top of your "
        "response followed by reasoning. Exclude any markdown or similar formatting symbols. "
        "The function in question is the following:\n\n"
        f"```Low level intermediary language (LLIL):\n{PromptVars.LLIL_FUNC_CODE}\n```\n\n"
        f"Consider that the name of the library is {PromptVars.LIBRARY_NAME} and only functions from within that"
        " library are used. Furthermore it is likely, that the function has"
        " something to do with gpio\n\n"
        # "The disassembled code of the whole file and therefore the context in which this function is used is the"
        # "following:\n\n"
        # f"```\n{PromptVars.LLIL_FILE_CODE}```"
    )

    RENAME_FUNCTION = (f"If you were given the task of finding a meaningful, accurate, descriptive and truthful name, " \
            "with no special characters other than '_', with no content other than the name, with no brackets, what " \
            "would you name the functions whose low-level intermediate code instructions are listed below:\n\n" \
            f"{PromptVars.LLIL_FUNC_CODE}\n\n" \
            "Do not give any additional info. Don't return a reasoning. Do not say anything else except your choice " \
            "for the name. Don't send anything at all besides the chosen function names. Only chose one name per " \
            "function. If there are multiple functions given put the individual names on new lines. Do not give " \
            "multiple recommendations per function. Prefer verbs before nouns in the function names. Try to avoid " \
            "general words. Try to guess what the function does."
    )

    RENAME_VARIABLE = (
        "In one word, with no special characters except '_', with no content except the name, what "
        "should be the name of variable currently named [VAR_NAME] in the following context:\n\n[LLIL_CODE]"
    )


GEMINI_API_KEY = os.getenv("GEMINI-API-KEY")
