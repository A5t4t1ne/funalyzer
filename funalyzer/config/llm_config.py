from dotenv import load_dotenv
from pathlib import Path
import os

fpath = Path(__file__)
env_path =  fpath.parent / ".env"
load_dotenv(env_path)


class Prompts:
    ANALYZE_FUNCTION = (
        "Along with this message I send you low level intermediary instructions from disassembled "
        "code. The code was disassembled with binary ninja. Can you try to guess what the code does and describe "
        "it very briefly. If you recognize the function from a library, tell me the function name, otherwise try "
        "to guess it. Please put your brief description and/or guess of the function name at the top of your "
        "response followed by reasoning. Exclude any markdown or similar formatting symbols.\n\n"
        "[LLIL_CODE]"
    )

    RENAME_FUNCTION = ("If you were given the task of finding a meaningful, accurate, descriptive and truthful name, " \
            "with no special characters other than '_', with no content other than the name, with no brackets, what " \
            "would you name the functions whose low-level intermediate code instructions are listed below:\n\n" \
            "[LLIL_CODE]\n\n" \
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
