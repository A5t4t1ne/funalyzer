import sys
from typing import Dict, List
sys.path.append('/home/dave/hslu/SEM6/BAA/funalyzer/')

from funalyzer.core.parser import ParsedDataKey

import funalyzer
from pathlib import Path
import shelve


root_folder = Path(__file__).parent.parent
# p = root_folder / "test/arm_none_eabi.fdb"
p = Path("/home/dave/arm_none_eabi.fdb")
keys = []
values = []

with shelve.open(p) as db:
    try:
        # Extract keys and values into lists for plotting
        keys = list(db.keys())
        # print(keys)
        values: List[Dict[str, int]] = [db[key] for key in keys]
    except KeyError as e:
        print(f"KeyError: {e}")
    except ModuleNotFoundError as e:
        print(f"ModuleNotFoundError: {e}")


for fname, val in zip(keys, values):
    if type(val) is dict:
        for parsed_data_key, data_val in val.items():
            if parsed_data_key == ParsedDataKey.VIABLE_SYMBOLS:
                print(f"{data_val}")
    print(f"{fname}: {type(val)}")
