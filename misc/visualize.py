import sys
sys.path.append('/home/dave/hslu/SEM6/BAA/')
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
        values = [db[key] for key in keys]
    except KeyError as e:
        print(f"KeyError: {e}")
    except ModuleNotFoundError as e:
        print(f"ModuleNotFoundError: {e}")


for key, val in zip(keys, values):
    if type(val) is dict:
        print(len(val))
        for addr, func_attrs in val.items():
            if int(addr) >= 1000:
                addr_str = addr
            elif int(addr) >= 100:
                addr_str = addr + " "
            elif int(addr) >= 10:
                addr_str = addr + "  "
            else:
                addr_str = addr + "   "
            print(f"{addr_str}: {func_attrs}")
    print(f"{key}: {type(val)}")
