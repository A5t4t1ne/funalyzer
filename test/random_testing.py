from pathlib import Path
import shelve


if __name__ == "__main__":
    p = "/home/dave/arm_none_eabi.fdb"
    with shelve.open(p) as shelf:
        for key, val in shelf.items():
            print(f"{key=}: {val=})")
