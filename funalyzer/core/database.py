from binaryninja.log import log_error, log_debug, log_info
import os
import shelve
from pathlib import Path
from typing import Dict
from .parser import UniformedFunction


class FunalyzerDatabase:
    """
    A container for analyzed object files
    """

    def __init__(self, data: Dict[str, Dict[str, UniformedFunction]]) -> None:
        self._data = data

    def __getitem__(self, key):
        return self._data.get(key, None)

    def __setitem__(self, key, value):
        self._data[key] = value

    def __repr__(self):
        return f"{self.__class__.__name__}: self.data"

    def save_to(self, path: str, overwrite: bool = False):
        """Save object to path"""
        p = Path(path)
        if p.is_dir():
            if p.is_absolute():
                p = p / "database.fdb"
            else:
                p = Path("~").resolve() / "database.fdb"
        elif p.suffix != ".fdb":
            raise ValueError("Suffix of database name must be '.fdb'")
        elif p.exists() and not overwrite:
            raise ValueError(f"File '{p.resolve()}' already exists")
        else:
            pass

        try:
            with shelve.open(p.resolve()) as shelf:
                shelf.clear()
                for filename, functions in self._data.items():
                    log_debug(f"Processing: {filename}")
                    data = {addr: func.get_essentials() for addr, func in functions.items()}
                    shelf[filename] = data

                log_debug(f"Processed {len(shelf)} files")
            log_info(f"Entries successfully saved to DB at {p.resolve()}.")
            return True
        except Exception as e:
            log_error(f"Could not save db: {e}")
            return False

    @staticmethod
    def load_from_path(path: str) -> "FunalyzerDatabase":
        """Load existing database from path.

        Args:
            path (str): Path to the database file

        Returns:
            _type_: FunalyzerDatabase object
        """
        if not os.path.exists(path):
            log_error(f"File {path} not found")
            return None
        try:
            with shelve.open(path) as shelf:
                db_data = dict()
                for k, essentials in shelf.items():
                    db_data[k] = UniformedFunction(None, None, parsed_data=essentials)

                return FunalyzerDatabase(db_data)
        except Exception as e:
            log_error(f"While trying to load db: {e}")
            return FunalyzerDatabase(data={})

    @staticmethod
    def create_from_path(path: str) -> "FunalyzerDatabase":
        """Create a database from a directory of object files.

        Args:
            path (str): Path to the directory containing object files

        Returns:
            FunalyzerDatabase: A database of analyzed object files
        """
        valid_extensions = [".o", ".obj", ".bin", ".bdsig"]

        data = dict()
        directory = Path(path).resolve()
        if directory.exists() and directory.is_dir():
            # recursively load object files from directory and create a database
            files = itertools.chain.from_iterable(directory.glob(f"**/*{ext}") for ext in valid_extensions)
            dir_parts_count = len(directory.parts)
            for i, f in enumerate(files):
                # if i >= 10:
                #     break
                try:
                    log_debug(f"Analyzing {f}")
                    with bn.load(f) as bv:
                        fname = Path(bv.file.filename)
                        rel_fname = Path("/".join(fname.parts[dir_parts_count - 1 :]))
                        log_info(f"{str(rel_fname)}")
                        data[str(rel_fname)] = {str(func.start): UniformedFunction(bv, func) for func in bv.functions}
                except Exception as e:
                    log_error(f"Couldn't analyze file: {e}")

        return FunalyzerDatabase(data)
