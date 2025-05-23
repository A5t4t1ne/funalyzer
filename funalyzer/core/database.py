from binaryninja.log import log_error, log_debug, log_info
import binaryninja as bn
import os
import shelve
from pathlib import Path
from typing import Dict, ItemsView
from .parser import LibDescriptor
import itertools


class FunalyzerDatabase:
    """
    A container for analyzed object files
    """

    def __init__(self, lib_descriptors: Dict[str, LibDescriptor]) -> None:
        self.lib_descriptors = lib_descriptors

    def __getitem__(self, key):
        return self.lib_descriptors.get(key, None)

    def __setitem__(self, key, value):
        self.lib_descriptors[key] = value

    def __repr__(self):
        return f"{self.__class__.__name__}: self.data"

    def items(self) -> ItemsView[str, LibDescriptor]:
        return self.lib_descriptors.items()

    def save_to(self, path: str, overwrite: bool = False):
        """Save object to path"""
        p = Path(path)
        if p.is_dir():
            if p.is_absolute():
                p = p / "database.fdb"
            else:
                p = Path(os.getcwd()) / "database.fdb"
        elif p.suffix != ".fdb":
            raise ValueError("Suffix of database name must be '.fdb'")
        elif p.exists() and not overwrite:
            raise ValueError(f"File '{p.resolve()}' already exists")
        elif not p.is_absolute():  # check if it's an absolute file path
            p = Path(os.getcwd()) / p

        try:
            with shelve.open(p.resolve()) as shelf:
                shelf.clear()
                for filename, descriptor in self.lib_descriptors.items():
                    log_debug(f"Saving {filename}")
                    # data = {addr: func.get_essentials() for addr, func in descriptor.items()}
                    shelf[filename] = descriptor.get_essentials()

                log_debug(f"Processed {len(shelf)} files")
            log_info(f"Entries successfully saved to DB at {p.resolve()}.")
            return True
        except ArithmeticError as e:
            log_error(f"Could not save db: {e}")
            return False

    @staticmethod
    def load_from_path(path: str) -> "FunalyzerDatabase | None":
        """Load existing database from path.

        Args:
            path (str): Path to the database file

        Returns:
            _type_: FunalyzerDatabase object
        """
        p = Path(path)
        if not p.exists():
            log_error(f"File {path} not found")
            return None
        if not p.is_absolute():
            log_error(f"{path} is not absolute")
        try:
            with shelve.open(path) as shelf:
                db_data = dict()
                for fname, descriptor in shelf.items():
                    db_data[fname] = LibDescriptor(parsed_data=descriptor)

                return FunalyzerDatabase(db_data)
        except ConnectionError as e:
            log_error(f"While trying to load db from {path}: {e}")
            return FunalyzerDatabase({})

    @staticmethod
    def create_from_path(path: str) -> "FunalyzerDatabase":
        """Create a database from a directory of object files.

        Args:
            path (str): Path to the directory containing object files

        Returns:
            FunalyzerDatabase: A database of analyzed object files
        """
        valid_extensions = [".o", ".obj", ".bin", ".bdsig"]

        directory = Path(path).resolve()
        lib_descriptors: Dict[str, LibDescriptor] = dict()

        if directory.exists() and directory.is_dir():
            # recursively load object files from directory and create a database
            files = itertools.chain.from_iterable(directory.glob(f"**/*{ext}") for ext in valid_extensions)
            dir_parts_count = len(directory.parts)
            for i, f in enumerate(files):
                if i >= 10:
                    # pass
                    break
                try:
                    log_debug(f"Analyzing {f}")
                    with bn.load(f) as bv:
                        fname = Path(bv.file.filename)
                        rel_fname = Path("/".join(fname.parts[dir_parts_count - 1 :]))
                        log_info(f"{str(rel_fname)}")
                        lib_descriptors[str(rel_fname)] = LibDescriptor(bv)
                except Exception as e:
                    log_error(f"Couldn't analyze file: {e}")

        return FunalyzerDatabase(lib_descriptors)
