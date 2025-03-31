from binaryninja.log import log_error
import binaryninja as bn
import shelve
from ..libmatch.libmatch_database import LibMatchDatabase
from pathlib import Path


class FunalyzerDatabase:
    """
    A container for analyzed object files
    """

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getitem__(self, key):
        return self._data.get(key, None)

    def __setitem__(self, key, value):
        self._data[key] = value

    def save_to(self, path: str):
        """Save object to path"""
        with shelve.open(path) as shelf:
            for key, value in self._data.items():
                shelf[key] = value

    @staticmethod
    def load_db_from_path(path: str):
        """Load existing database from path.

        Args:
            path (str): Path to the database file

        Returns:
            _type_: FunalyzerDatabase object
        """
        try:
            with shelve.open(path) as shelf:
                return FunalyzerDatabase({k: v for k, v in shelf.items()})
        except Exception as e:
            log_error(f"failed to load DB: {e}")
            return None


    @staticmethod
    def create_from_path(path: str) -> 'FunalyzerDatabase':
        """Create a database from a directory of object files.

        Args:
            path (str): Path to the directory containing object files

        Returns:
            FunalyzerDatabase: A database of analyzed object files
        """
        p = Path(path)
        if p.exists() and p.is_dir():
            # recursively load object files from directory and create a database
            data = dict()
            for f in p.glob('**/*.o'):
                with bn.load(str(f.resolve())) as file:
                    pass
            return FunalyzerDatabase(data)
        else:
            return LibMatchDatabase(dict())

