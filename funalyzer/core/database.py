from binaryninja.log import log_error
import shelve
import pickle
from ..libmatch import LibMatchDatabase


class FunalyzerDatabase:
    """
    A container for analyzed object files
    """

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value

    def save_to(self, path: str):
        """Save object to path"""
        with shelve.open(path) as shelf:
            for key, value in self._data.items():
                shelf[key] = value

    @staticmethod
    def load_path(path: str) -> 'FunalyzerDatabase' | None:
        """Load DB from path"""
        try:
            with shelve.open(path) as shelf:
                return FunalyzerDatabase({k: v for k, v in shelf.items()})
        except Exception as e:
            log_error(f"failed to load DB: {e}")
            return None

    @staticmethod
    def load_libmatch_db(path: str) -> LibMatchDatabase | None:
        with open(path, "rb") as f:
            lmdb = pickle.load(f)

        if not isinstance(lmdb, LibMatchDatabase):
            log_error("That's not a InterObjectCallgraph!")
            return None

        return lmdb
