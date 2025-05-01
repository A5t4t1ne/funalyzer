import shelve
import pytest
from src.core.database import FunalyzerDatabase
from src.core.parser import UniformedFunction
from pathlib import Path
import os


class TestFunalyzerDatabase:
    TEST_KEY = "functions"
    DB_PATH = "database.fdb"
    LIB_PATH = "lib_folder"

    @pytest.fixture(autouse=True)
    def setup_db(self):
        with shelve.open("./arm_none_eabi.fdb") as shelf:
            for key, val in shelf.items():
                print(f"{key=}: {val=})")
            self.TEST_VAL = dict()  # {"addr": UniformedFunction(None, None, {"whats": "up"})}
        self.db = FunalyzerDatabase({self.TEST_KEY: self.TEST_VAL})
        yield

    #    @pytest.mark.dependency()
    def test_item_access(self):
        print(self.db[self.TEST_KEY])
        assert self.db[self.TEST_KEY] == self.TEST_VAL

    @pytest.mark.dependency()
    def test_save_to_with_filename(self):
        self.db["functions"] = [1, 2, 3, 4]
        path = Path(self.DB_PATH).resolve()

        if path.exists():
            with pytest.raises(ValueError):
                self.db.save_to(self.DB_PATH)

            os.remove(self.DB_PATH)

        assert self.db.save_to(self.DB_PATH)
        assert path.exists()

    def test_save_to_with_dirname(self):
        self.db["functions"] = [1, 2, 3, 4]
        assert self.db.save_to("./")
        assert Path(self.DB_PATH).exists()

    @pytest.mark.dependency(depends=["test_save_to_with_filename"])
    def load_db_from_path(self):
        db = FunalyzerDatabase.load_db_from_path(self.DB_PATH)
        functions = db["functions"]
        assert functions is not None
        assert len(functions) > 0
        assert type(functions) is list

    def test_create_from_path(self):
        db = FunalyzerDatabase.create_from_path(self.LIB_PATH)
        assert type(db) is FunalyzerDatabase
