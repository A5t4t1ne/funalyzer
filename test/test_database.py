import pytest
from src.core.database import FunalyzerDatabase



class TestFunalyzerDatabase:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        self.db = FunalyzerDatabase(dict())
        yield

    def test_item_access(self):
        key = 'hello'
        content = 'there'
        self.db[key] = content
        assert self.db[key] == content


    def test_save_to(self):
        """Save object to path"""
        print(f"there: {self.db['hello']}")
        assert 1 == 1

    def load_db_from_path(self):
        pass


    def create_from_path(self):
        pass
