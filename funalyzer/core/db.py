import shelve



def write_to_file():
    with shelve.open("db.lmdb") as db:
        db["key1"] = "val1"








