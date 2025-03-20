from binaryninja import log_info, log_warn, log_error
import shelve
from shelve import Shelf
from pathlib import Path
from collections import defaultdict
from .lmd import LibMatchDescriptor
from .libmatch import LibMatch
from .utils import score_matches
from typing import Type


class LibMatchDatabase(object):
    """
    A container for a lot of LibMatchDescriptors and their metadata.

    An LMDB is based on a set of libraries in a directory structure, similar to how they are found on the filesystem.
    The top level should contain folders for each arch-tuple (e.g., arm-none-eabi-)
    THe next level should consist of one folder per library.
    Under that, they can contain any arbitrary folder structure (e.g., you can just pile a bunch of library folders in there and it'll get figured out)
    """
    def __init__(self, lib_lmds):
        self.lib_lmds = lib_lmds
        self.lmds = dict()
        self._build_sym_list(lib_lmds)
        self.symbols = defaultdict(list) # Mapping of string names to all the libraries and objects that contain them.

    def _smoosh(self, candidates):
        for f_addr, content in candidates.items():
            if len(content) <= 1:
                continue

            name = content[0][2].function_b.name
            for lib, lmd, fd in content:
                if name != fd.function_b.name:
                    break
            else:
                # Smoosh it!
                candidates[f_addr] = [content[0]]
        return candidates

    def _postprocess_matches(self, target_lmd, results):
        """
        Clean up the matches for the user.
        This encodes the behavior "we consider it a match if we 
        match with exactly one name"
        """
        final_matches = {}
        collisions = 0
        junk = 0
        guesses = 0
        for f_addr, match_infos in results.items():
            if len(match_infos) > 1:
                collisions += 1    
                continue
            if f_addr not in target_lmd.viable_functions:
                # we put a name on it, but it's a stub!
                # What. Ever.
                junk += 1
                continue
            for lib, lmd, match in match_infos:
                if isinstance(match, str):
                    sym_name = match
                    guesses += 1
                else:
                    obj_func_addr = match.function_b.addr
                    sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
                final_matches[f_addr] = sym_name
        log_warn(f"Detected {collisions} collisions")
        log_warn(f"Ignored {junk} junk function matches")
        log_warn(f"Made {guesses} guesses")
        log_warn(f"Matched {len(list(final_matches.keys()))} symbols")
        return final_matches


    def match(self, lmd_path: str, score=False):
        """
        Scan the database and try to match all libraries with the target.

        :param lib: Either a string (program path) or a LibMatchDescriptor
        :return: A dictionary of addresses in the program to possible symbols.
        """
        lmd: dict = LibMatchDescriptor.load_path(lmd_path)
        candidates = []
        try:
            self.lm = LibMatch(lmd, self)
            candidates = self.lm._candidate_matches
            plain_candidates = self.lm._plain_matches
        except Exception as e:
            log_error(f"Error computing matches: {e}")
            raise

        # TODO: This is where we put multi-library heuristics!
        candidates = self._smoosh(candidates)
        plain_candidates = self._smoosh(plain_candidates)
        if score:
            print("############### UNREFINED MATCHES ###############")
            score_matches(lmd_path, plain_candidates, self)
            input()
            print("############### FINAL MATCHES ###############")
            score_matches(lmd_path, candidates, self)

        out = self._postprocess_matches(lmd, candidates)
        return out

    # Creation and Serialization
    @staticmethod
    def _build_lib(lib_dir: Path) -> set:
        lmds = set()
        # TODO prio high: replace angr
        # for dir_name, _, file_list in lib_dir.walk():
        #     log_debug(f"Found directory: {dir_name}")
        #     for file in file_list:
        #         file = Path(file)
        #         if file.suffix() == ".o" or file.suffix() == ".obj":
        #             fullname = dir_name / file
        #             log_debug("Making signature for " + fullname)
        #             try:
        #                 lmds.add(LibMatchDescriptor.make_signature(fullfile, **PROJECT_KWARGS))
        #             except angr.errors.AngrCFGError:
        #                 log_warn(f"No executable data for {fullfile}, skipping")
        #             except Exception as e:
        #                 log_error("Could not make signature for {fullfile}")
        return lmds

    @staticmethod
    def build(target: str, dbfile=None):
        """Build a LibMatchDatabase from a directory of libraries.

        Args:
            target (str): target directory to all libraries.
            dbfile (str, optional): Name of the database. Defaults to None.

        Raises:
            ValueError: Non valid directory.
            ValueError: Non valid DB name.
        """
        root_dir = Path(target)
        lmds = dict() # mapping of the lib's name, to the list of lmds it contains
        if not root_dir.is_dir() or not root_dir.exists():
            raise ValueError(f"Not a valid directory: {root_dir}")
        if dbfile is not None:
            if type(dbfile) is not str:
                raise ValueError(f"Not a valid DB name: {dbfile}")
            db = Path(dbfile)
        # Each directory in the root tree is treated as a seperate library
        for obj in root_dir.iterdir():
            fullname = root_dir / obj
            if fullname.is_dir():
                log_info(f"Building signatures for library {obj} {fullname}")
                lmds[str(obj)] = LibMatchDatabase._build_lib(fullname)

        log_info("Making LMDB")
        lmdb = LibMatchDatabase(lmds)
        directory = root_dir.resolve().parent

        if dbfile is None:
            db = directory / (root_dir.resolve().name + ".lmdb")
        elif Path(dbfile).is_absolute():
            db = Path(dbfile)
        else:
            db = directory / Path(dbfile)
        lmdb.dump_path(db)
        log_info("Done")

    def _build_sym_list(self, lmds):
        """
        Build the total list of symbols this database contains.
        If its not in this list, we are for sure not going to match well with it
        (used for scoring)
        :param lmds:
        :return:
        """
        syms = set()
        for _, lmd_list in lmds.items():
            for lmd in lmd_list:
                names = {x.name for x in lmd.viable_symbols}
                syms.update(names)
        self.symbol_names = syms

    @staticmethod
    def load_path(path: str) -> 'LibMatchDatabase':
        with shelve.open(path) as shelf:
            return LibMatchDatabase.load(shelf)

    @staticmethod
    def load(shelf: Shelf) -> 'LibMatchDatabase':
        items = {k: v for k, v in shelf.items()}
        # TODO prio medium: check instance somehow
        # if not isinstance(lmdb, LibMatchDatabase):
        #     raise ValueError("That's not a InterObjectCallgraph!")
        # return lmdb
        return LibMatchDatabase(items)

    def dump_path(self, p) -> None:
        with shelve.open(p) as shelf:
            self.dump(shelf)

    def dump(self, shelf: Shelf) -> None:
        shelf.update({k: v for k, v in self.lmds.items()}) 



