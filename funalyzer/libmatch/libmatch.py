from binaryninja.log import log_debug, log_error, log_warn, log_info
from funalyzer.libmatch.functiondiff import FunctionDiff
from funalyzer.core.parser import LibDescriptor, UniformedFunction
from funalyzer.core.database import FunalyzerDatabase
from collections import defaultdict
from typing import Dict, DefaultDict, List, Set, Tuple


class LibMatch(object):
    def __init__(self, binary_desc: LibDescriptor, db: FunalyzerDatabase):
        """
        :param binary_lmd: The LibMatchDescriptor of the target binary
        :param lib_lmds: An iterable of LibMatchDescriptors corresponding to libraries
        """
        self.binary_desc = binary_desc
        self.fdb = db
        self.ambiguous_funcs = []
        self._computed = False
        self._first_order_matches: DefaultDict[str, Dict[LibDescriptor, Dict[int, Set]]] = defaultdict()
        self._second_order_matches: DefaultDict[str, Dict[LibDescriptor, Dict[int, List[Tuple[int, FunctionDiff]]]]] = (
            defaultdict(dict)
        )

    def compute(self) -> None:
        """
        Orchestrates the main steps of the library matching process.
        This function serves as a high-level entry point to trigger the matching pipeline.
        """
        log_info("Starting the library matching computation...")

        for libname, descriptor in self.fdb.items():
            self._compute_first_order_matches(libname, descriptor)
            self._compute_second_order_matches(lib_name=libname)
            self._compute_third_order()
            self._compute_fourth_order()

        # Post-processing and deduplication
        self._dedup()

        self._computed = True

        log_info("Library matching computation completed.")

    def match(self, score: bool = True) -> Dict[int, str] | None:
        if not self._computed:
            self.compute()

        candidates: DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]] = self._candidate_matches
        plain_candidates: DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]] = self._plain_matches

        candidates = self._smoosh(candidates)
        plain_candidates = self._smoosh(plain_candidates)
        if score:
            # log_info("############### UNREFINED MATCHES ###############")
            self.score_matches(self.binary_desc, plain_candidates, self.fdb)
            # log_info("############### FINAL MATCHES ###############")
            self.score_matches(self.binary_desc, candidates, self.fdb)

        return self._postprocess_matches(self.binary_desc, candidates)

    def score_matches(
        self,
        target_desc: LibDescriptor,
        matches: DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]],
        fdb: FunalyzerDatabase,
    ) -> None:
        precise_matches = 0
        imprecise_matches = 0
        incorrect_matches = 0
        missing = 0
        guesses = 0
        targ_sym_addrs = set(target_desc.viable_func_addrs)
        scorable_syms = targ_sym_addrs.intersection(fdb.symbol_addresses)
        total_syms = len(scorable_syms)
        ignored = 0
        addrs_to_names = defaultdict(list)
        for sym in target_desc.viable_func_addrs:
            # TODO: the following line is not correct, it should map sym.rebased_addr to sym.name
            addrs_to_names[sym].append(sym)

        for sym in target_desc.viable_func_addrs:
            if sym not in scorable_syms:  # TODO: original: sym.name not in ...
                # Maybe it's some app code we guessed
                f_addr = sym  # TODO: original: sym.rebased_addr
                if f_addr in matches:
                    match_infos = matches[f_addr]
                    if len(match_infos) == 1:
                        for lib, desc, match in match_infos:
                            if isinstance(match, str):
                                # we just have the name
                                sym_name = match.library_func.name
                                guesses += 1
                                log_info(f"{f_addr:x} => {sym_name} (Guessed)")
                            else:
                                ignored += 1
                continue
            f_addr = sym  # TODO: original: sym.rebased_addr
            if f_addr in target_desc.banned_addrs:
                ignored += 1
                log_info(f"{f_addr:x} => Junk")
            elif f_addr in matches:
                match_infos = matches[f_addr]
                if len(match_infos) == 1:
                    for lib, desc, match in match_infos:
                        similarity_score = 0.0
                        if isinstance(match, str):
                            # we just have the name
                            # obj_func_addr = 0
                            sym_name = match.library_func.name
                            # similarity_score = 0.0
                            filename = "(Guessed via context)"
                            guesses += 1
                        else:
                            # TODO: implement similarity_score
                            # similarity_score = match.similarity_score
                            obj_func_addr = match.library_func.start
                            sym_name = desc.uniformed_functions[obj_func_addr].name
                            filename = desc.filename
                        if sym_name in addrs_to_names[f_addr]:
                            log_info(f"{f_addr:x} => {lib}:{sym_name}({similarity_score}) [Correct!] in {filename}")
                            precise_matches += 1
                        else:
                            log_info(
                                f"{f_addr:x} => {lib}:{sym_name}({similarity_score}) [WRONG, {sym}] in "
                                "{desc.filename}"  # TODO: sym.name
                            )
                            incorrect_matches += 1
                elif len(match_infos) == 0:
                    missing += 1
                    log_info(f"{f_addr} => {sym}(UNMATCHED)")  # TODO: sym.name
                else:
                    imprecise_matches += 1
                    log_info(f"{f_addr:x}")
                    for lib, desc, match in match_infos:
                        obj_func_addr = match.library_func.start
                        sym_name = desc.uniformed_functions[obj_func_addr].name
                        # if sym_name == sym:  # TODO: sym.name
                        #     log_info(
                        #         green("\t=> %s:%s(%f) in %s" % (lib, sym_name, match.similarity_score, desc.filename))
                        #     )
                        # else:
                        #     log_info(
                        #         yellow("\t=> %s:%s(%f) in %s" % (lib, sym_name, match.similarity_score, desc.filename))
                        #     )
            else:
                missing += 1
                log_error(f"{f_addr:x} => {sym}(UNMATCHED)")  # TODO: sym.name
        # TODO: undo comment
        # log_info(f"Matched symbols: {precise_matches}")
        # log_info(f"Missing symbols: {missing}")
        # log_info(f"Incorrect symbols: {incorrect_matches}")
        # log_info(f"Imprecise matches: {imprecise_matches}")
        # log_info(f"Guesses: {guesses}")
        # log_info(f"Ignored: {ignored}")
        # log_info(f"Total symbols: {total_syms} ")
        # if total_syms != 0:
        #     log_info(f"Hit rate: {precise_matches / total_syms}")
        #     log_info(f"Error rate: {incorrect_matches / total_syms}")
        #     log_info(f"Collision rate: {imprecise_matches / total_syms}")
        # else:
        #     log_warn("'total_syms' is 0")

    def _postprocess_matches(
        self, target_lmd: LibDescriptor, results: DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]]
    ) -> Dict[int, str]:
        """Clean up the matches for the user.
        This encodes the behavior "we consider it a match if we match with exactly one name".

        Args:
            target_lmd (LibMatchDescriptor): The target library.
            results (dict): The results of all previous matchings.

        Returns:
            Dict[int, str]: A dictionary of addresses to symbol names.
        """
        final_matches = {}
        collisions = 0
        junk = 0
        guesses = 0
        for f_addr, match_infos in results.items():
            if len(match_infos) > 1:
                collisions += 1
                continue
            if f_addr not in target_lmd.viable_func_addrs:
                # we put a name on it, but it's a stub!
                junk += 1
                continue
            for _, desc, match in match_infos:
                if isinstance(match, str):
                    sym_name = match
                    guesses += 1
                else:
                    obj_func_addr = match.library_func.start
                    # sym_name = "name"
                    # TODO: implement get_func_by_addr
                    sym_name = desc.uniformed_functions[obj_func_addr].name
                final_matches[f_addr] = sym_name
        # TODO: undo comment
        # if collisions > 0:
        #     log_warn(f"Detected {collisions} collisions")
        # else:
        #     log_info(f"Detected {collisions} collisions")
        # if junk > 0:
        #     log_warn(f"Ignored {junk} junk function matches")
        # else:
        #     log_info(f"Ignored {junk} junk function matches")

        # log_info(f"Made {guesses} guesses")
        log_info(f"Matched {len(list(final_matches.keys()))} symbols")
        return final_matches

    def _smoosh(
        self, candidates: DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]]
    ) -> DefaultDict[int, list]:
        for f_addr, stuff in candidates.items():
            if len(stuff) <= 1:
                continue

            name = stuff[0][2].library_func.name
            for _, _, fdiff in stuff:  # lib, lmd, fd
                if name != fdiff.library_func.name:
                    break
            else:
                # Smoosh it!
                candidates[f_addr] = [stuff[0]]
        return candidates

    def _compute_first_order_matches(
        self, lib_name: str, lib_descriptor: LibDescriptor
    ) -> DefaultDict[str, Dict[LibDescriptor, Dict[int, Set]]] | None:
        """
        Find matches between a lib and the target binary based purely on function attribute tuples.
        """
        self._first_order_matches[lib_name] = {}
        self._first_order_matches[lib_name][lib_descriptor] = {}
        total_possible_matches = 0

        log_debug(f"functions: {len(self.binary_desc.function_attributes)}")

        for lib_func_addr in lib_descriptor.viable_func_addrs:
            attrs = lib_descriptor.function_attributes[lib_func_addr]
            possible_binary_func_matches: Set[int] = set()
            for bin_faddr, bin_attrs in self.binary_desc.function_attributes.items():
                if attrs == bin_attrs:
                    possible_binary_func_matches.add(bin_faddr)
            self._first_order_matches[lib_name][lib_descriptor][lib_func_addr] = possible_binary_func_matches

            total_possible_matches += len(possible_binary_func_matches)

        log_debug(f"Done with first order, found {total_possible_matches} possible matches {lib_descriptor}")

    def _second_order_heuristic(
        self, binary_desc: LibDescriptor, lib_desc: LibDescriptor, binary_faddr: int, lib_faddr: int
    ) -> FunctionDiff:
        """
        The heuristic to use to determine whether or not two functions are approximately the same
        based on the FunctionDiff implementation.
        """
        bin_func = binary_desc.uniformed_functions[binary_faddr]
        lib_func = lib_desc.uniformed_functions[lib_faddr]

        return FunctionDiff(binary_desc, lib_desc, bin_func, lib_func)

    def _compute_second_order_matches(self, lib_name) -> None:
        """
        Refine matches between a lib and the target binary based purely on the FunctionDiff method.
        """
        self._second_order_matches[lib_name] = {}
        for lib_desc, matches in self._first_order_matches[lib_name].items():
            self._second_order_matches[lib_name][lib_desc] = {}
            for lib_faddr, func_matches in matches.items():
                self._second_order_matches[lib_name][lib_desc][lib_faddr] = []
                for maddr in func_matches:
                    if maddr not in self.binary_desc.uniformed_functions:
                        continue
                    fdiff = self._second_order_heuristic(self.binary_desc, lib_desc, maddr, lib_faddr)
                    if fdiff.probably_identical:
                        self._second_order_matches[lib_name][lib_desc][lib_faddr].append((maddr, fdiff))

    def _postprocess_second_order_matches(self) -> DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]]:
        # Gather the matches based on the functions in the original binary:
        matches: DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]] = defaultdict(list)
        # for lib_res in self._second_order_matches:
        for lib_name, lib_matches in self._second_order_matches.items():
            for obj_libd, obj_res in lib_matches.items():
                for _, obj_func_matches in obj_res.items():  # obj_func_addr, obj_func_matches
                    if obj_func_matches:
                        for target_addr, match_info in obj_func_matches:
                            if len(matches[target_addr]) > 0:
                                # TODO
                                # A collision! But is it a real one?
                                # Did we match better?
                                # _, _, prev_match_info = matches[target_addr][0]  # prev_lib, prev_lmd,
                                # if match_info.similarity_score > prev_match_info.similarity_score:
                                #     # Better match
                                #     matches[target_addr] = [(lib_name, obj_libd, match_info)]
                                # elif match_info.similarity_score == prev_match_info.similarity_score:
                                #     matches[target_addr].append((lib_name, obj_libd, match_info))
                                # else:
                                #     continue  # Worse match, ignore
                                pass
                            else:
                                matches[target_addr].append((lib_name, obj_libd, match_info))
        return matches

    def _compute_third_order(self) -> None:
        self._plain_matches = self._postprocess_second_order_matches()
        self._candidate_matches = self._postprocess_second_order_matches()
        for f_addr, matches in self._candidate_matches.items():
            if matches:
                self._narrow_third_order(f_addr, matches)

    def _compute_fourth_order(self) -> None:
        self.recursion_list = []
        good_hits = []
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) == 1:
                good_hits.append(
                    (
                        f_addr,
                        matches,
                    )
                )
        for f_addr, matches in good_hits:
            self._narrow_fourth_order(f_addr, matches)

    def squish(self, func):
        """
        When resolving collisions, are all the collisions duplicates? If so, we probably don't care, and will handle it in post later
        (but we save the dupes for stats purposes)

        :return:
        """
        matches = self._candidate_matches[func]
        the_name = None
        if not matches:
            return
        for _, _, fd in matches:  # lib, lmd,
            if the_name is None:
                if isinstance(fd, str):
                    the_name = fd
                else:
                    the_name = fd.library_func.name
            if isinstance(fd, str) and the_name == fd:
                continue
            elif the_name == fd.library_func.name:
                continue
            elif isinstance(fd, UniformedFunction) and the_name == fd.name:
                continue
            else:
                return
        self._candidate_matches[func] = [matches[0]]

    recursion_list = []

    def _narrow_third_order(
        self, f_addr: int, matches: List[Tuple[str, LibDescriptor, FunctionDiff]], exact_narrowing=False
    ):
        """
        Refine candidate matches for a function based on its call graph context.

        Args:
            f_addr (int): Address of the function in the target binary.
            matches (list): Candidate matches for this function, each a tuple (lib_name, lib_descriptor, FunctionDiff or str).
            exact_narrowing (bool): If True, use stricter narrowing criteria.

        This method attempts to disambiguate matches by comparing callees of the candidate functions.
        """
        for match in matches:
            if not isinstance(match[-1], FunctionDiff):
                raise ValueError(f"third argument is not fdiff, but instead {type(match[-1])} in {match}")

        if f_addr in self.recursion_list:
            log_warn(f"Warning: recursion to {f_addr:x}!")
            return
        self.recursion_list.append(f_addr)

        if len(matches) == 1:
            # Perfect match, nothing to refine
            self.recursion_list.remove(f_addr)
            return

        log_info(f"Analyzing function {f_addr:x}")

        # Get the target function object from the first match's FunctionDiff (or string)
        first_match = matches[0]
        fdiff = first_match[2]
        if isinstance(fdiff, str):
            log_warn(f"Function {f_addr:x} has only guessed matches, cannot refine by call context.")
            self.recursion_list.remove(f_addr)
            return
        target_func = fdiff.library_func  # Binary Ninja Function object in target binary

        # Collect callees from the target function
        target_callees = []
        for _, callees in target_func.call_sites.items():
            callees_set: Set[Tuple[int, str]] = set()
            for callee_addr in callees:
                if not self.binary_desc.bv.is_valid_offset(callee_addr):
                    # Address outside the binary view
                    callee_name = "UnresolvableCallTarget"
                    callees_set.add((callee_addr, callee_name))
                elif callee_addr in self.binary_desc.banned_addrs:
                    callee_name = "Ignored"
                    callees_set.add((callee_addr, callee_name))
                elif callee_addr not in self._candidate_matches or len(self._candidate_matches[callee_addr]) == 0:
                    log_error(f"Cannot disambiguate function at {f_addr:x}, unmatched call to {callee_addr:x}")
                    self.ambiguous_funcs.append(f_addr)
                    self.recursion_list.remove(f_addr)
                    return
                else:
                    # Collect all possible callee names from candidate matches
                    callee_names = set()
                    for _, _, callee_fd_or_name in self._candidate_matches[callee_addr]:
                        if isinstance(callee_fd_or_name, str):
                            callee_names.add((callee_addr, callee_fd_or_name))
                        else:
                            callee_names.add((callee_addr, callee_fd_or_name.library_func.name))
                    callees_set.update(callee_names)
            target_callees.append(callees_set)

        # Now, for each candidate match, check if callees are compatible
        narrowed_matches = []
        for lib_name, lib_lmd, fdiff in matches:
            # if isinstance(fdiff, str):
            #     # Guessed name, keep only if exact narrowing is off
            #     if not exact_narrowing:
            #         narrowed_matches.append((lib_name, lib_lmd, fdiff))
            #     continue

            lib_func = fdiff.library_func  # Function in library
            lib_callees = []
            for callees in lib_func.call_sites.values():
                callees_set: Set[Tuple[int, str]] = set()
                for callee_addr in callees:
                    if not lib_lmd.bv.is_valid_offset(callee_addr):
                        callee_name = "UnresolvableCallTarget"
                        callees_set.add((callee_addr, callee_name))
                    elif callee_addr in lib_lmd.banned_addrs:
                        callee_name = "Ignored"
                        callees_set.add((callee_addr, callee_name))
                    else:
                        callee_func = lib_lmd.bv.get_function_at(callee_addr)
                        if callee_func is None:
                            callee_name = "Unknown"
                        else:
                            callee_name = callee_func.name
                        callees_set.add((callee_addr, callee_name))
                lib_callees.append(callees_set)

            # Compare callees sets between target and lib function
            if len(target_callees) != len(lib_callees):
                # Different number of call sites, discard if exact narrowing
                if exact_narrowing:
                    continue
                else:
                    narrowed_matches.append((lib_name, lib_lmd, fdiff))
                    continue

            # Check if all callees sets intersect non-empty
            compatible = True
            for t_callees, l_callees in zip(target_callees, lib_callees):
                if t_callees.isdisjoint(l_callees):
                    compatible = False
                    break

            if compatible:
                narrowed_matches.append((lib_name, lib_lmd, fdiff))

        if len(narrowed_matches) < len(matches):
            log_info(f"Narrowed matches for function {f_addr:#08x} from {len(matches)} to {len(narrowed_matches)}")
            self._candidate_matches[f_addr] = narrowed_matches
            # Recursively narrow callees
            for _, _, fdiff in narrowed_matches:
                if isinstance(fdiff, str):
                    continue
                for call_site in fdiff.function_a.call_sites:
                    _, callees = call_site
                    for callee_addr in callees:
                        if callee_addr in self._candidate_matches:
                            self._narrow_third_order(callee_addr, self._candidate_matches[callee_addr])
        else:
            log_info(f"No narrowing possible for function {f_addr:#08x}")

        self.recursion_list.remove(f_addr)

    def _narrow_fourth_order(self, f_addr, matches):
        """
        Further refine candidate matches for a function using advanced heuristics,
        such as analyzing recursion patterns or call graph consistency.

        Args:
            f_addr (int): Address of the function in the target binary.
            matches (list): Candidate matches for this function, each a tuple (lib_name, lib_descriptor, FunctionDiff or str).

        This method attempts to disambiguate matches by analyzing recursive calls,
        and possibly other heuristics beyond call graph similarity.
        """

        if len(matches) <= 1:
            # Nothing to refine if zero or one candidate
            return

        log_info(f"Fourth order narrowing on function {f_addr:#08x} with {len(matches)} candidates")

        # Extract the target function (Binary Ninja Function) from the first candidate
        first_match = matches[0]
        fd_or_name = first_match[2]
        if isinstance(fd_or_name, str):
            # If only guessed names, no further refinement possible
            log_warn(f"Function {f_addr:#08x} has only guessed matches, skipping fourth order narrowing")
            return

        target_func = fd_or_name.function_a  # Binary Ninja Function object in target binary

        # Check if the function is recursive in the target binary
        is_target_recursive = self._is_function_recursive(target_func)

        # Prepare a list to hold refined matches
        refined_matches = []

        for lib_name, lib_lmd, fd_or_name in matches:
            if isinstance(fd_or_name, str):
                # Keep guessed names only if no exact narrowing requested
                refined_matches.append((lib_name, lib_lmd, fd_or_name))
                continue

            lib_func = fd_or_name.function_b  # Binary Ninja Function object in library

            # Check if the candidate function is recursive
            is_lib_recursive = self._is_function_recursive(lib_func)

            # If recursion property mismatches, discard this candidate
            if is_target_recursive != is_lib_recursive:
                log_info(f"Discarding candidate {lib_func.name} for function {f_addr:#08x} due to recursion mismatch")
                continue

            # Additional heuristics can be added here, e.g., comparing loop structures,
            # instruction counts, or other function metrics.

            # If passed all heuristics, keep the candidate
            refined_matches.append((lib_name, lib_lmd, fd_or_name))

        if len(refined_matches) < len(matches):
            log_info(
                f"Fourth order narrowing reduced candidates for function {f_addr:#08x} from {len(matches)} to {len(refined_matches)}"
            )
            self._candidate_matches[f_addr] = refined_matches
        else:
            log_info(f"Fourth order narrowing could not reduce candidates for function {f_addr:#08x}")

    def _is_function_recursive(self, func):
        """
        Checks if a Binary Ninja function is directly recursive (calls itself).
        Args:
            func (binaryninja.Function): The function to check.
        Returns:
            bool: True if the function calls itself directly.
        """
        for ref in func.call_sites:
            # ref is a ReferenceSource object
            # Depending on BN version, ref.address, ref.target_address or ref.to must be used
            # The most reliable is ref.address (the call instruction) and ref.target (target address)

            callee_addr = None
            if hasattr(ref, "target"):
                callee_addr = ref.target
            elif hasattr(ref, "target_address"):
                callee_addr = ref.target_address
            elif hasattr(ref, "to"):
                callee_addr = ref.to
            else:
                # Fallback
                # TODO: try to get the called function from the instruction
                # This is more complicated; for now, skip
                continue

            if callee_addr == func.start:
                return True

        return False

    def _dedup(self):
        """
        Deduplicates candidate matches by resolving collisions and keeping only the best matches.
        """
        log_info("Starting deduplication of candidate matches...")
        # Iterate through candidate matches and resolve collisions
        for f_addr in list(self._candidate_matches.keys()):  # Use list() to avoid modifying dict while iterating
            matches = self._candidate_matches[f_addr]

            if not matches:
                continue  # Skip if no matches

            if len(matches) == 1:
                continue  # Skip if only one match

            # Implement your collision resolution logic here
            # Example: Keep only the match with the highest similarity score
            best_match = max(
                matches, key=lambda match: match[2].similarity_score if hasattr(match[2], "similarity_score") else 0
            )
            self._candidate_matches[f_addr] = [best_match]  # Keep only the best match
            log_info(
                f"Deduplicated function {f_addr:#08x}, keeping best match '{best_match[2].library_func.name if hasattr(best_match[2], 'function_b') else best_match[2]}'"
            )

        log_info("Deduplication of candidate matches completed.")
