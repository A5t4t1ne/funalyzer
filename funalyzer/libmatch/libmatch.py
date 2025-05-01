from binaryninja.log import log_error, log_warn, log_info, log_debug
from .functiondiff import FunctionDiff
from ..core.parser import LibDescriptor, UniformedFunction
from ..core.database import FunalyzerDatabase
from collections import defaultdict
from typing import Any, Dict, DefaultDict, List, Set, Tuple
from clint.textui.colored import red, yellow, green


class LibMatch(object):
    def __init__(self, binary_desc: LibDescriptor, db: FunalyzerDatabase):
        """
        :param binary_lmd: The LibMatchDescriptor of the target binary
        :param lib_lmds: An iterable of LibMatchDescriptors corresponding to libraries
        """
        self.binary_desc = binary_desc
        self.fdb = db
        self.ambiguous_funcs = []
        self._first_order_matches: DefaultDict[str, Dict[LibDescriptor, Dict[int, Set]]] = defaultdict()
        self._second_order_matches: DefaultDict[str, Dict[Any, Dict[int, List[Tuple[int, Any]]]]] = defaultdict(dict)

        self._compute()

    def match(self, lib_descriptor: LibDescriptor, database: FunalyzerDatabase, score=False):
        candidates: defaultdict = self._candidate_matches
        plain_candidates: defaultdict = self._plain_matches
        # TODO: This is where we put multi-library heuristics!

        candidates = self._smoosh(candidates)
        plain_candidates = self._smoosh(plain_candidates)
        if score:
            log_info("############### UNREFINED MATCHES ###############")
            self.score_matches(lib_descriptor, plain_candidates, database)
            input()
            log_info("############### FINAL MATCHES ###############")
            self.score_matches(lib_descriptor, candidates, database)

        out = self._postprocess_matches(lib_descriptor, candidates)
        return out

    def score_matches(self, target_desc: LibDescriptor, matches, lmdb):
        precise_matches = 0
        imprecise_matches = 0
        incorrect_matches = 0
        missing = 0
        guesses = 0
        targ_sym_names = {x.name for x in target_desc.viable_symbols}
        scorable_syms = targ_sym_names.intersection(lmdb.symbol_names)
        total_syms = len(scorable_syms)
        ignored = 0
        addrs_to_names = defaultdict(list)
        for sym in target_desc.viable_symbols:
            addrs_to_names[sym.rebased_addr].append(sym.name)

        for sym in target_desc.viable_symbols:
            if sym.name not in scorable_syms:
                # Maybe it's some app code we guessed
                f_addr = sym.rebased_addr
                if f_addr in matches:
                    match_infos = matches[f_addr]
                    if len(match_infos) == 1:
                        for lib, lmd, match in match_infos:
                            if isinstance(match, str):
                                # we just have the name
                                sym_name = match
                                guesses += 1
                                log_info(yellow("%#08x => %s (Guessed)" % (f_addr, sym_name)))
                            else:
                                ignored += 1
                continue
            f_addr = sym.rebased_addr
            if f_addr in target_desc.banned_addrs:
                ignored += 1
                log_info("%#08x => Junk" % (f_addr))
            elif f_addr in matches:
                match_infos = matches[f_addr]
                if len(match_infos) == 1:
                    for lib, lmd, match in match_infos:
                        if isinstance(match, str):
                            # we just have the name
                            obj_func_addr = 0
                            sym_name = match
                            similarity_score = 0.0
                            filename = "(Guessed via context)"
                            guesses += 1
                        else:
                            similarity_score = match.similarity_score
                            obj_func_addr = match.function_b.addr
                            sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
                            filename = lmd.filename
                        if sym_name in addrs_to_names[f_addr]:
                            log_info(
                                green(
                                    "%#08x => %s:%s(%f) [Correct!] in %s"
                                    % (f_addr, lib, sym_name, similarity_score, filename)
                                )
                            )
                            precise_matches += 1
                        else:
                            log_info(
                                red(
                                    "%#08x => %s:%s(%f) [WRONG, %s] in %s"
                                    % (f_addr, lib, sym_name, similarity_score, sym.name, lmd.filename)
                                )
                            )
                            incorrect_matches += 1
                elif len(match_infos) == 0:
                    missing += 1
                    log_info(red("%#08x => %s(UNMATCHED)" % (f_addr, sym.name)))
                else:
                    imprecise_matches += 1
                    log_info(yellow("%#08x" % f_addr))
                    for lib, lmd, match in match_infos:
                        obj_func_addr = match.function_b.addr
                        sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
                        if sym_name == sym.name:
                            log_info(
                                green("\t=> %s:%s(%f) in %s" % (lib, sym_name, match.similarity_score, lmd.filename))
                            )
                        else:
                            log_info(
                                yellow("\t=> %s:%s(%f) in %s" % (lib, sym_name, match.similarity_score, lmd.filename))
                            )
            else:
                missing += 1
                log_error("%#08x => %s(UNMATCHED)" % (f_addr, sym.name))
        log_info(f"Matched symbols: {precise_matches}")
        log_info(f"Missing symbols: {missing}")
        log_info(f"Incorrect symbols: {incorrect_matches}")
        log_info(f"Imprecise matches: {imprecise_matches}")
        log_info(f"Guesses: {guesses}")
        log_info(f"Ignored: {ignored}")
        log_info(f"Total symbols: {total_syms} ")
        log_info(f"Hit rate: {precise_matches / total_syms}")
        log_info(f"Error rate: {incorrect_matches / total_syms}")
        log_info(f"Collision rate: {imprecise_matches / total_syms:}")

    @classmethod
    def _first_order_heuristic(cls, lib_attrs, bin_attrs) -> bool:
        """
        The heuristic to use to determine whether or not a given tuple of attrs from a lib func
        should match with a given tuple of attrs from a bin func.
        """
        # TODO: perfect matching
        return lib_attrs == bin_attrs

    def _postprocess_matches(self, target_lmd: LibDescriptor, results: dict) -> Dict[int, str]:
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
            if f_addr not in target_lmd.viable_functions:
                # we put a name on it, but it's a stub!
                junk += 1
                continue
            for _, lmd, match in match_infos:
                if isinstance(match, str):
                    sym_name = match
                    guesses += 1
                else:
                    obj_func_addr = match.function_b.addr
                    sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
                final_matches[f_addr] = sym_name
        if collisions > 0:
            log_warn(f"Detected {collisions} collisions")
        else:
            log_info(f"Detected {collisions} collisions")
        if junk > 0:
            log_warn(f"Ignored {junk} junk function matches")
        else:
            log_info(f"Ignored {junk} junk function matches")

        log_info(f"Made {guesses} guesses")
        log_info(f"Matched {len(list(final_matches.keys()))} symbols")
        return final_matches

    def _smoosh(self, candidates):
        for f_addr, stuff in candidates.items():
            if len(stuff) <= 1:
                continue

            name = stuff[0][2].function_b.name
            for _, _, fd in stuff:  # lib, lmd, fd
                if name != fd.function_b.name:
                    break
            else:
                # Smoosh it!
                candidates[f_addr] = [stuff[0]]
        return candidates

    def _compute_first_order_matches(self, lib_name: str, lib_descriptors) -> DefaultDict[str, Dict[LibDescriptor, Dict[int, Set]]] | None:
        """
        Find matches between a lib and the target binary based purely on function attribute tuples.
        """
        self._first_order_matches[lib_name] = {}
        for descriptor in lib_descriptors:
            self._first_order_matches[lib_name][descriptor] = {}

            for faddr in descriptor.viable_functions:
                # match the lib func against the binary if the first order heuristic passes
                attrs = descriptor.function_attributes[faddr]
                results = set()
                # results = {bin_faddr for bin_faddr, bin_attrs in self.binary_lmd.function_attributes.items()
                #           if self._first_order_heuristic(attrs, bin_attrs)}
                for bin_faddr, bin_attrs in self.binary_desc.function_attributes.items():
                    if faddr == 0x4002BD and bin_faddr == 0x00003D45:
                        # TODO: Why?
                        # import ipdb

                        # ipdb.set_trace()
                        pass
                    if self._first_order_heuristic(attrs, bin_attrs):
                        results.add(bin_faddr)
                self._first_order_matches[lib_name][descriptor][faddr] = results

    @classmethod
    def _second_order_heuristic(cls, binary_lmd, lib_lmd, binary_faddr, lib_faddr):
        """
        The heuristic to use to determine whether or not two functions are approximately the same
        based on the FunctionDiff implementation.
        """
        lib_func = lib_lmd.normalized_functions[lib_faddr]
        bin_func = binary_lmd.normalized_functions[binary_faddr]
        # TODO: perfect matching
        return FunctionDiff(binary_lmd, lib_lmd, bin_func, lib_func)

    def _compute_second_order_matches(self, lib_name):
        """
        Refine matches between a lib and the target binary based purely on the FunctionDiff method.
        """
        self._second_order_matches[lib_name] = {}
        for lmd, lmd_matches in self._first_order_matches[lib_name].items():
            self._second_order_matches[lib_name][lmd] = {}
            for faddr, func_matches in lmd_matches.items():
                self._second_order_matches[lib_name][lmd][faddr] = []
                for maddr in func_matches:
                    fd = self._second_order_heuristic(self.binary_desc, lmd, maddr, faddr)
                    if fd.function_a.name == "tcp_recved" and fd.function_b.name == "tcp_recved":
                        # TODO: Why?
                        # import ipdb

                        # ipdb.set_trace()
                        pass
                    if fd.probably_identical:
                        self._second_order_matches[lib_name][lmd][faddr].append((maddr, fd))

    def _postprocess_second_order_matches(self) -> DefaultDict[int, list]:
        # Gather the matches based on the functions in the original binary:
        matches: DefaultDict[int, List[Tuple[str, LibDescriptor, FunctionDiff]]] = defaultdict(list)
        # for lib_res in self._second_order_matches:
        for lib_name, lib_matches in self._second_order_matches.items():
            for obj_lmd, obj_res in lib_matches.items():
                for _, obj_func_matches in obj_res.items():  # obj_func_addr, obj_func_matches
                    if obj_func_matches:
                        for target_addr, match_info in obj_func_matches:
                            if len(matches[target_addr]) > 0:
                                # A collision! But is it a real one?
                                # Did we match better?
                                _, _, prev_match_info = matches[target_addr][0]  # prev_lib, prev_lmd,
                                if match_info.similarity_score > prev_match_info.similarity_score:
                                    # Better match
                                    matches[target_addr] = [(lib_name, obj_lmd, match_info)]
                                elif match_info.similarity_score == prev_match_info.similarity_score:
                                    matches[target_addr].append((lib_name, obj_lmd, match_info))
                                else:
                                    continue  # Worse match, ignore
                            else:
                                matches[target_addr].append((lib_name, obj_lmd, match_info))
        return matches

    def _compute_third_order(self):
        self._plain_matches = self._postprocess_second_order_matches()
        self._candidate_matches = self._postprocess_second_order_matches()
        for f_addr, matches in self._candidate_matches.items():
            if matches:
                self._narrow_third_order(f_addr, matches)

    def _compute_fourth_order(self):
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
                    the_name = fd.function_b.name
            if isinstance(fd, str) and the_name == fd:
                continue
            # elif the_name == fd.function_b.name:
            #    continue
            elif isinstance(fd, UniformedFunction) and the_name == fd.name:
                continue
            else:
                return
        self._candidate_matches[func] = [matches[0]]

    recursion_list = []

    def _narrow_third_order(self, f_addr, matches, exact_narrowing=False):
        # TODO: FIXME:
        # It's possible that you get a single match, and this match is good, but it's wrong, due to function call targets.
        # Maybe we should check everything, even if it has more than one match.
        # No match is better than one wrong one!
        if f_addr in self.recursion_list:
            log_warn("Oof, recursion to %#08x!" % f_addr)
            return
        self.recursion_list.append(f_addr)
        if len(matches) == 1:
            # Perfect match! cannot refine
            self.recursion_list.remove(f_addr)
            return
        log_info("Analyzing function %#08x" % f_addr)
        # Get the target for each candidate match
        target_func = list(matches)[0][2].function_a
        target_callees = []
        for _, callees in target_func.call_sites.items():  # from_block, callees
            for callee in callees:
                if not self.binary_desc.loader.main_object.contains_addr(callee):
                    # A jumpout! Fuck.
                    callee_name = "UnresolvableCallTarget"
                    target_callees.append(
                        {
                            (
                                callee,
                                callee_name,
                            )
                        }
                    )
                elif callee in self.binary_desc.banned_addrs:
                    callee_name = "Ignored"
                    target_callees.append(
                        {
                            (
                                callee,
                                callee_name,
                            )
                        }
                    )
                elif callee not in self._candidate_matches or len(self._candidate_matches[callee]) == 0:
                    log_error("Cannot disambiguate function at %#08x, unmatched call to %#08x" % (f_addr, callee))
                    self.ambiguous_funcs.append(f_addr)
                    self.recursion_list.remove(f_addr)
                    return  # We're fucked
                else:
                    callee_matches = self._candidate_matches[callee]
                    if len(callee_matches) > 1:
                        if callee == f_addr:
                            log_warn("Recursion is bad!")
                            continue
                        log_error("Recursively resolving %#08x" % callee)
                        self._narrow_third_order(callee, callee_matches)
                        self.squish(callee)

                        if exact_narrowing and len(self._candidate_matches[callee]) > 1:
                            log_error("Failed to narrow down call to %#08x" % callee)
                            self.ambiguous_funcs.append(f_addr)
                            self.recursion_list.remove(f_addr)
                            return
                    possible_callees = set()
                    for cm in callee_matches:
                        _, m_lmd, m_fd = cm  # m_lib, m_lmd, m_fd
                        callee_sym = m_lmd.symbol_for_addr(m_fd.function_b.addr)
                        if not callee_sym:
                            continue
                        callee_name = callee_sym.name
                        possible_callees.add(
                            (
                                callee,
                                callee_name,
                            )
                        )
                    target_callees.append(possible_callees)
        if not target_callees:
            log_error("No calls in function %#08x, cannot disambiguate" % f_addr)
            self.ambiguous_funcs.append(f_addr)
            return
        # For each possible match
        self._candidate_matches[f_addr] = []
        log_debug("Resolving Function %#08x" % f_addr)
        for lib_name, match_lmd, match_diff in matches:
            match_name = match_diff.function_b.name
            # Get the addresses of each function that library calls.
            lib_callees = []
            for lol in match_diff.function_b.call_sites.values():
                for lmao in lol:
                    lib_callees.append(lmao)
            # Here, we try to compare the functions we matched via direct block comparison with libraries, based on what we think
            # the target actually called.
            # However, we may not be able to accurately resolve the target's callees, so we check that, for each candidate
            # library function, its exact callees are in the set of potential callees in the target.
            # If not, we rule it out.
            for possible_targ_callees, lib_callee in zip(target_callees, lib_callees):
                if not possible_targ_callees:
                    continue
                try:
                    targ_callee_addr = list(possible_targ_callees)[0][0]
                    lib_callee_name = match_lmd.symbol_for_addr(lib_callee).name
                except Exception as e:
                    log_error(f"Hmm, something is wrong %#08x %#08x %s\n{e}" % (f_addr, lib_callee, match_lmd.filename))
                    return
                for targ_callee in possible_targ_callees:
                    targ_callee_addr, targ_callee_name = targ_callee
                    if targ_callee_name == "Ignored":
                        log_debug("Ignoring unresolvable call to %#08x" % targ_callee_addr)
                        break
                    if targ_callee_name == lib_callee_name:
                        log_debug("\t\tMatched call to %s" % targ_callee_name)
                        break
                else:
                    log_debug("\tRuling out %s due to mismatched call to %#08x" % (lib_callee_name, targ_callee_addr))
                    break
            else:
                self._candidate_matches[f_addr].append((lib_name, match_lmd, match_diff))
                log_error("Resolved call to %#08x to %s via callgraph" % (f_addr, match_name))
        self.recursion_list.remove(f_addr)

    def _narrow_fourth_order(self, f_addr, matches):
        """
        By now, we've probably matched a bunch of functions.  But we can't get them all.
        This will use those functions we could match to find the ones we can't.
        In contrast to the third phase, which uses callees to find callers, this does the opposite.
        For each function we can precisely match, collect the set of callees, and assign names to them based on the
        symbols in the source library.

        :param f_addr:
        :param matches:
        :return:
        """
        if f_addr in self.recursion_list:
            log_warn("Oof, recursion to %#08x!" % f_addr)
            return
        self.recursion_list.append(f_addr)
        if len(matches) != 1:
            self.recursion_list.remove(f_addr)
            return
        m_lib, m_lmd, m_fd = matches[0]
        if isinstance(m_fd, str):
            # We've already been here
            self.recursion_list.remove(f_addr)
            return
        target_func = m_fd.function_a
        lib_func = m_fd.function_b
        for (_, targ_callees), (_, lib_callees) in zip(  # (targ_block, targ_callees), (lib_block, lib_callees)
            target_func.call_sites.items(), lib_func.call_sites.items()
        ):
            for targ_callee, lib_callee in zip(targ_callees, lib_callees):
                if not self.binary_desc.loader.main_object.contains_addr(targ_callee):
                    # A jumpout! Fuck.
                    continue
                elif targ_callee in self.binary_desc.banned_addrs:
                    # Junk.
                    continue
                elif targ_callee not in self._candidate_matches or len(self._candidate_matches[targ_callee]) == 0:
                    # Take a wild guess based on context
                    # Assuming the current match is correct, figure out what it would call in the original
                    # library and make that the name to match.
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if guessed_sym is None:
                        log_info(
                            "No findable name for call to %#08x from %#08x(%s)"
                            % (targ_callee, target_func.addr, lib_func.name)
                        )
                    else:
                        guessed_name = guessed_sym.name
                        log_info(
                            "Guessing name of %#08x is %s due to call from %#08x(%s)"
                            % (targ_callee, guessed_name, target_func.addr, lib_func.name)
                        )
                        self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                elif len(self._candidate_matches[targ_callee]) == 1:
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if guessed_sym is None:
                        log_info(
                            "No findable name for call to %#08x from %#08x(%s)"
                            % (targ_callee, target_func.addr, lib_func.name)
                        )
                    else:
                        guessed_name = guessed_sym.name
                        _, _, fd = self._candidate_matches[targ_callee][0]  # lol, blah, fd
                        if isinstance(fd, str):
                            if fd == guessed_name:
                                continue
                        else:
                            if fd.function_b.name == guessed_name:
                                continue
                        log_info(
                            "Guessing name of %#08x is %s due to call from %#08x(%s)"
                            % (targ_callee, guessed_name, target_func.addr, lib_func.name)
                        )
                        self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                    # Nothing to do
                    continue
                else:
                    # We have a collision.  Resolve it by picking the one with the matching
                    # name based on the lib's symbols
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if not guessed_sym:
                        log_warn(
                            "Couldn't figure out what %#08x is, called by func %#08x" % (lib_callee, lib_func.addr)
                        )
                        continue
                    guessed_name = guessed_sym.name
                    new_matches = []
                    for match in self._candidate_matches[targ_callee]:
                        c_lib, c_lmd, c_fd = match
                        if c_fd.function_b.name == guessed_name:
                            log_info(
                                "Resolving %#08x to %s via call from %#08x(%s)"
                                % (targ_callee, guessed_name, target_func.addr, lib_func.name)
                            )
                            new_matches.append(
                                (
                                    c_lib,
                                    c_lmd,
                                    c_fd,
                                )
                            )
                    self._candidate_matches[targ_callee] = new_matches
                    if not new_matches:
                        # Welp, it really wasn't the other ones.
                        # Try something new instead
                        guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                        if guessed_sym is None:
                            log_info(
                                "No findable name for call to %#08x from %#08x(%s)"
                                % (targ_callee, target_func.addr, lib_func.name)
                            )
                        else:
                            guessed_name = guessed_sym.name
                            log_info(
                                "Guessing name of %#08x is %s due to call from %#08x(%s)"
                                % (targ_callee, guessed_name, target_func.addr, lib_func.name)
                            )
                            self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                    self.squish(targ_callee)
                    if len(self._candidate_matches[targ_callee]) == 1:
                        # Recurse, see if that helps any.
                        log_info("Recursively resolving %#08x" % targ_callee)
                        self._narrow_fourth_order(targ_callee, self._candidate_matches[targ_callee])
        self.recursion_list.remove(f_addr)

    def _dedup(self):
        """
        During all the previous phases, we'll make guesses, and all sorts of cool stuff.
        Now we have a bit of cleanup to do.  If we guessed a name for a function x, and a collision for
        function y includes the name of x, take it out of y's list, as we assume we can only have one copy of x in the binary
        THis means, by process of elimination, we may get even more matches!
        :return:
        """
        import copy

        good_hits = []
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) == 1:
                _, _, m_fd = matches[0]  # m_lib, m_lmd, m_fd
                if isinstance(m_fd, str):
                    # A guess has no fd
                    good_hits.append(m_fd)
                else:
                    good_hits.append(m_fd.function_b.name)
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) > 1:
                fixed_matches = copy.copy(matches)
                for match in matches:
                    _, _, m_fd = match  # m_lib, m_lmd, m_fd
                    if m_fd.function_b.name in good_hits:
                        log_info("Removing %s from consideration for %#08x" % (m_fd.function_b.name, f_addr))
                        fixed_matches.remove(match)
                self._candidate_matches[f_addr] = fixed_matches

    def _compute(self):
        """
        Compute everything, hopefully resulting in matches!
        """
        # first, find all first order matches (matches depending only on the attr tuples)
        log_info("Phase 1: Coarse statistical matching")
        for lib, lib_lmds in self.fdb.lib_descriptors.items():
            self._compute_first_order_matches(lib, lib_lmds)
        log_info("Phase 2: FunctionDiff")
        for lib in self.fdb.lib_descriptors:
            self._compute_second_order_matches(lib)
        log_info("Phase 3: Callee context")
        self._compute_third_order()
        log_info("Phase 4: Caller context")
        self._compute_fourth_order()
        log_info("Phase 5: Cleanup")
        self._dedup()
