from ctypes import Union
import binaryninja as bn
import types
import math
from typing import Any, Iterable, List, Tuple

from funalyzer.core.parser import LibDescriptor, UniformedBasicBlock, UniformedFunction


DIFF_TYPE = "type"
DIFF_VALUE = "value"


# exception for trying find basic block changes
class UnmatchedStatementsException(Exception):
    pass


# statement difference classes
class Difference(object):
    def __init__(self, diff_type, value_a, value_b):
        self.type = diff_type
        self.value_a = value_a
        self.value_b = value_b


class ConstantChange(object):
    def __init__(self, offset, value_a, value_b):
        self.offset = offset
        self.value_a = value_a
        self.value_b = value_b


def differing_constants(block_a, block_b):
    """
    Compares two basic blocks and finds all the constants that differ from the first block to the second.

    :param block_a: The first block to compare.
    :param block_b: The second block to compare.
    :returns:       Returns a list of differing constants in the form of ConstantChange, which has the offset in the
                    block and the respective constants.
    """
    statements_a = [s for s in block_a.vex.statements if s.tag != "Ist_IMark"] + [block_a.vex.next]
    statements_b = [s for s in block_b.vex.statements if s.tag != "Ist_IMark"] + [block_b.vex.next]
    if len(statements_a) != len(statements_b):
        raise UnmatchedStatementsException("Blocks have different numbers of statements")

    start_1 = min(block_a.instruction_addrs)
    start_2 = min(block_b.instruction_addrs)

    changes = []

    # check statements
    current_offset = None
    for statement, statement_2 in zip(statements_a, statements_b):
        # sanity check
        if statement.tag != statement_2.tag:
            raise UnmatchedStatementsException("Statement tag has changed")

        if statement.tag == "Ist_IMark":
            if statement.addr - start_1 != statement_2.addr - start_2:
                raise UnmatchedStatementsException("Instruction length has changed")
            current_offset = statement.addr - start_1
            continue

        differences = compare_statement_dict(statement, statement_2)
        if isinstance(differences, Difference):
            raise Exception(f"{differences=} can't be of type Difference")
        for d in differences:
            if d.type != DIFF_VALUE:
                raise UnmatchedStatementsException("Instruction has changed")
            else:
                changes.append(ConstantChange(current_offset, d.value_a, d.value_b))

    return changes


# TODO: cleanup / uniform these fucked up types
def compare_statement_dict(
    statement_1: Tuple[tuple, list] | Tuple[int, bytes, float, str] | List[Any] | float | str | bytes | None,
    statement_2,
) -> List[Difference] | Difference:
    # should return whether or not the statement's type/effects changed
    # need to return the specific number that changed too

    if type(statement_1) is not type(statement_2):
        return [Difference(DIFF_TYPE, None, None)]

    # None
    if statement_1 is None and statement_2 is None:
        return []

    # constants
    if isinstance(statement_1, (int, bytes, float, str)):
        if isinstance(statement_1, float) and math.isnan(statement_1) and math.isnan(statement_2):
            return []
        elif statement_1 == statement_2:
            return []
        else:
            return [Difference(None, statement_1, statement_2)]

    # tuples/lists
    if isinstance(statement_1, (tuple, list)):
        if len(statement_1) != len(statement_2):
            return Difference(DIFF_TYPE, None, None)

        differences: List[Difference] = []
        for s1, s2 in zip(statement_1, statement_2):
            ret_val = compare_statement_dict(s1, s2)
            if not isinstance(ret_val, list):
                raise Exception("value of {ret_val=} isn't what it should be")
            differences += ret_val
        return differences

    # Yan's weird types
    differences = []
    for attr in statement_1.__slots__:
        # don't check arch, property, or methods
        if attr == "arch":
            continue
        if hasattr(statement_1.__class__, attr) and isinstance(getattr(statement_1.__class__, attr), property):
            continue
        if isinstance(getattr(statement_1, attr), types.MethodType):
            continue

        new_diffs = compare_statement_dict(getattr(statement_1, attr), getattr(statement_2, attr))

        if not isinstance(new_diffs, Iterable):
            raise Exception("new_diffs is Difference, can't iterate")
        # set the difference types
        for diff in new_diffs:
            if diff.type is None:
                diff.type = attr
        differences += new_diffs

    return differences


class FunctionDiff:
    """
    This class computes the difference between two functions.
    """

    def __init__(
        self, binary_desc: LibDescriptor, library_desc: LibDescriptor, binary_func: UniformedFunction, library_func: UniformedFunction
    ):
        """
        :param binary_desc: The first Descriptor (owns function_a)
        :param library_desc: The second Descriptor (owns function_b)
        :param function_a: The first UniformedFunction object
        :param function_b: The second UniformedFunction object
        """
        self.ignored_expr_types = {
            bn.LowLevelILOperation.LLIL_CONST_PTR,
            bn.LowLevelILOperation.LLIL_LOAD,
            bn.LowLevelILOperation.LLIL_JUMP,
            bn.LowLevelILOperation.LLIL_CALL,
            bn.LowLevelILOperation.LLIL_TAILCALL,
        }

        self.library_desc: LibDescriptor = library_desc
        self.binary_desc: LibDescriptor = binary_desc
        self.binary_func: UniformedFunction = binary_func
        self.library_func: UniformedFunction = library_func

        self._block_matches: List = []
        self._probably_identical: bool | None = None

        self.compare_functions(self.binary_func, self.library_func)

    @property
    def probably_identical(self) -> bool:
        if not self._probably_identical:
            self._probably_identical = self.compare_functions(self.binary_func, self.library_func)
        return self._probably_identical

    @property
    def similarity_score(self):
        """
        Return the mean similarity for all matched blocks in the function
        """
        score = 0.0
        n = 0
        for b1, b2 in self._block_matches:
            score += self.block_similarity(b1, b2)
            n += 1
        return score / n


    def block_similarity(self, block_a: UniformedBasicBlock, block_b: UniformedBasicBlock) -> float:
        """Compute the similarity between two basic blocks.
        The similarity of the basic blocks, normalized for the base address of the block and function call addresses.

        Args:
            block_a (UniformedBasicBlock): BasicBlock from the binary function
            block_b (UniformedBasicBlock): BasicBlock from the library function

        Returns:
            float: A value between 0.0 and 1.0, where 1.0 means the blocks are identical and 0.0 means they are completely different.
        """

        if block_a is None or block_b is None:
            raise(f"block_a is None: {block_a is None}\nblock_b is None: {block_b is None}")

        # handle sim procedure blocks
        # if self.binary_desc.is_hooked(block_a) and self.library_desc.is_hooked(block_b):
        #     if self.binary_desc._sim_procedures[block_a] == self.library_desc._sim_procedures[block_b]:
        #         return 1.0
        #     else:
        #         return 0.0

        # block_a = self.binary_desc.normalized_blocks[(self.function_a.addr, block_a.addr)]
        # block_b = self.library_desc.normalized_blocks[(self.function_b.addr, block_b.addr)]

        # if both were None then they are assumed to be the same, if only one was the same they are assumed to differ
        # if block_a is None and block_b is None:
        #     return 1.0
        # elif block_a is None or block_b is None:
        #     return 0.0

        # get all elements for computing similarity
        tags_a = [s.tag for s in block_a.statements]
        tags_b = [s.tag for s in block_b.statements]
        consts_a = [c.value for c in block_a.all_constants if not self.binary_desc.loader.main_object.contains_addr(c.value)]
        consts_b = [c.value for c in block_b.all_constants if not (self.library_desc.loader.min_addr <= c.value < self.library_desc.loader.max_addr)]
        all_registers_a = [s.offset for s in block_a.statements if hasattr(s, "offset")]
        all_registers_b = [s.offset for s in block_b.statements if hasattr(s, "offset")]
        jumpkind_a = block_a.jumpkind
        jumpkind_b = block_b.jumpkind
        # compute total distance
        total_dist = 0
        total_dist += _levenshtein_distance(tags_a, tags_b)
        total_dist += _levenshtein_distance(block_a.operations, block_b.operations)
        total_dist += _levenshtein_distance(all_registers_a, all_registers_b)
        acceptable_differences = self._get_acceptable_constant_differences(block_a, block_b)
        total_dist += _normalized_levenshtein_distance(consts_a, consts_b, acceptable_differences)
        total_dist += 0 if jumpkind_a == jumpkind_b else 1

        # compute similarity
        num_values = max(len(tags_a), len(tags_b))
        num_values += max(len(consts_a), len(consts_b))
        num_values += max(len(block_a.operations), len(block_b.operations))
        num_values += 1  # jumpkind
        similarity = 1 - (float(total_dist) / num_values)

        return similarity



    def compare_functions(self, func1: UniformedFunction, func2: UniformedFunction) -> bool:
        """Compare two functions based on their normalized basic block content"""
        # Get basic blocks for each function
        blocks1 = list(func1.basic_blocks)
        blocks2 = list(func2.basic_blocks)

        if len(blocks1) != len(blocks2):
            return False

        # Compare each corresponding block
        for b1, b2 in zip(blocks1, blocks2):
            if b1 != b2:
                return False

        return True
