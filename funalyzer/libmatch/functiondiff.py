import binaryninja as bn
import types
import math
import debugpy
from typing import Any, Iterable, List, Set, Tuple


from binaryninja.architecture import RegisterName

from funalyzer.core.parser import LibDescriptor, UniformedBasicBlock, UniformedFunction, UniformedInstruction


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


def _levenshtein_distance(
    s1: List[UniformedInstruction] | List[RegisterName] | List[str],
    s2: List[UniformedInstruction] | List[RegisterName] | List[str],
) -> int:
    """Computes the Levenshtein distance between two strings or lists.

    Args:
        s1 (LevDistArgType): The first list to compare.
        s2 (LevDistArgType): The second list to compare.

    Returns:
        int: The Levenshtein distance between the two strings or lists.
    """

    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for index2, num2 in enumerate(s2):
        new_distances = [index2 + 1]
        for index1, num1 in enumerate(s1):
            if num1 == num2:
                new_distances.append(distances[index1])
            else:
                new_distances.append(1 + min((distances[index1], distances[index1 + 1], new_distances[-1])))
        distances = new_distances
    return distances[-1]


def _normalized_levenshtein_distance(s1: List[int], s2: List[int], acceptable_differences: Set[int]) -> int:
    """Computes the normalized Levenshtein distance between two lists of integers, allowing for acceptable differences.

    Args:
        s1 (List[int]): The first list of integers to compare.
        s2 (List[int]): The second list of integers to compare.
        acceptable_differences (Set[int]): A set of numbers. If (s2[i]-s1[i]) is in the set then they are considered equal. 

    Returns:
        int: The normalized Levenshtein distance between the two lists.
    """
    if len(s1) > len(s2):
        s1, s2 = s2, s1
        acceptable_differences = set(-i for i in acceptable_differences)
    distances = range(len(s1) + 1)
    for index2, num2 in enumerate(s2):
        new_distances = [index2 + 1]
        for index1, num1 in enumerate(s1):
            if num2 - num1 in acceptable_differences:
                new_distances.append(distances[index1])
            else:
                new_distances.append(1 + min((distances[index1], distances[index1 + 1], new_distances[-1])))
        distances = new_distances
    return distances[-1]


class FunctionDiff:
    """
    This class computes and represents the difference between two functions.

    Args:
        binary_desc (LibDescriptor): The descriptor of the target binary (owns binary_func)
        library_desc (LibDescriptor): The descriptor of the library (owns library_func)
        binary_func (UniformedFunction): The function from the binary to compare.
        library_func (UniformedFunction): The function from the library to compare.
    """

    def __init__(
        self,
        binary_desc: LibDescriptor,
        library_desc: LibDescriptor,
        binary_func: UniformedFunction,
        library_func: UniformedFunction,
    ):
        self.ignored_expr_types = {
            bn.LowLevelILOperation.LLIL_CONST_PTR,
            bn.LowLevelILOperation.LLIL_LOAD,
            bn.LowLevelILOperation.LLIL_JUMP,
            bn.LowLevelILOperation.LLIL_CALL,
            bn.LowLevelILOperation.LLIL_TAILCALL,
        }
        self._block_matches: List[Tuple[UniformedBasicBlock, UniformedBasicBlock]] = []

        self.binary_desc = binary_desc
        self.library_desc = library_desc
        self.binary_func = binary_func
        self.library_func = library_func

        self._similarity_score: float | None = None
        self._probably_identical: bool | None = None

    @property
    def probably_identical(self) -> bool:
        if not self._probably_identical:
            self._probably_identical = self.compare_functions(self.binary_func, self.library_func)
        return self._probably_identical

    @property
    def similarity_score(self):
        """Computes a similarity score between the two functions."""
        if self._similarity_score is not None:
            return self._similarity_score

        score = 0.0
        n = 0
        for b1, b2 in self._block_matches:
            score += self.block_similarity(b1, b2)
            n += 1
        self._similarity_score = score / n if n > 0 else 0

        return self._similarity_score

    def block_similarity(self, block_a: UniformedBasicBlock | None, block_b: UniformedBasicBlock | None) -> float:
        """Computes the similarity between two basic blocks.

        Args:
            block_a (UniformedBasicBlock | None): First basic block to compare.
            block_b (UniformedBasicBlock | None): Second basic block to compare.

        Returns:
            float: The similarity of the basic blocks, normalized for the base address of the block and function call addresses.
        """

        # if both were None then they are assumed to be the same, if only one was the same they are assumed to differ
        if block_a is None and block_b is None:
            return 1.0
        elif block_a is None or block_b is None:
            return 0.0

        similarity = 0.0
        # get all elements for computing similarity
        # compute total distance
        total_dist = 0
        total_dist += _levenshtein_distance(block_a.statements, block_b.statements)
        # total_dist += _levenshtein_distance(block_a.instructions, block_b.instructions)
        total_dist += _levenshtein_distance(block_a.all_regs, block_b.all_regs)
        acceptable_differences = self._get_acceptable_constant_differences(block_a, block_b)
        total_dist += _normalized_levenshtein_distance(
            block_a.all_constants, block_b.all_constants, acceptable_differences
        )
        total_dist += 0 if block_a.jumpkind == block_b.jumpkind else 1

        # compute similarity
        num_values = 0
        num_values += max(len(block_a.statements), len(block_b.statements))
        num_values += max(len(block_a.all_constants), len(block_b.all_constants))
        num_values += max(len(block_a.instructions), len(block_b.instructions))
        num_values += 1  # jumpkind
        similarity = 1 - (float(total_dist) / num_values)

        return similarity

    def compare_functions(self, func1: UniformedFunction, func2: UniformedFunction) -> bool:
        """Compare two functions based on their normalized basic block content"""
        # Get basic blocks for each function
        blocks1 = list(func1.basic_blocks.items())
        blocks2 = list(func2.basic_blocks.items())

        if len(blocks1) != len(blocks2):
            return False

        # Compare each corresponding block
        for (_, b1), (_, b2) in zip(blocks1, blocks2):
            if b1 != b2:
                return False
            else:
                self._block_matches.append((b1, b2))

        return True

    def _get_acceptable_constant_differences(
        self, block_a: UniformedBasicBlock, block_b: UniformedBasicBlock
    ) -> Set[int]:
        # keep a set of the acceptable differences in constants between the two blocks
        acceptable_differences: Set[int] = set()
        acceptable_differences.add(0)

        if not block_a.instruction_addrs or not block_b.instruction_addrs:
            return set()

        acceptable_differences.add(block_b.start - block_a.start)

        # get matching successors
        for target_a, target_b in zip(block_a.call_targets, block_b.call_targets):
            # these can be none if we couldn't resolve the call target
            if target_a is None or target_b is None:
                continue
            acceptable_differences.add(target_b - target_a)
            acceptable_differences.add((target_b - block_b.start) - (target_a - block_a.start))

        # TODO: in original implementation there is more commented out code here, maybe necessary

        return acceptable_differences
