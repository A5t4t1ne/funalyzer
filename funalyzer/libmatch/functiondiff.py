from ctypes import Union
import binaryninja as bn
import types
import math
from typing import Any, Iterable, List, Tuple

from funalyzer.core.parser import LibDescriptor, UniformedFunction


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
    This class computes the diff between two functions.
    """

    def __init__(
        self, binary_desc: LibDescriptor, library_desc: LibDescriptor, binary_func: UniformedFunction, library_func: UniformedFunction
    ):
        """
        :param lmd_a: The first Descriptor (owns function_a)
        :param lmd_b: The second Descriptor (owns function_b)
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

        self.libd = binary_desc
        self.binary_desc = library_desc
        self.binary_func = binary_func
        self.library_func = library_func
        self.similarity_score = 0 # TODO: implement

        self._probably_identical: bool | None = None
        self.compare_functions(self.binary_func, self.library_func)

    @property
    def probably_identical(self) -> bool:
        if not self._probably_identical:
            self._probably_identical = self.compare_functions(self.binary_func, self.library_func)
        return self._probably_identical

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
