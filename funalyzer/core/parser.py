from ctypes import ArgumentError
from enum import Enum, unique, auto
import binaryninja as bn
from binaryninja import (
    BasicBlock,
    Function,
    LowLevelILCall,
    LowLevelILOperandType,
    LowLevelILOperation,
    InstructionTextTokenType,
)
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_warn
from binaryninja.lowlevelil import LowLevelILBasicBlock, LowLevelILInstruction, LowLevelILFunction
from binaryninja.flowgraph import CoreFlowGraph
from typing import Any, Iterable, List, Dict, Optional, Set, Tuple
from funalyzer.config.funalyzer_config import DEBUG


@unique
class ParsedDataKey(Enum):
    CALL_SITES = auto()
    START = auto()
    LLIL = auto()
    NAME = auto()
    BANNED_ADDRS = auto()
    ORDERED_SUCCS = auto()
    STATEMENTS = auto()
    CONSTANTS = auto()
    OPERATIONS = auto()
    CALL_TARGETS = auto()
    FUNCTION_ATTRS = auto()
    VIABLE_SYMBOLS = auto()
    UNIFORMED_FUNCTIONS = auto()
    UNIFORMED_BASIC_BLOCKS = auto()
    INSTRUCTIONS_ADDRS = auto()
    INSTRUCTIONS = auto()

    def __str__(self):
        return self.name.lower()


class UniformedFunction:
    """A uniformed function structure for further use"""

    def __init__(
        self,
        bv: Optional[BinaryView] = None,
        function: Optional[bn.Function] = None,
        parsed_data: Dict[ParsedDataKey, Any] | None = None,
    ):
        """Creates a uniformed function structure for further use.
        Either a Binary View AND a function OR already parsed data is necessary.

        Args:
            bv (Optional[BinaryView]): Binary view of the file
            function (Optional[bn.Function]): original
            parsed_data (Dict[ParsedDataKey, Any] | None, optional): _description_. Defaults to None.

        Raises:
            ValueError: Raised when wrong arguments are supplied.
        """
        self.bv = bv
        self.orig_function = function
        self.basic_blocks: Dict[int, UniformedBasicBlock] = {}

        if parsed_data is None:
            if bv is not None and function is not None:
                self.low_level_il: LowLevelILFunction | List = function.low_level_il
                self.graph: CoreFlowGraph | None = function.create_graph()
                self.call_sites: Dict[int, List[int]] = {}
                self.start: int = function.start
                self.name: str = function.name

                if not self.low_level_il:
                    self.low_level_il = []

                self.llil_str: str = "\n".join([str(instr) for instr in self.low_level_il])
                self._parse_basic_blocks()
                self._setup_call_sites()
            else:
                raise ValueError("Either bv and a function or parsed_data must be submitted")
        else:
            self.start = parsed_data[ParsedDataKey.START]
            self.call_sites = parsed_data[ParsedDataKey.CALL_SITES]
            self.basic_blocks = parsed_data[ParsedDataKey.UNIFORMED_BASIC_BLOCKS]
            self.llil_str = parsed_data[ParsedDataKey.LLIL]
            self.name = parsed_data[ParsedDataKey.NAME]

            self.low_level_il = []
            self.graph = None

    def get_essentials(self) -> Dict[ParsedDataKey, Any]:
        """Return essential information about the function.

        Returns:
            Dict[EssentialsKey, Any]: A dictionary containing essential information about the function.
        """
        return {
            # ParsedDataKey.ORIG_FUNCTION: self.orig_function,
            ParsedDataKey.LLIL: self.llil_str,
            ParsedDataKey.CALL_SITES: self.call_sites,
            ParsedDataKey.UNIFORMED_BASIC_BLOCKS: self.basic_blocks,
            ParsedDataKey.START: self.start,
            ParsedDataKey.NAME: self.name,
        }

    def _parse_basic_blocks(self):
        if self.orig_function is None:
            raise AttributeError("Method can only be called if a function is given")

        # Map: block.start -> set of merged block starts
        self.merged_blocks = {}
        blocks = list(self.low_level_il)  # List of LLILBasicBlock

        done = False
        while not done:
            done = True
            for block in blocks:
                # Only consider blocks that haven't been merged away
                if block.start in self.merged_blocks and self.merged_blocks[block.start] is None:
                    continue

                if len(block.outgoing_edges) != 1:
                    continue

                succ = block.outgoing_edges[0].target
                if succ is None:
                    continue

                last_instr = block[-1]
                if (
                    #    len(succ.incoming_edges) != 1
                    last_instr.operation != LowLevelILOperation.LLIL_CALL or block.start > succ.start
                ):
                    continue

                # Merge: record that block absorbs succ
                if block.start not in self.merged_blocks:
                    self.merged_blocks[block.start] = set()
                self.merged_blocks[block.start].add(succ.start)

                # Mark succ as merged away
                self.merged_blocks[succ.start] = None

                done = False
                break  # Restart iteration

        # Clean up: remove merged-away blocks
        self.merged_blocks = {k: v for k, v in self.merged_blocks.items() if v is not None}
        self.basic_blocks = {k: UniformedBasicBlock(block=bb) for k, bb in self.merged_blocks.items()}

    def _setup_call_sites(self) -> None:
        if not self.orig_function:
            raise AttributeError("A function must be present in order to use this method")
        for block in self.low_level_il:
            if block.start in self.merged_blocks and self.merged_blocks[block.start] is None:
                continue  # Skip merged-away blocks
            call_targets = self._get_call_targets(block)
            if call_targets:
                self.call_sites[block.start] = call_targets

    def _get_call_targets(self, block) -> List[int]:
        call_targets: List[int] = []
        for instr in block:
            if instr.operation == LowLevelILOperation.LLIL_CALL:
                dest = self._get_call_destination(instr)
                if dest:
                    call_targets.append(dest)
        # Recurse into merged blocks
        if block.start in self.merged_blocks:
            for merged_start in self.merged_blocks[block.start]:
                merged_block = next((b for b in self.low_level_il if b.start == merged_start), None)
                if merged_block:
                    call_targets.extend(self._get_call_targets(merged_block))
        return call_targets

    def _get_call_destination(self, instr):
        for token in instr.tokens:
            if token.type == InstructionTextTokenType.PossibleAddressToken:
                return int(token.value)
        return None

    def __repr__(self):
        return f"<UniformedFunction at {self.start:x}>"


class UniformedBasicBlock:
    """A uniformed Basic Block structure for further use"""

    def __init__(
        self,
        block: Optional[LowLevelILBasicBlock] = None,
        parent_function: Optional[UniformedFunction] = None,
        parsed_data: Optional[dict] = None,
    ):
        """Creates a uniformed basic block structure for further use.
        Either (Binary View, block, parent function) OR already parsed data is necessary.
        If the parsed data is provided, the other arguments are ignored.

        Args:
            block (Optional[LowLevelILBasicBlock], optional): original block. Defaults to None.
            parent_function (Optional[UniformedFunction], optional): parent function. Defaults to None.
            parsed_data (Optional[dict], optional): parsed data. Defaults to None.

        Raises:
            ArgumentError: Raised when wrong arguments are supplied.
        """
        # Initialize collections
        self.statements: List[str] = []
        self.all_constants: List[int] = []
        self.operations: List[str] = []
        self.call_targets: List[int] = []
        self.instruction_addrs: List[int] = []
        self.ignored_operation_types: Set[LowLevelILOperation] = {
            LowLevelILOperation.LLIL_CONST_PTR,
            LowLevelILOperation.LLIL_LOAD,
            LowLevelILOperation.LLIL_JUMP,
            LowLevelILOperation.LLIL_CALL,
            LowLevelILOperation.LLIL_TAILCALL,
        }

        if not parsed_data:
            if not block or not parent_function:
                raise ArgumentError("Either parsed data or all the other arguments must be present")

            # Initialize basic properties
            self.start: int = block.start
            self.length: int = block.length
            self.instructions: List[UniformedInstruction] = [UniformedInstruction(instr) for instr in block]
            self.blocks = [block]

            # Add merged block addresses if any
            # if block.start in parent_function.basic_blocks:
            #     for merged_block in parent_function.basic_blocks[block.start]:
            #         self.blocks.append(merged_block)

            # Process LLIL for each instruction in block
            for bb in self.blocks:
                for instr in bb:
                    self.instruction_addrs.append(instr.address)

                    # Extract constants from instruction tokens
                    for token in instr.tokens:
                        if token.type == InstructionTextTokenType.IntegerToken:
                            self.all_constants.append(token.value)

                    # Record operation type
                    self.operations.append(str(instr.operation))

                    # Store normalized instruction text
                    self.statements.append(str(instr))

                    # Handle calls
                    if isinstance(instr, LowLevelILCall):
                        target_expr = instr.dest
                        # For direct calls, get the constant address
                        if target_expr.operation in (
                            bn.LowLevelILOperation.LLIL_CONST_PTR,
                            bn.LowLevelILOperation.LLIL_CONST,
                        ):
                            call_target = target_expr.value.value
                            self.call_targets.append(call_target)
                        else:
                            log_warn(f"Call at {hex(instr.address)} has non-constant target: {target_expr}")

                # Get jump type from last instruction
                last_instr = bb[-1]
                self.jumpkind = last_instr.operation if last_instr else None

        else:
            self.statements: List[str] = parsed_data[ParsedDataKey.STATEMENTS]
            self.operations = parsed_data[ParsedDataKey.OPERATIONS]
            self.call_targets = parsed_data[ParsedDataKey.CALL_TARGETS]
            self.instruction_addrs = parsed_data[ParsedDataKey.INSTRUCTIONS_ADDRS]
            self.instructions = parsed_data[ParsedDataKey.INSTRUCTIONS]

        # Update size to include merged blocks
        self.size = sum(b.length for b in self.blocks)

    def get_essentials(self) -> Dict[ParsedDataKey, Any]:
        return {
            ParsedDataKey.STATEMENTS: self.statements,
            ParsedDataKey.OPERATIONS: self.operations,
            ParsedDataKey.INSTRUCTIONS: self.instructions,
            ParsedDataKey.CALL_TARGETS: self.call_targets,
            ParsedDataKey.INSTRUCTIONS_ADDRS: self.instruction_addrs,
        }

    def __repr__(self):
        size = sum([b.length for b in self.blocks])
        return f"<Basic Block for {self.start:x}, {size} bytes>"

    def __iter__(self):
        for instr in self.instructions:
            yield instr

    def __eq__(self, value: object, /) -> bool:
        if not isinstance(value, UniformedBasicBlock):
            return False

        for instr1, instr2 in zip(self, value):
            if instr1.operation in self.ignored_operation_types or instr2.operation in self.ignored_operation_types:
                continue
            if instr1 != instr2:
                return False

        return True


class UniformedInstruction:
    def __init__(self, instr: LowLevelILInstruction) -> None:
        self.operation: LowLevelILOperation = instr.operation
        self.value: int = instr.value.value
        self.llil_str: str = str(instr)

    def __eq__(self, value: object, /) -> bool:
        if not isinstance(value, self.__class__):
            return False
        return self.llil_str == value.llil_str


class LibDescriptor:
    def __init__(self, bv: Optional[BinaryView] = None, banned_names=("$d", "$t"), parsed_data: Optional[Dict] = None):
        self.banned_addrs: Set[int] = set()
        self.uniformed_functions: Dict[int, UniformedFunction] = dict()
        self.uniformed_blocks: Dict[Tuple[int, int], UniformedBasicBlock] = dict()
        self.ordered_successors: Dict[Tuple[int, int], List[int]] = {}
        self.viable_func_addrs: Set[int] = set()
        self.function_attributes: Dict[int, Tuple[int, int, int]] = {}

        if not parsed_data and bv:
            self.bv = bv

            if DEBUG:
                func = self.bv.get_function_at(0x65C)
                if not func:
                    raise Exception("func not found")
                functions: Iterable[bn.function.Function] = [func]
            else:
                functions = self.bv.functions

            self.filename = bv.file.filename
            # Normalize functions
            for func in functions:
                uni_func = UniformedFunction(bv, func)
                self.uniformed_functions[func.start] = uni_func
                for block in func.low_level_il or []:
                    self.uniformed_blocks[(func.start, block.start)] = UniformedBasicBlock(
                        block=block, parent_function=uni_func
                    )

                    ord_succ = self._get_ordered_successors(block)
                    self.ordered_successors[(func.start, block.start)] = ord_succ

                if func.name in banned_names or self.is_trivial(func):
                    self.banned_addrs.add(func.start)
                else:
                    self.viable_func_addrs.add(func.start)

            self.function_attributes = self._compute_function_attributes()

        elif parsed_data:
            self.filename = parsed_data.get(ParsedDataKey.NAME, "")
            self.banned_addrs = parsed_data.get(ParsedDataKey.BANNED_ADDRS, set())
            self.function_attributes = parsed_data.get(ParsedDataKey.FUNCTION_ATTRS, {})
            self.ordered_successors = parsed_data.get(ParsedDataKey.ORDERED_SUCCS, {})
            self.viable_func_addrs = parsed_data.get(ParsedDataKey.VIABLE_SYMBOLS, set())
            funcs = {
                addr: UniformedFunction(parsed_data=data)
                for addr, data in parsed_data[ParsedDataKey.UNIFORMED_FUNCTIONS].items()
            }
            self.uniformed_functions = funcs

            # blocks = {addr: UniformedBasicBlock(parsed_data=data) for addr, data in parsed_data[ParsedDataKey.UNIFORMED_BASIC_BLOCKS].items()}
            # self.uniformed_blocks = blocks
        else:
            raise ArgumentError("Either 'parsed_data' or a valid BinaryView must be submitted")

    def get_essentials(self) -> Dict[ParsedDataKey, Any]:
        """Get (hashable) essential information about the descriptor.
        All data returned by this function is hashable and can be used to re-construct the descriptor.

        Returns:
            Dict[ParsedDataKey, Any]: A dictionary containing essential information about the descriptor.
        """
        functions = {addr: func.get_essentials() for addr, func in self.uniformed_functions.items()}
        blocks = {start: block.get_essentials() for start, block in self.uniformed_blocks.items()}
        data = {
            ParsedDataKey.NAME: self.filename,
            ParsedDataKey.BANNED_ADDRS: self.banned_addrs,
            ParsedDataKey.UNIFORMED_FUNCTIONS: functions,
            ParsedDataKey.UNIFORMED_BASIC_BLOCKS: blocks,
            ParsedDataKey.ORDERED_SUCCS: self.ordered_successors,
            ParsedDataKey.FUNCTION_ATTRS: self.function_attributes,
            ParsedDataKey.VIABLE_SYMBOLS: self.viable_func_addrs,
        }

        return data

    def is_trivial(self, func: Function) -> bool:
        """A function is trivial if it consists of a single block with <=2 instructions.

        Args:
            func (Function): Function to be checked.

        Returns:
            bool: True if the function is trivial, False otherwise.
        """
        if len(func.basic_blocks) == 1:
            block = next(iter(func.basic_blocks))
            if len(list(block.disassembly_text)) <= 2:
                return True
        return False

    def get_func_by_addr(self, addr: int) -> str:
        return ""

    def _compute_function_attributes(self) -> Dict[int, Tuple[int, int, int]]:
        """Exctracts function attributes from the BinaryView.
        The attributes are:
        - Number of blocks
        - Number of edges
        - Number of calls
        The function attributes are stored in a dictionary with the function start address as key.

        Returns:
            dict: A dictionary containing function attributes.
        """
        attributes = dict()
        for func in self.bv.functions:
            num_blocks = len(func.basic_blocks)
            num_edges = sum(len(list(block.outgoing_edges)) for block in func.basic_blocks)
            num_calls = len(list(func.callees))
            attributes[func.start] = (num_blocks, num_edges, num_calls)
        return attributes

    def _get_ordered_successors(self, block: BasicBlock) -> List[int]:
        """Returns the ordered list of successor blocks (by address).

        Args:
            block (BasicBlock): The block for which to find successors.

        Returns:
            List[int]: List of successor block addresses.
        """
        return [edge.target.start for edge in block.outgoing_edges]

    def __repr__(self):
        return f"<LibMatchDescriptorBN for {self.filename}>"

    def __str__(self):
        return repr(self)
