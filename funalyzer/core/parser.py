from ctypes import ArgumentError
from enum import Enum, unique, auto
from urllib import parse
import binaryninja as bn
from binaryninja import BasicBlock, Function, LowLevelILCall, LowLevelILOperation, InstructionTextTokenType, SymbolType
from binaryninja.binaryview import BinaryView
from binaryninja.lowlevelil import LowLevelILBasicBlock, LowLevelILInstruction, LowLevelILFunction
from binaryninja.flowgraph import CoreFlowGraph
from typing import Any, List, Dict, Optional, Set, Tuple, overload


@unique
class ParsedDataKey(Enum):
    ORIG_FUNCTION = auto()
    GRAPH = auto()
    CALL_SITES = auto()
    BASIC_BLOCKS = auto()
    START = auto()
    LLIL = auto()
    NAME = auto()
    BANNED_ADDRS = auto()
    FUNCTIONS = auto()
    ORDERED_SUCCS = auto()
    STATEMENTS = auto()
    CONSTANTS = auto()
    OPERATIONS = auto()
    CALL_TARGETS = auto()
    INSTRUCTIONS_ADDRS = auto()

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

        if parsed_data is None:
            if bv is not None and function is not None:
                self.low_level_il: LowLevelILFunction | List = function.low_level_il
                self.graph: CoreFlowGraph | None = function.create_graph()
                self.call_sites: dict = {}
                self.basic_blocks: dict = {}
                self.start: int = function.start
                self.name: str = function.name

                if not self.low_level_il:
                    self.low_level_il = []

                self.llil_str: str = "\n".join([str(instr) for instr in self.low_level_il])
                self.graph.layout()
                self._parse_basic_blocks()
                self._setup_call_sites()
            else:
                raise ValueError("Either bv and a function or parsed_data must be submitted")
        else:
            self.start = parsed_data[ParsedDataKey.START]
            self.call_sites = parsed_data[ParsedDataKey.CALL_SITES]
            self.basic_blocks = parsed_data[ParsedDataKey.BASIC_BLOCKS]
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
            ParsedDataKey.BASIC_BLOCKS: self.basic_blocks,
            ParsedDataKey.START: self.start,
            ParsedDataKey.NAME: self.name,
        }

    @classmethod
    def from_raw_data(cls, bv: bn.BinaryView, func: bn.Function) -> 'UniformedFunction':
        """Create uniformed function from raw BN data.

        Args:
            bv (bn.BinaryView): Binary View of the file
            func (bn.Function): Function to be parsed

        Returns:
            UniformedFunction: A uniformed function structure.
        """
        return cls(bv=bv, function=func)

    @classmethod
    def from_parsed_data(cls, parsed_data: Dict[ParsedDataKey, Any]) -> 'UniformedFunction':
        """Create uniformed function from parsed data.
        
        Args:
            parsed_data (Dict[ParsedDataKey, Any]): Parsed data to be used.
            
        Returns:
            UniformedFunction: A uniformed function structure.
        """
        return cls(parsed_data=parsed_data)

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
                    len(succ.incoming_edges) != 1
                    or last_instr.operation != LowLevelILOperation.LLIL_CALL
                    or block.start > succ.start
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

    def _setup_call_sites(self):
        if not self.orig_function:
            raise AttributeError("A function must be present in order to use this method")
        for block in self.low_level_il:
            if block.start in self.merged_blocks and self.merged_blocks[block.start] is None:
                continue  # Skip merged-away blocks
            call_targets = self._get_call_targets(block)
            if call_targets:
                self.call_sites[block.start] = call_targets

    def _get_call_targets(self, block):
        call_targets = []
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
        bv: Optional[BinaryView] = None,
        block: Optional[LowLevelILBasicBlock] = None,
        parent_function: Optional[UniformedFunction] = None,
        parsed_data: Optional[dict] = None,
    ):
        """Creates a uniformed basic block structure for further use.
        Either (Binary View, block, parent function) OR already parsed data is necessary.
        The parsed data must contain the following keys:
        - STATEMENTS
        - OPERATIONS
        - CALL_TARGETS
        - INSTRUCTIONS_ADDRS
        If not, the class will raise an ArgumentError.
        If the parsed data is provided, the other arguments are ignored.

        Args:
            bv (Optional[BinaryView], optional): Binary view of the file. Defaults to None.
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
        self.call_targets: List[Tuple[int, str]] = []
        self.instruction_addrs: List[int] = []

        if not parsed_data:
            if not bv or not block or not parent_function:
                raise ArgumentError("Either parsed data or all the other arguments must be present")

            # Initialize basic properties
            self.start: int = block.start
            self.length: int = block.length
            self.instructions: List[LowLevelILInstruction] = [instr for instr in block]
            self.blocks = [block]

            # Add merged block addresses if any
            if block.start in parent_function.basic_blocks:
                for merged_block in parent_function.basic_blocks[block]:
                    self.blocks.append(merged_block)

            # Process LLIL for each instruction in block
            for bb in self.blocks:
                for instr in bb:
                    # Collect instruction addresses
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
                        dest = instr.dest
                        if isinstance(dest, int):
                            # Try to resolve symbol name for direct calls
                            symbol = bv.get_symbol_at(dest)
                            target = symbol.name if symbol else hex(dest)
                            self.call_targets.append((block.start, target))

                # Get jump type from last instruction
                last_instr = bb[-1]
                self.jumpkind = last_instr.operation if last_instr else None

        else:
            self.statements: List[str] = parsed_data[ParsedDataKey.STATEMENTS]
            # self.all_constants: List[int] = parsed_data[ParsedDataKey.A
            self.operations: List[str] = parsed_data[ParsedDataKey.OPERATIONS]
            self.call_targets: List[Tuple[int, str]] = parsed_data[ParsedDataKey.CALL_TARGETS]
            self.instruction_addrs: List[int] = parsed_data[ParsedDataKey.INSTRUCTIONS_ADDRS]

        # Update size to include merged blocks
        self.size = sum(b.length for b in self.blocks)

    def get_essentials(self) -> Dict[ParsedDataKey, Any]:
        return {
            ParsedDataKey.STATEMENTS: self.statements,
            ParsedDataKey.CONSTANTS: self.all_constants,
            ParsedDataKey.OPERATIONS: self.operations,
            ParsedDataKey.CALL_TARGETS: self.call_targets,
            ParsedDataKey.INSTRUCTIONS_ADDRS: self.instruction_addrs,
        }

    def __repr__(self):
        size = sum([b.length for b in self.blocks])
        return f"<Basic Block for {self.start:x}, {size} bytes>"


class LibDescriptor:
    def __init__(self, bv: BinaryView, banned_names=("$d", "$t"), parsed_data: Optional[Dict] = None):
        self.bv = bv
        self.bv.update_analysis_and_wait()
        self.banned_addrs: Set[int] = set()
        self.uniformed_functions: Dict[int, UniformedFunction] = dict()
        self.uniformed_blocks: Dict[Tuple[int, int], UniformedBasicBlock] = dict()
        self.ordered_successors: Dict[Tuple[int, int], List[int]] = {}

        if not parsed_data:
            self.filename = bv.file.filename
            # self.callgraph = self.bv.call_graph # needs to be done with func.create_graph() if needed

            # TODO: adapt logic, SimProcedures do not exist in Binary Ninja
            # self._sim_procedures = {}

            # Normalize functions
            for func in self.bv.functions:
                uni_func = UniformedFunction(bv, func)
                self.uniformed_functions[func.start] = uni_func
                for block in func.low_level_il or []:
                    self.uniformed_blocks[(func.start, block.start)] = UniformedBasicBlock(bv, block, uni_func)

            # Compute ordered successors for each block
            for func in self.bv.functions:
                for block in func.basic_blocks:
                    ord_succ = self._get_ordered_successors(block)
                    self.ordered_successors[(func.start, block.start)] = ord_succ

            self.function_attributes = self._compute_function_attributes()

            # Mark banned (trivial or special) functions
            for func in self.bv.functions:
                if func.name in banned_names or self.is_trivial(func):
                    self.banned_addrs.add(func.start)

            self.viable_functions = set(self.function_attributes) - set(self.banned_addrs)

            # Collect viable symbols
            self.viable_symbols = set()
            for sym_list in self.bv.symbols.values():
                for sym in sym_list:
                    if sym.type == SymbolType.FunctionSymbol and not sym.auto and sym.address not in self.banned_addrs:
                        self.viable_symbols.add(sym)
        else:
            self.filename = parsed_data[ParsedDataKey.NAME]
            self.banned_addrs = parsed_data[ParsedDataKey.BANNED_ADDRS]

            funcs = {addr: UniformedFunction(parsed_data=data) for addr, data in parsed_data[ParsedDataKey]}
            self.uniformed_functions = funcs

            blocks = {addr: UniformedBasicBlock(parsed_data=data) for addr, data in parsed_data[ParsedDataKey]}
            self.uniformed_blocks = blocks
            self.ordered_successors = parsed_data[ParsedDataKey.ORDERED_SUCCS]

    def get_essentials(self) -> Dict[ParsedDataKey, Any]:
        functions = {addr: func.get_essentials() for addr, func in self.uniformed_functions.items()}
        blocks = {start: block.get_essentials() for start, block in self.uniformed_blocks.items()}
        data = {
            ParsedDataKey.NAME: self.filename,
            ParsedDataKey.BANNED_ADDRS: self.banned_addrs,
            ParsedDataKey.FUNCTIONS: functions,
            ParsedDataKey.BASIC_BLOCKS: blocks,
            ParsedDataKey.ORDERED_SUCCS: self.ordered_successors,
        }

        return data

    def is_trivial(self, func: Function):
        # A function is trivial if it consists of a single block with <=2 instructions
        if len(func.basic_blocks) == 1:
            block = next(iter(func.basic_blocks))
            if len(list(block.disassembly_text)) <= 2:
                return True
        return False

    def _compute_function_attributes(self):
        attributes = dict()
        for func in self.bv.functions:
            num_blocks = len(func.basic_blocks)
            num_edges = sum(len(list(block.outgoing_edges)) for block in func.basic_blocks)
            num_calls = len(list(func.callees))
            attributes[func.start] = (num_blocks, num_edges, num_calls)
        return attributes

    def _get_ordered_successors(self, block: BasicBlock) -> List[int]:
        # Returns the ordered list of successor blocks (by address)
        return [edge.target.start for edge in block.outgoing_edges]

    def symbol_for_addr(self, addr: int):
        # Find a symbol for the given address
        for sym_list in self.bv.symbols.values():
            for sym in sym_list:
                if sym.address == addr:
                    return sym
        return None

    # Serialization and other methods would be similar, using pickle or your preferred method

    def __repr__(self):
        return f"<LibMatchDescriptorBN for {self.filename}>"

    def __str__(self):
        return repr(self)
