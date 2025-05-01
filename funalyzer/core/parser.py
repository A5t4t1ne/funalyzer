from enum import Enum, unique
import binaryninja as bn
from binaryninja import BasicBlock, LowLevelILCall, LowLevelILOperation, InstructionTextTokenType, SymbolType
from binaryninja.log import log_debug
from binaryninja.binaryview import BinaryView
from binaryninja.lowlevelil import LowLevelILBasicBlock, LowLevelILInstruction, LowLevelILFunction
from binaryninja.flowgraph import CoreFlowGraph
from typing import Any, List, Dict, Optional


@unique
class ParsedDataKey(Enum):
    ORIG_FUNCTION = 1
    GRAPH = 2
    CALL_SITES = 3
    BASIC_BLOCKS = 4
    START = 5
    LLIL = 6

    def __str__(self):
        return self.name.lower()


class UniformedFunction:
    """A uniformed function structure for further use"""

    def __init__(
        self,
        bv: Optional[BinaryView],
        function: Optional[bn.Function],
        parsed_data: Dict[ParsedDataKey, Any] | None = None,
    ):
        """Creates a uniform function structure for further use.
        Either a Binary View AND a Binja functions OR already parsed data is necessary.

        Args:
            bv (Optional[BinaryView]): Binary view of the file
            function (Optional[bn.Function]): original 
            parsed_data (Dict[ParsedDataKey, Any] | None, optional): _description_. Defaults to None.

        Raises:
            ValueError: Raised when wrong arguments are supplied.
        """
        self.bv = bv
        self.orig_function = function
    
        # check if built from source or with pre-trained data
        if parsed_data is None: 
            if bv is not None and function is not None:
                self.low_level_il: LowLevelILFunction | List = function.low_level_il
                self.graph: CoreFlowGraph | None = function.create_graph()
                self.call_sites: dict = {}
                self.basic_blocks: dict = {}
                self.start: int = function.start

                self.llil_str: str = "\n".join([str(instr) for instr in self.low_level_il])
                self.graph.layout_and_wait()
                self._parse_basic_blocks()
                self._setup_call_sites()
            else:
                raise ValueError("Either bv and function or parsed_data must be submitted")
        else:
            self.start = parsed_data[ParsedDataKey.START]
            self.call_sites = parsed_data[ParsedDataKey.CALL_SITES]
            self.basic_blocks = parsed_data[ParsedDataKey.BASIC_BLOCKS]
            self.llil_str = parsed_data[ParsedDataKey.LLIL]

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
                    len(succ.incoming_edges) != 1 or
                    last_instr.operation != LowLevelILOperation.LLIL_CALL or
                    block.start > succ.start
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

    def __init__(self, bv: BinaryView, block: LowLevelILBasicBlock, parent_function: UniformedFunction):
        # Initialize basic properties
        self.start: int = block.start
        self.length: int = block.length
        self.block: LowLevelILBasicBlock = block
        self.instructions: List[LowLevelILInstruction] = [instr for instr in block]

        # Add merged block addresses if any
        if block.start in parent_function.basic_blocks:
            for merged_block in parent_function.basic_blocks[block]:
                self.blocks.append(merged_block)

        # Initialize collections
        self.statements = []
        self.all_constants = []
        self.operations = []
        self.call_targets = []
        self.blocks = [block]
        self.instruction_addrs = []

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
                self.operations.append(instr.operation)

                # Store normalized instruction text
                self.statements.append(str(instr))

                # Handle calls
                if isinstance(instr, LowLevelILCall):
                    dest = instr.dest
                    if isinstance(dest, int):
                        # Try to resolve symbol name for direct calls
                        symbol = bv.get_symbol_at(dest)
                        target = symbol.name if symbol else hex(dest)
                        self.call_targets.append((block, target))

            # Get jump type from last instruction
            last_instr = bb[-1]
            self.jumpkind = last_instr.operation if last_instr else None

        # Update size to include merged blocks
        self.size = sum(b.length for b in self.blocks)

    def __repr__(self):
        size = sum([b.length for b in self.blocks])
        return f"<Basic Block for {self.start:x}, {size} bytes>"


class LibDescriptor:
    def __init__(self, bv: BinaryView, banned_names=("$d", "$t")):
        # Open the binary in Binary Ninja
        self.bv = bv
        self.bv.update_analysis_and_wait()
        self.filename = bv.file.filename

        # Build the callgraph using Binary Ninja's API
        # self.callgraph = self.bv.call_graph # needs to be done with func.create_graph()

        # SimProcedures do not exist in Binary Ninja; skip or adapt this logic
        self._sim_procedures = {}

        self.banned_addrs = set()
        self.normalized_functions = {}
        self.normalized_blocks = {}
        self.ordered_successors = {}

        # Enumerate functions and normalize them
        for func in self.bv.functions:
            self.normalized_functions[func.start] = UniformedFunction(bv, func)
            for block in func.basic_blocks:
                self.normalized_blocks[(func.start, block.start)] = UniformedBasicBlock(bv, block.low_level_il, func)

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
        for sym in self.bv.symbols.values():
            if sym.type == SymbolType.FunctionSymbol and \
               not sym.auto and \
               sym.address not in self.banned_addrs:
                self.viable_symbols.add(sym)

    def _normalize_function(self, func):
        # Placeholder for your normalization logic
        return func

    def _normalize_block(self, block):
        # Placeholder for your normalization logic
        return block

    def is_trivial(self, func):
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

    def _get_ordered_successors(self, block):
        # Returns the ordered list of successor blocks (by address)
        return [edge.target.start for edge in block.outgoing_edges]

    def symbol_for_addr(self, addr):
        # Find a symbol for the given address
        for sym in self.bv.symbols.values():
            if sym.address == addr:
                return sym
        return None

    # Serialization and other methods would be similar, using pickle or your preferred method

    def __repr__(self):
        return f"<LibMatchDescriptorBN for {self.filename}>"

    def __str__(self):
        return repr(self)
