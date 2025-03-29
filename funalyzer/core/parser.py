import binaryninja as bn
from binaryninja import BasicBlock, LowLevelILCall, LowLevelILOperation, InstructionTextTokenType
from binaryninja.binaryview import BinaryView
from binaryninja.lowlevelil import LowLevelILBasicBlock, LowLevelILInstruction
from typing import List


class UniformedFunction:
    """A more normalized function class for use in LibMatch"""

    def __init__(self, bv: BinaryView, function: bn.Function):
        self.bv = bv
        self.orig_function = function
        self.graph = function.create_graph()
        self.call_sites: dict = {}
        self.startpoint: int = function.start
        self.basic_blocks: dict = {}
        self.addr = function.start

        self._parse_basic_blocks()
        self._setup_call_sites()

    def _parse_basic_blocks(self):
        # TODO low: naming is shit
        done = False
        while not done:
            done = True
            for block in self.orig_function.low_level_il:
                # check if blocks can be combined
                if len(block.outgoing_edges) != 1:
                    continue

                succ = list(block.outgoing_edges)[0].target
                last_instr = block[-1]
                if (
                    len(block.outgoing_edges) != 1
                    or len(succ.incoming_edges) != 1  # target has other predecessor-nodes
                    or last_instr.operation != LowLevelILOperation.LLIL_CALL
                    or block.start > succ.start  # target is predecessors of current block
                ):
                    continue

                self._merge_blocks(block, succ)
                done = False
                break

    def _merge_blocks(self, block: LowLevelILBasicBlock, succ: BasicBlock):
        # TODO low: naming is shit
        # Track merged blocks without modifying original graph
        if block not in self.basic_blocks:
            self.basic_blocks[block] = []
        self.basic_blocks[block].append(succ)
        
        # Propagate any existing merges from successor
        if succ in self.basic_blocks:
            self.basic_blocks[block].extend(self.basic_blocks[succ])
            del self.basic_blocks[succ]

    def _setup_call_sites(self):
        for block in self.orig_function: # was initially self.graph, maybe I'm wrong?
            call_targets = self._get_call_targets(block)
            if call_targets:
                self.call_sites[block.start] = call_targets

    def _get_call_targets(self, block):
        call_targets = []

        for instr in block.get_disassembly_text():
            if instr.tokens[0].text == "call":
                dest = self._get_call_destination(instr)
                if dest:
                    call_targets.append(dest)

        if block in self.basic_blocks:
            for merged_block in self.basic_blocks[block]:
                call_targets.extend(self._get_call_targets(merged_block))

        return call_targets

    def _get_call_destination(self, instr):
        for token in instr.tokens:
            if token.type == InstructionTextTokenType.PossibleAddressToken:
                return int(token.value)
        return None


class UniformedBasicBlock:
    """A class for normalizing basic blocks."""

    def __init__(self, bv: BinaryView, block: LowLevelILBasicBlock, function: UniformedFunction):
        # Initialize basic properties
        self.start: int = block.start
        self.length: int = block.length
        self.block: LowLevelILBasicBlock = block
        self.instructions: List[LowLevelILInstruction] = [instr for instr in block]

        # Add merged block addresses if any
        if block.start in function.basic_blocks:
            for merged_block in function.basic_blocks[block]:
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



