import binaryninja as bn
from binaryninja import SymbolType
from binaryninja import LowLevelILOperation, InstructionTextTokenType
from binaryninja.binaryview import BinaryView
from binaryninja.lowlevelil import LowLevelILBasicBlock
from pathlib import Path
import shelve
from shelve import Shelf
from typing import Dict, Any
import networkx
from networkx.reportviews import NodeView

from binaryninja.log import log_error


class NormalizedFunction():
    """A more normalized function class for use in LibMatch
    """
    def __init__(self, function: bn.Function):
        # start by copying the graph
        self.graph = self._function_to_networkx(function)
        self.nodes = [node for node in function.low_level_il]
        self.call_sites: Dict[NodeView, List[int]] = dict()
        self.startpoint = function.start
        self.merged_blocks = dict()
        self.orig_function = function
        self.addr = function.start

        # find nodes which end in call and combine them
        done = False
        while not done:
            done = True
            # iterate over all basic blocks in IL for architecture independency
            for basic_block in function.low_level_il:
                try:
                    # Get the last instruction of the block
                    last_instr = basic_block[-1]
                except IndexError:
                    continue

                successors = list(basic_block.outgoing_edges)
                
                # Check if the block ends with a call and meets merging criteria
                if (last_instr.operation == LowLevelILOperation.LLIL_CALL and
                    len(successors) == 1 and
                    len(list(basic_block.incoming_edges)) == 1 and
                    successors[0].target.start > basic_block.start):

                    succ = successors[0]
                    
                    # Add edges to the successors of its successor
                    # TODO high: fix this, not sure about the for block
                    for edge in succ.target.outgoing_edges:
                        self.graph.add_edge(basic_block, edge)
                    
                    # Remove the original successor
                    self.graph.remove_node(succ)
                    done = False

                    # Update merged blocks
                    if basic_block not in self.merged_blocks:
                        self.merged_blocks[basic_block] = []
                    self.merged_blocks[basic_block].append(succ)
                    if succ in self.merged_blocks:
                        self.merged_blocks[basic_block].extend(self.merged_blocks[succ])
                        del self.merged_blocks[succ]
                    
                    # Start over
                    break
                            
        # set up call sites
        # TODO high: fix this
        # Process call sites for each node in graph
        for n in self.graph.nodes:
            call_targets = []
            merged_block = None
            
            # Check if this node is in merged blocks
            for mb in self.merged_blocks:
                if n == mb.start:
                    merged_block = mb
                    break
            
            # Get call targets for current block
            llil = self.orig_function.get_llil_at(n)
            if llil and llil.operation == LowLevelILOperation.LLIL_CALL:
                dest = llil.operands[0]  # Call destination is the first operand
                if isinstance(dest, int):
                    call_targets.append(dest)

            # Get call targets from merged blocks
            if merged_block:
                for block in self.merged_blocks[merged_block]:
                    llil = self.orig_function.get_llil_at(block.start)
                    if llil and llil.operation == LowLevelILOperation.LLIL_CALL:
                        dest = llil.operands[0]  # Call destination is the first operand
                        if isinstance(dest, int):
                            call_targets.append(dest)

            # Handle tail calls (transitions in angr terminology)
            last_llil = self.orig_function.get_llil_at(n)
            if (last_llil and 
                last_llil.operation == LowLevelILOperation.LLIL_JUMP and 
                isinstance(last_llil.operands[0], int) and  # Jump destination is the first operand
                not self.orig_function.contains_address(last_llil.operands[0])):
                call_targets.append(last_llil.operands[0])

            # Store call targets if any found
            if call_targets:
                self.call_sites[n] = call_targets

    def _function_to_networkx(self, function: bn.Function) -> networkx.DiGraph:
        """Convert a Binary Ninja function to a networkx directed graph
        
        Args:
            function: Binary Ninja Function object
        
        Returns:
            networkx.DiGraph representing the function's CFG
        """
        # Create empty directed graph
        graph = networkx.DiGraph()
        
        # Get function's flow graph
        flow_graph = function.create_graph()
        
        # Add all basic blocks as nodes
        for node in flow_graph:
            graph.add_node(node.basic_block.start, 
                          block=node.basic_block,
                          size=node.basic_block.length)
        
        # Add edges between blocks
        for node in flow_graph:
            for edge in node.outgoing_edges:
                graph.add_edge(node.basic_block.start, 
                             edge.target.basic_block.start)
        
        return graph


class NormalizedBlock():
    """A class for normalizing basic blocks.
    """
    def __init__(self, bv: BinaryView, block: LowLevelILBasicBlock, function: NormalizedFunction):
        """Constructor

        Args:
            project (angr (TODO)): replace with binja
            block (_type_): _description_
            function (_type_): _description_
        """
        # Initialize basic properties
        self.addr = block.start
        self.blocks = [block]
        self.size = block.length
        
        # Add merged block addresses if any
        if block.start in function.merged_blocks:
            for merged_block in function.merged_blocks[block]:
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
            if bb:
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
                    if instr.operation == LowLevelILOperation.LLIL_CALL:
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
        size = sum([b.size for b in self.blocks])
        return '<Normalized Block for %#x, %d bytes>' % (self.addr, size)




class LibMatchDescriptor():
    """
    A class to precompute all information for a project necessary for LibMatch to run.
    Serializes easily into a (relatively) small blob.
    """
    def __init__(self, bv: BinaryView, banned_names=("$d", "$t")):
        bv.update_analysis_and_wait()
        self.callgraph = self._build_callgraph(bv)
        self._sim_procedures = dict()
        for func in bv.functions:
            if func.symbol.type == SymbolType.ImportedFunctionSymbol:
                library_name = func.symbol.namespace or "_UNKNOWN_LIB"
                self._sim_procedures[func.start] = f"{library_name}:{func.symbol.name}"

        self.banned_addrs = set()
        self.normalized_functions = dict() # 
        self.normalized_blocks = dict()
        self.ordered_successors = dict() 
        self.filename: str = bv.file.filename
        self.bv: BinaryView = bv

        # Normalize all functions and save in attribute
        for fun in self.bv.functions:
            # TODO high: remove project (and replace with bv?)
            self.normalized_functions[fun.start] = NormalizedFunction(proj, fun)
            for node in fun.create_graph().nodes:
                block = node.basic_block
                try:
                    # TODO high: fix project parameter
                    self.normalized_blocks[(fun.start, block.start)] = NormalizedBlock(self.bv, b, self.normalized_functions[fun.start])
                except Exception as e:
                    self.normalized_blocks[(fun.start, block.addr)] = None
                    log_error(f"Failed to normalize block ({fun.name}, {block}) with {e}")
                

        # for norm_f in self.normalized_functions.values():
        #     for b in norm_f.graph.nodes():
        #         ord_succ = self._get_ordered_successors(proj, b, norm_f.graph.successors(b))
        #         self.ordered_successors[(norm_f.addr, b.addr)] = ord_succ

        self.function_attributes = self._compute_function_attributes()

        for faddr in self.cfg.kb.functions:
            f = self.cfg.kb.functions.function(faddr)
            f._project = None
            if hasattr(f, '_block_cache'):
                f._block_cache = {}

        self.function_manager = self.cfg.kb.functions.copy()
        self.function_manager._kb = None

        for faddr in self.cfg.kb.functions:
            f = self.cfg.kb.functions.function(faddr)
            f._function_manager = self.function_manager

        # Do this last because it is somewhat dangerous (must modify symbol owner object references)
        self.loader = CleLoaderHusk(proj.loader)
        # aaaand cleanup
        for faddr in self.function_manager:
            f = self.function_manager.function(faddr)
            if f.is_plt or f.is_simprocedure \
                    or not f.name or \
                    f.name in banned_names or \
                    self.is_trivial(proj, f):
                self.banned_addrs.add(faddr)

        self.viable_functions = set(self.function_attributes) - set(self.banned_addrs)

        self.viable_symbols = set()
        for sym in self.loader.main_object.symbols:
            if sym.is_function \
                    and not sym.is_hidden \
                    and not sym.is_weak \
                    and sym.binding != "STB_LOCAL" \
                    and sym.rebased_addr not in self.banned_addrs:
                self.viable_symbols.add(sym)
        proj.loader.close()
        del proj.loader
    
    def _build_callgraph(self, bv: BinaryView) -> networkx.DiGraph:
        """Build callgraph from BinaryNinja function call references"""
        graph = networkx.DiGraph()
        
        # Add all functions as nodes
        for function in bv.functions:
            graph.add_node(function.start)
            
            # Add edges for all callees
            for callee in function.callees:
                graph.add_edge(function.start, callee.start)
            
        return graph


    def is_trivial(self, proj, f):
        """
        Return True is a function is "trivial"
        Right now, this means a ret stub, matching those does us no good
        :param f:
        :return:
        """
        # The function is one block.
        if len(list(f.block_addrs)) == 1:
            b = proj.factory.block(list(f.block_addrs)[0])
            if len(b.instruction_addrs) <= 2:# and b.vex.jumpkind == 'Ijk_Ret':
                # mov r0, #0
                # bx lr
                #.... and similar
                return True
            #if len(b.instruction_addrs) == 1:
            #    # One instruction must be either a jump or a ret.
            #    # Or.... uh.. mangled garbage functions i guess
            #    # Either way, it can't do anything useful.
            #g    return True
        return False


    def is_hooked(self, addr):
        return addr in self._sim_procedures

    def _compute_function_attributes(self) -> dict:
        """
        :returns:    a dictionary of function addresses to tuples of attributes
        """

        # the attributes we use are the number of basic blocks, number of edges, and number of subfunction calls
        attributes = dict()
        all_funcs = set(self.cfg.kb.callgraph.nodes())
        for function_addr in self.cfg.kb.functions:
            # skip syscalls and functions which are None in the cfg
            if self.cfg.kb.functions.function(function_addr) is None or self.cfg.kb.functions.function(function_addr).is_syscall:
                continue
            normalized_function = self.normalized_functions[function_addr]
            number_of_basic_blocks = len(normalized_function.graph.nodes())
            #number_of_edges = len(normalized_function.graph.edges())
            number_of_edges = 0
            for u, v in normalized_function.graph.edges():
                d = normalized_function.graph.get_edge_data(u, v)
                if 'type' in d and d['type'] == 'fake_return':
                    continue
                number_of_edges += 1

            if function_addr in all_funcs:
                number_of_subfunction_calls = len(list(self.cfg.kb.callgraph.successors(function_addr)))
            else:
                number_of_subfunction_calls = 0
            attributes[function_addr] = (number_of_basic_blocks, number_of_edges, number_of_subfunction_calls)

        return attributes

    def _get_ordered_successors(self, proj, block, succ):
        # TODO
        # try:
        #     # add them in order of the vex
        #     succ = set(succ)
        #     ordered_succ = []
        #     bl = proj.factory.block(block.addr, opt_level=-1)
        #     for x in bl.vex.all_constants:
        #         if x in succ:
        #             ordered_succ.append(x)

        #     # add the rest (sorting might be better than no order)
        #     for s in sorted(succ - set(ordered_succ), key=lambda x:x.addr):
        #         ordered_succ.append(s)
        #     return ordered_succ
        # except (SimMemoryError, SimEngineError):
        #     return sorted(succ, key=lambda x:x.addr)
        pass


    def symbol_for_addr(self, addr):
        for s in self.loader.main_object.symbols:
            if s.rebased_addr == addr:
                return s
        # Also check the externs
        for s in self.loader.extern_object.symbols:
            if s.rebased_addr == addr:
                return s

    # Creation and Serialization
    @staticmethod
    def make_signature_dump(filename, **project_kwargs):
        lmd = LibMatchDescriptor.make_signature(filename, **project_kwargs)
        path = Path(filename).absolute() / ".lmd"
        lmd.dump_path(str(path))
        return path

    @staticmethod
    def load_path(path: str) -> dict:
        with shelve.open(path) as shelf:
            return LibMatchDescriptor.load(shelf)

    @staticmethod
    def load(shelf: Shelf[Dict[str, Any]]) -> dict:
        if not isinstance(shelf, Shelf):
            raise ValueError(f"Shelf object expected, got {type(shelf)}")
        # TODO ev: some check if it is a valid descriptor
        return {k: v for k, v in shelf.items()}

    # @staticmethod
    # def loads(data):
    #     lmd = pickle.loads(data)

    #     if not isinstance(lmd, LibMatchDescriptor):
    #         raise ValueError("That's not a LibMatchDescriptor!")
    #     return lmd

    def dump_path(self, path):
        with shelve.open(path) as shelf:
            return self.dump(shelf)

    def dump(self, shelf: Shelf[Dict[str, Any] | Any]):
        if not isinstance(shelf, Shelf):
            raise ValueError(f"Shelf object expected, got {type(shelf)}")

        shelf['cfg'] = self.cfg
        shelf['callgraph'] = self.callgraph
        shelf['sim_procedures'] = self._sim_procedures
        shelf['banned_addrs'] = self.banned_addrs
        shelf['normalized_functions'] = self.normalized_functions
        shelf['normalized_blocks'] = self.normalized_blocks
        shelf['ordered_successors'] = self.ordered_successors
        shelf['filename'] = self.filename

    # def dumps(self):
    #     return pickle.dumps(self, pickle.HIGHEST_PROTOCOL)

    # Formatting
    def __repr__(self):
        return f"<LibMatchDescriptor for {self.filename}>"

    def __str__(self):
        # TODO priority low: add better str format?
        return f"{self.__class__.__name__}(filename={self.filename})"





class CleLoaderHusk(object):
    """
    A husk of a typical cle Loader, saving only main_object
    """
    def __init__(self, loader):
        self.main_object = CleBackendHusk(loader.main_object)
        self.extern_object = CleBackendHusk(loader.extern_object)
        self.min_addr = loader.min_addr
        self.max_addr = loader.max_addr

class CleBackendHusk(object):
    """
    A husk of a typical cle Backend, saving only .segments, .sections, .symbols, and .plt.
    Supports .contains_addr.
    """
    def __init__(self, backend):
        self.sections = backend.sections
        self.segments = backend.segments
        try:
            self.plt = backend.plt
        except Exception as e:
            log_error(f"{e}\nIn constructor in class {self.__class__.__name__}")
            self.plt = None # Blobs do not have a plt
        self.sections_map = backend.sections_map
        self.arch = backend.arch
        self.provides = backend.provides

        try:
            self.all_symbols = backend.all_symbols
        except:
            self.all_symbols = {}
        self.mapped_base = backend.mapped_base

        self.symbols = backend.symbols
        for sym in self.symbols:
            sym.owner = self

    def contains_addr(self, addr):
        """
        Is `addr` in one of the binary's segments/sections we have loaded? (i.e. is it mapped into memory ?)
        """
        return self.find_loadable_containing(addr) is not None

    def find_loadable_containing(self, addr):
        lookup = self.find_segment_containing if self.segments else self.find_section_containing
        return lookup(addr)

    def find_segment_containing(self, addr):
        """
        Returns the segment that contains `addr`, or ``None``.
        """
        return self.segments.find_region_containing(addr)

    def find_section_containing(self, addr):
        """
        Returns the section that contains `addr` or ``None``.
        """
        return self.sections.find_region_containing(addr)




