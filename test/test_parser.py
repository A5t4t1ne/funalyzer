from src.core.parser import UniformedFunction, UniformedBasicBlock


# class TestUniformedFunction:
#     """A uniformed function structure for further use"""
# 
#     def test_creation(self):
#         block = UniformedFunction()
# 
#     def __init__(self, bv: BinaryView, function: bn.Function):
#         self.bv = bv
#         self.orig_function = function
#         self.graph = function.create_graph()
#         self.call_sites: dict = {}
#         self.startpoint: int = function.start
#         self.basic_blocks: dict = {}
#         self.addr = function.start
# 
#         self._parse_basic_blocks()
#         self._setup_call_sites()
# 
# 
# 
# class TestUniformedBasicBlock:
#     """A uniformed Basic Block structure for further use"""
# 
#     def __init__(self, bv: BinaryView, block: LowLevelILBasicBlock, function: UniformedFunction):
#         # Initialize basic properties
#         self.start: int = block.start
#         self.length: int = block.length
#         self.block: LowLevelILBasicBlock = block
#         self.instructions: List[LowLevelILInstruction] = [instr for instr in block]
# 
#         # Add merged block addresses if any
#         if block.start in function.basic_blocks:
#             for merged_block in function.basic_blocks[block]:
#                 self.blocks.append(merged_block)
# 
#         # Initialize collections
#         self.statements = []
#         self.all_constants = []
#         self.operations = []
#         self.call_targets = []
#         self.blocks = [block]
#         self.instruction_addrs = []
# 
#         # Process LLIL for each instruction in block
#         for bb in self.blocks:
#             for instr in bb:
#                 # Collect instruction addresses
#                 self.instruction_addrs.append(instr.address)
# 
#                 # Extract constants from instruction tokens
#                 for token in instr.tokens:
#                     if token.type == InstructionTextTokenType.IntegerToken:
#                         self.all_constants.append(token.value)
# 
#                 # Record operation type
#                 self.operations.append(instr.operation)
# 
#                 # Store normalized instruction text
#                 self.statements.append(str(instr))
# 
#                 # Handle calls
#                 if isinstance(instr, LowLevelILCall):
#                     dest = instr.dest
#                     if isinstance(dest, int):
#                         # Try to resolve symbol name for direct calls
#                         symbol = bv.get_symbol_at(dest)
#                         target = symbol.name if symbol else hex(dest)
#                         self.call_targets.append((block, target))
# 
#             # Get jump type from last instruction
#             last_instr = bb[-1]
#             self.jumpkind = last_instr.operation if last_instr else None
# 
#         # Update size to include merged blocks
#         self.size = sum(b.length for b in self.blocks)
# 
#     def __repr__(self):
#         size = sum([b.length for b in self.blocks])
#         return f"<Basic Block for {self.start:x}, {size} bytes>"
# 
# 
# 
# class LibDescriptor:
#     """
#     A class to precompute all information for a project.
#     """
#     def __init__(self, proj, banned_names=("$d", "$t")):
#         pass
#     # def __init__(self, proj, banned_names=("$d", "$t")):
#     #     # TODO high: implement
#     #     self.cfg = proj.analyses.CFGFast(force_complete_scan=False, 
#     #             resolve_indirect_jumps=True, 
#     #             normalize=True,
#     #             cross_references=True,
#     #             detect_tail_calls=True)
#     #     self.callgraph = self.cfg.kb.callgraph
#     #     self._sim_procedures = {addr: (sp.library_name or "_UNKNOWN_LIB") + ":" + sp.display_name
#     #                             for addr, sp in proj._sim_procedures.items()}
# 
#     #     self.banned_addrs = set()
#     #     self.normalized_functions = {}
#     #     self.normalized_blocks = {}
#     #     self.ordered_successors = {}
#     #     self.filename = proj.filename
# 
#     #     for faddr in self.cfg.kb.functions:
#     #         f = self.cfg.kb.functions.function(faddr)
#     #         self.normalized_functions[f.addr] = NormalizedFunction(proj, f)
#     #         for b in f.graph.nodes():
#     #             try:
#     #                 self.normalized_blocks[(f.addr, b.addr)] = NormalizedBlock(proj, b, self.normalized_functions[f.addr])
#     #             except (SimMemoryError, SimEngineError):
#     #                 self.normalized_blocks[(f.addr, b.addr)] = None
# 
#     #     for norm_f in self.normalized_functions.values():
#     #         for b in norm_f.graph.nodes():
#     #             ord_succ = self._get_ordered_successors(proj, b, norm_f.graph.successors(b))
#     #             self.ordered_successors[(norm_f.addr, b.addr)] = ord_succ
# 
#     #     self.function_attributes = self._compute_function_attributes()
# 
#     #     for faddr in self.cfg.kb.functions:
#     #         f = self.cfg.kb.functions.function(faddr)
#     #         f._project = None
#     #         if hasattr(f, '_block_cache'):
#     #             f._block_cache = {}
# 
#     #     self.function_manager = self.cfg.kb.functions.copy()
#     #     self.function_manager._kb = None
# 
#     #     for faddr in self.cfg.kb.functions:
#     #         f = self.cfg.kb.functions.function(faddr)
#     #         f._function_manager = self.function_manager
# 
#     #     # Do this last because it is somewhat dangerous (must modify symbol owner object references)
#     #     self.loader = CleLoaderHusk(proj.loader)
#     #     # aaaand cleanup
#     #     for faddr in self.function_manager:
#     #         f = self.function_manager.function(faddr)
#     #         if f.is_plt or f.is_simprocedure \
#     #                 or not f.name or \
#     #                 f.name in banned_names or \
#     #                 self.is_trivial(proj, f):
#     #             self.banned_addrs.add(faddr)
# 
#     #     self.viable_functions = set(self.function_attributes) - set(self.banned_addrs)
# 
#     #     self.viable_symbols = set()
#     #     for sym in self.loader.main_object.symbols:
#     #         if sym.is_function \
#     #                 and not sym.is_hidden \
#     #                 and not sym.is_weak \
#     #                 and sym.binding != "STB_LOCAL" \
#     #                 and sym.rebased_addr not in self.banned_addrs:
#     #             self.viable_symbols.add(sym)
#     #     proj.loader.close()
#     #     del proj.loader
#     #     
#     # def is_trivial(self, proj, f):
#     #     """
#     #     Return True is a function is "trivial"
#     #     Right now, this means a ret stub, matching those does us no good
#     #     :param f:
#     #     :return:
#     #     """
#     #     # The function is one block.
#     #     if len(list(f.block_addrs)) == 1:
#     #         b = proj.factory.block(list(f.block_addrs)[0])
#     #         if len(b.instruction_addrs) <= 2:# and b.vex.jumpkind == 'Ijk_Ret':
#     #             # mov r0, #0
#     #             # bx lr
#     #             #.... and similar
#     #             return True
#     #         #if len(b.instruction_addrs) == 1:
#     #         #    # One instruction must be either a jump or a ret.
#     #         #    # Or.... uh.. mangled garbage functions i guess
#     #         #    # Either way, it can't do anything useful.
#     #         #g    return True
#     #     return False
# 
# 
#     # def is_hooked(self, addr):
#     #     return addr in self._sim_procedures
# 
#     # def _compute_function_attributes(self):
#     #     """
#     #     :returns:    a dictionary of function addresses to tuples of attributes
#     #     """
# 
#     #     # the attributes we use are the number of basic blocks, number of edges, and number of subfunction calls
#     #     attributes = dict()
#     #     all_funcs = set(self.cfg.kb.callgraph.nodes())
#     #     for function_addr in self.cfg.kb.functions:
#     #         # skip syscalls and functions which are None in the cfg
#     #         if self.cfg.kb.functions.function(function_addr) is None or self.cfg.kb.functions.function(function_addr).is_syscall:
#     #             continue
#     #         normalized_function = self.normalized_functions[function_addr]
#     #         number_of_basic_blocks = len(normalized_function.graph.nodes())
#     #         #number_of_edges = len(normalized_function.graph.edges())
#     #         number_of_edges = 0
#     #         for u, v in normalized_function.graph.edges():
#     #             d = normalized_function.graph.get_edge_data(u, v)
#     #             if 'type' in d and d['type'] == 'fake_return':
#     #                 continue
#     #             number_of_edges += 1
# 
#     #         if function_addr in all_funcs:
#     #             number_of_subfunction_calls = len(list(self.cfg.kb.callgraph.successors(function_addr)))
#     #         else:
#     #             number_of_subfunction_calls = 0
#     #         attributes[function_addr] = (number_of_basic_blocks, number_of_edges, number_of_subfunction_calls)
# 
#     #     return attributes
# 
#     # def _get_ordered_successors(self, proj, block, succ):
#     #     try:
#     #         # add them in order of the vex
#     #         succ = set(succ)
#     #         ordered_succ = []
#     #         bl = proj.factory.block(block.addr, opt_level=-1)
#     #         for x in bl.vex.all_constants:
#     #             if x in succ:
#     #                 ordered_succ.append(x)
# 
#     #         # add the rest (sorting might be better than no order)
#     #         for s in sorted(succ - set(ordered_succ), key=lambda x:x.addr):
#     #             ordered_succ.append(s)
#     #         return ordered_succ
#     #     except (SimMemoryError, SimEngineError):
#     #         return sorted(succ, key=lambda x:x.addr)
# 
# 
#     # def symbol_for_addr(self, addr):
#     #     for s in self.loader.main_object.symbols:
#     #         if s.rebased_addr == addr:
#     #             return s
#     #     # Also check the externs
#     #     for s in self.loader.extern_object.symbols:
#     #         if s.rebased_addr == addr:
#     #             return s
# 
#     # # Creation and Serialization
# 
#     # @staticmethod
#     # def make_signature(filename, **project_kwargs):
#     #     proj = angr.Project(filename, **project_kwargs)
#     #     lmd = LibMatchDescriptor(proj)
#     #     return lmd
# 
#     # @staticmethod
#     # def make_signature_dump(filename, **project_kwargs):
#     #     lmd = LibMatchDescriptor.make_signature(filename, **project_kwargs)
#     #     path = os.path.abspath(filename) + ".lmd"
#     #     with open(path, "wb") as f:
#     #         lmd.dump(f)
#     #     return path
# 
#     # @staticmethod
#     # def load_path(p):
#     #     with open(p, "rb") as f:
#     #         return LibMatchDescriptor.load(f)
# 
#     # @staticmethod
#     # def load(f):
#     #     lmd = pickle.load(f)
# 
#     #     if not isinstance(lmd, LibMatchDescriptor):
#     #         raise ValueError("That's not a LibMatchDescriptor!")
#     #     return lmd
# 
#     # @staticmethod
#     # def loads(data):
#     #     lmd = pickle.loads(data)
# 
#     #     if not isinstance(lmd, LibMatchDescriptor):
#     #         raise ValueError("That's not a LibMatchDescriptor!")
#     #     return lmd
# 
#     # def dump_path(self, p):
#     #     with open(p, "wb") as f:
#     #         self.dump(f)
# 
#     # def dump(self, f):
#     #     return pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)
# 
#     # def dumps(self):
#     #     return pickle.dumps(self, pickle.HIGHEST_PROTOCOL)
# 
#     # # Formatting
# 
#     # def __repr__(self):
#     #     return "<LibMatchDescriptor for %r>" % self.filename
# 
#     # def __str__(self):
#     #     # TODO: add better str format?
#     #     return repr(self)
