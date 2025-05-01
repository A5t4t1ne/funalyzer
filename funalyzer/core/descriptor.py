from binaryninja.binaryview import BinaryView
from typing import List
from .parser import UniformedBasicBlock, UniformedFunction
from .database import FunalyzerDatabase


class FunDescriptor():
    def __init__(self, bv: BinaryView, fdb: FunalyzerDatabase):
        self.bv = bv
        self.blocks: List[UniformedBasicBlock]
        self.functions: List[UniformedFunction]
        self.raw = None
