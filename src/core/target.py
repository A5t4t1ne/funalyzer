from binaryninja.binaryview import BinaryView
from typing import List
from .parser import UniformedBasicBlock, UniformedFunction


class TargetBinary():
    """Class for describing a target binary file to analyse."""
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.blocks: List[UniformedBasicBlock]
        self.functions: List[UniformedFunction]
        self.raw = None
        

    def load_path(self):
        """docstring for load_path"""
        pass
        

    def save_path(self):
        """docstring for save_path"""
        pass
        

