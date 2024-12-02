from binaryninja import *
from binaryninja import lineardisassembly
from binaryninja.function import *
from binaryninja.enums import (
    AnalysisSkipReason, FunctionGraphType, SymbolType, InstructionTextTokenType, HighlightStandardColor,
    HighlightColorStyle, DisassemblyOption, IntegerDisplayType, FunctionAnalysisSkipOverride, FunctionUpdateType
)


def get_ast(bv):
    for func in bv.hlil_functions:
       print(func)

if __name__ == '__main__':
    testBinary = '/home/logan/Dev/IntermediateDragon/activeExperiments/ghidraEnvVarTest/rundata/run1/0.libemotion.so.1.26/0.libemotion.so.1.26'
    bv = binaryninja.load(testBinary)
    get_ast(bv)