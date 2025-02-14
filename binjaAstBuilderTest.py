import hashlib

from binaryninja import *
from binaryninja import lineardisassembly
from binaryninja.function import *
from binaryninja.enums import (
    AnalysisSkipReason, FunctionGraphType, SymbolType, InstructionTextTokenType, HighlightStandardColor,
    HighlightColorStyle, DisassemblyOption, IntegerDisplayType, FunctionAnalysisSkipOverride, FunctionUpdateType
)

from astlib import astBinja
from varlib.datatype import datatypes as dt
from varlib.datatype import structtype as st
from varlib.location import Location as lt
#this should get overwritten by hash of address to create unique id
valueOfID = 0

binaryOperations = {
        32: '+', #HLIL_ADD
        33: '+', #HLIL_ADC
        34: '-', #HLIL_SUB
        35: '-', #HLIL_SBB 
        36: '&&', #HLIL_AND
        37: '||', #HLIL_OR
        38: '^', #HLIL_XOR
        39: '<<', #HLIL_LSL
        40: 'u>>', #HLIL_LSR
        41: 's>>', #HLIL_ASR
        42: 'HLIL_ROL', 
        43: 'HLIL_RLC', 
        44: 'HLIL_ROR', 
        45: 'HLIL_RRC', 
        46: '*', #HLIL_MUL
        47: 'HLIL_MULU_DP',
        48: 'HLIL_DIVU',
        49: 'HLIL_DIVU_DP',
        50: 'divu.dp.q', #HLIL_DIVU_DP
        51: 'HLIL_DIVS',
        52: 'divs.dp.d', #HLIL_DIVS_DP
        53: 'HLIL_MODU',
        54: 'HLIL_MODU_DP',
        55: 'HLIL_MODS',
        56: 'HLIL_MODS_DP', #HLIL_DIV
        63: '==', #HLIL_CMP_E
        64: '!=', #HLIL_CMP_NE
        65: 'HLIL_CMPLE',
        66: 'u<', #HLIL_CMP_ULT
        67: 's<=', #HLIL_CMP_SLE
        68: 'u<=', #HLIL_CMP_ULE
        69: 's>=', #HLIL_CMP_SGE
        70: 'u>=', #HLIL_CMP_UGE
        71: 's>', #HLIL_CMP_SGT
        72: 'u>', #HLIL_CMP_UGT
        73: 'HLIL_TEST_BIT',
        75: 'HLIL_ADD_OVERFLOW',
        84: 'HLIL_FADD',
        85: 'f-', #HLIL_FSUB
        86: 'f*', #HLIL_FMUL
        87: 'f/', #HLIL_FDIV
        88: 'HLIL_FSQRT',
        98: 'HLIL_FCMP_E',
        99: 'HLIL_FCMP_NE',
        100: 'HLIL_FCMP_LT',
        101: 'HLIL_FCMP_LE',
        102: 'HLIL_FCMP_GE',
        103: 'HLIL_FCMP_GT',
        104: 'HLIL_FCMP_O',
        105: 'HLIL_FCMP_UO'
}

unaryOperations = {
        
        23: 'HLIL_DEREF',
        24: 'HLIL_DEREF_FIELD',
        25: 'HLIL_ADDRESS_OF',
        57: 'HLIL_NEG',
        58: 'HLIL_NOT',
        59: 'HLIL_SX',
        60: 'HLIL_ZX',
        61: 'HLIL_LOW_PART',
        74: 'HLIL_BOOL_TO_INT', #casting or unary?
        89: 'HLIL_FNEG',
        90: 'HLIL_FABS',
        91: 'HLIL_FLOAT_TO_INT', #again casting?
        92: 'HLIL_INT_TO_FLOAT', #again casting?
        93: 'HLIL_FLOAT_CONV', #again casting?
        94: 'HLIL_ROUND_TO_INT', #again casting?
        95: 'HLIL_FLOOR',
        96: 'HLIL_CEIL',
        97: 'HLIL_FTRUNC'
}

def generate_unique_id(address: int) -> int:
        # Generate a unique integer ID based on the address
        return int(hashlib.md5(str(address).encode()).hexdigest(), 16) % (10 ** 8)
    

def typeConverter(BinjaType,bv):
    """
    Convert the given binary ninja type to a data type object
    """
    # these are the types that need to be converted
    # BuiltIn = 'BUILTIN'
    # Pointer = 'PTR' X
    # Array = 'ARR'   X
    # Struct = 'STRUCT'  not special case in datatype
    # Union = 'UNION' unions are considered a struct in binja, method to differentiate?
    # Enum = 'ENUM'      X
    # Function = 'FUNC'  X

    #check against type category for need of recursion
    if BinjaType.type_class == 6: #PointerTypeClass
        typeCon = dt.PointerType(typeConverter(BinjaType.target,bv),BinjaType.width)
    elif BinjaType.type_class == 11: #NamedTypeReferenceClass
        typeCon = dt.PointerType(typeConverter(BinjaType.target(bv),bv),BinjaType.width)
    elif BinjaType.type_class == 7: #ArrayTypeClass
        typeCon = dt.ArrayType(typeConverter(BinjaType.element_type,bv), BinjaType.count)
    elif BinjaType.type_class == 5: #EnumerationTypeClass
        typeCon = dt.EnumType(BinjaType.altname, BinjaType.width)
    elif BinjaType.type_class == 8: #FunctionTypeClass
        paramConverted = []
        params = BinjaType.parameters
        for each in params:
            paramConverted.append(typeConverter(each.type,bv))
        typeCon = dt.FunctionType(typeConverter(BinjaType.return_value,bv), paramConverted, BinjaType.altname)                                     
    else: #built in type
       
        if BinjaType.type_class == 0: #VoidTypeClass
            typeCon = dt.BuiltinType.from_standard_name('void')
        elif BinjaType.type_class == 1: #BoolTypeClass    
            typeCon = dt.BuiltinType.from_standard_name('bool')
        elif BinjaType.type_class == 2: #IntegerTypeClass
            if BinjaType.signed:
                typeCon = dt.BuiltinType.from_standard_name(dt._builtin_ints_by_size[BinjaType.width])
            else:
                typeCon = dt.BuiltinType.from_standard_name(dt._builtin_uints_by_size[BinjaType.width])
        elif BinjaType.type_class == 3: #FloatTypeClass
            typeCon = dt.BuiltinType.from_standard_name(dt._builtin_floats_by_size[BinjaType.width])
        elif BinjaType.type_class == 4: #StructTypeClass, has StrucutreVariant value
            if BinjaType.type == 2:
                #this is method to generate a unique id for the struct using properties from binary ninja
                #possible collision but unlikely
                sid = generate_unique_id(BinjaType.width + BinjaType.pointer_offset)

                typeCon = st.StructType(None,sid,False,BinjaType.altname)
            else:
                sid = generate_unique_id(BinjaType.width + BinjaType.pointer_offset)
                typeCon = st.UnionType(None,sid,BinjaType.altname)

        elif BinjaType.type_class == 12: #wideCharTypeClass
            typeCon = dt.BuiltinType.from_standard_name('char')
            typeCon.size = BinjaType.width
        else:
            print('Unknown type class: {}'.format(BinjaType.type_class))
            typeCon = dt.BuiltinType.from_standard_name('void')
            #raise Exception('Unknown type class: {}'.format
    return typeCon

def missingInts():
    missingInts = []
    for i in range(0, 122):
        if i not in binaryOperations and i not in unaryOperations:
            missingInts.append(i)

    print(missingInts)
    print(len(missingInts))


def recursiveTraversal(node, hlilOp):
    """
    Recursively traverse the HLIL tree to append nodes to the AST
    """
    # Check if the node is a valid HLIL operation
    # if type(hlilOp) == list:
    #     if hlilOp == None or not hlilOp:
    #         print('end node') 
    #         return
    #     elif hlilOp[0] == 'constant' or hlilOp== [] or hlilOp[0] == 'src':
    #         print('end node')
    #         return
    # elif type(hlilOp) == int:
    #     print('end node')
    #     return
   

    #constants and variables/registers are the terminal nodes in the graph
    #per Binja Slack channel
    if not isinstance(hlilOp, HighLevelILInstruction):
        print(hlilOp)
        return

    # # Print the operation name
    #print('normal node')
    print(hlilOp.ast)

    # Recursively traverse the operands
    for operand in hlilOp.detailed_operands:
        recursiveTraversal(node, operand[1])

    return

def get_ast(bv):
    for func in bv.functions:

        
        #set up the ast builder
        #first in the translation unit declaration
        tu = astBinja.TranslationUnitDecl()

        
        #then the function declaration with translation unit as parent
        funcName = func.name
        funcAddress = func.start
        funcReturnType = func.return_type
        funcReturnType = typeConverter(funcReturnType,bv)
        funcParams = func.parameter_vars.vars
        funcFirstHLILTemp = func.hlil.root


        # nodeTest = astBinja.VarDecl.from_hlil(func.hlil.root,valueOfID,funcName,funcReturnType,lt('stack'))
        # print(nodeTest.to_dict())
        # return
        #need to make param objects from var objects and convert return type
        funcParamsConverted = []

        for each in funcParams:
            typeCon = typeConverter(each.type,bv)
            funcParamsConverted.append(astBinja.ParmVarDecl.from_hlil(funcFirstHLILTemp, valueOfID, each.last_seen_name, typeCon, lt('stack')))



        #funcDecl = astBinja.FunctionDecl.from_hlil(funcFirstHLILTemp, valueOfID,  funcName, funcAddress, False, funcReturnType, funcParamsConverted)
        funcDecl = astBinja.FunctionDecl(valueOfID,  funcName, funcAddress, False, funcReturnType, funcParamsConverted)
        tu.add_child(funcDecl)
        #then the function body  as a combo statement with the function declaration as parent
        funcBodyBase = astBinja.CompoundStmt()
        #add the function body to the function declaration
        funcDecl.add_child(funcBodyBase)
        #print(tu.to_dict())
        #traverse each hlil instruction in the function in dfs order
        instructionsDFS = []

        for a in func.hlil.traverse(lambda x: x):
            #print(a)
            #print(a.detailed_operands)
            recursiveTraversal(funcBodyBase, a)
            #print(a.instr.value.type)
            #print(a.instr.value.operation.value)
            #print(a.instr.value.operation)
            #print(a.instr.value.operation.value)
            #print(a.instr.value.operation.name)
            #print(a.instr.value.operation.name == 'HLIL_CALL')
            #print(a.instr.value.operation.name == 'HLIL_CALL_INDIRECT')
            #instructionsDFS.append(a)
            break
        
        # a = instructionsDFS[0]
        # print(a.ast)
        # print(a.operands)
        # print(a.detailed_operands)
        # print(a.operands[0])
        # print(instructionsDFS[2].ast)
        #print(a.core_instr)
        # print(a.core_instr.operation.value) #can get intruction type and make a map of values to ghidra ast stuff
        # print(type(str(a.core_instr.operation)))
        # print(a.core_instr.operands)
        # print(a.mlil)
        # if a.mlil:
        #     print(a.mlil.instr)
        #     print(a.mlil)
        #     print(a.mlil.instr.value.type)
        # print(a.llil) #type info not in llil
        # print(a.core_instr.operands)
        print()
        #break


        # for a in func.hlil.traverse(lambda x: x):
        #     #print()
        #     print(a.ast)
        #     #print(a.operands)
        #     #print(a.detailed_operands)
        #     #print(a.core_instr)
        #     #print(a.core_instr.operands)
        #     #print()
        #     #break
        # print()
        # for a in func.hlil.traverse(lambda x: x):
        # #print()
        # #print(a.ast)
        # #print(a.operands)
        #     print(a.detailed_operands)
        # #print(a.core_instr)
        # #print(a.core_instr.operands)
        # #print()
        # #break
        # print()
        # for a in func.hlil.traverse(lambda x: x):
        # #print()
        # # print(a.ast)
        # #print(a.operands)
        # # print(a.detailed_operands)
        #     print(a.core_instr)
        # # print(a.core_instr.operands)
        # # print()
        # #break
        # print()
        # for a in func.hlil.traverse(lambda x: x):
        # #print()
        # # print(a.ast)
        # #print(a.operands)
        # # print(a.detailed_operands)
        # # print(a.core_instr)
        # #print(a.core_instr.operands)
        # # print()
        # #break
        #  print()
        # #print(func.hlil)
        #break
       

if __name__ == '__main__':
    testBinary = '/home/logan/Dev/IntermediateDragon/activeExperiments/ghidraEnvVarTest/rundata/run1/0.libemotion.so.1.26/0.libemotion.so.1.26'
    bv = binaryninja.load(testBinary)
    get_ast(bv)
    #missingInts()