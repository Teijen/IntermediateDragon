import hashlib
import math

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
        97: 'HLIL_FTRUNC',
        111: 'HLIL_ASSIGN_MEM_SSA',
        112: 'HLIL_ASSIGN_UNPACK_MEM_SSA',
        115: 'HLIL_DEREF_SSA',
        116: 'HLIL_DEREF_FIELD_SSA'
}

callOperations = {
        
        62: 'HLIL_CALL',
        76: 'HLIL_SYSCALL',
        77: 'HLIL_TAILCALL',
        117: 'HLIL_CALL_SSA',
        118: 'HLIL_SYSCALL_SSA'
}

#these operations do not make sense in the context of the AST
#they will normally be used in Reverse Engineering operations
#for testing purposes they will be ignored, and handled as a null node
reverseEngineeringOperations = {
        
        78: 'HLIL_INTRINSIC',
        79: 'HLIL_BP',
        80: 'HLIL_TRAP',
        81: 'HLIL_UNDEF',
        82: 'HLIL_UNIMPL',
        83: 'HLIL_UNIMPL_MEM',
        106: 'HLIL_UNREACHABLE',
        119: 'HLIL_INTRINSIC_SSA'
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
    elif BinjaType.type_class == 11: #NamedTypeReferenceClass, might need to change, structs and unions are named types, but has target so maybe not
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
                #possible collision but unlikely, 

                #should edit, var.coreVariable.identifier is a UID so I should use that, but need to 
                #figure out how to go from Type to Variable
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

def astNodeFromHLIL(hlilOp,parentNode):
    """
    Convert the given HLIL operation to an AST node
    #ssa variants default to normal hlil instrucitons here
    """
    # Check if the node is a valid HLIL operation
    if not isinstance(hlilOp, HighLevelILInstruction):
        print(hlilOp)
        return None

    opvalue = hlilOp.core_instr.operation.value
    
    # Check if the operation is a binary operation
    if opvalue in binaryOperations:
        node = astBinja.BinaryOperator.from_hlil(hlilOp)
    # Check if the operation is a unary operation
    elif opvalue in unaryOperations:
        node = astBinja.UnaryOperator.from_hlil(hlilOp)
    # Check if the operation is a call operation
    elif opvalue in callOperations:
        node = astBinja.CallExpr.from_hlil(hlilOp)
    # Check if the operation is a reverse engineering operation
    elif opvalue in reverseEngineeringOperations:
        node = astBinja.NullNode.from_hlil(hlilOp)
    elif opvalue == 0: #HLIL_NOP, might get removed as base case, tesing as null node
        node = astBinja.NullNode.from_hlil(hlilOp)
    elif opvalue == 1: #HLIL_BLOCK
        #compound statement
        node = astBinja.CompoundStmt.from_hlil(hlilOp)
    elif opvalue == 2: #HLIL_IF
        #if statement
        node = astBinja.IfStmt.from_hlil(hlilOp)
    elif opvalue == 3 or opvalue == 107: #HLIL_WHILE
        #while statement
        node = astBinja.WhileStmt.from_hlil(hlilOp)
    elif opvalue == 4 or opvalue == 108: #HLIL_DO_WHILE
        #do while statement
        node = astBinja.DoStmt.from_hlil(hlilOp)
    elif opvalue == 5 or opvalue == 108: #HLIL_FOR
        #for statement
        node = astBinja.ForStmt.from_hlil(hlilOp)
    elif opvalue == 6: #HLIL_SWITCH
        #switch statement
        node = astBinja.SwitchStmt.from_hlil(hlilOp)
    elif opvalue == 7: #HLIL_CASE
        #case statement
        node = astBinja.CaseStmt.from_hlil(hlilOp)
    elif opvalue == 8: #HLIL_BREAK
        #break statement
        node = astBinja.BreakStmt.from_hlil(hlilOp)
    elif opvalue == 9: #HLIL_CONTINUE
        #continue statement, mapped to GotoStmt since no native node
        node = astBinja.GotoStmt.from_hlil(hlilOp)
    elif opvalue == 10: #HLIL_JUMP
        #goto statement
        node = astBinja.GotoStmt.from_hlil(hlilOp)
    elif opvalue == 11: #HLIL_RETURN
        #return statement
        node = astBinja.ReturnStmt.from_hlil(hlilOp)
    elif opvalue == 12: #HLIL_NORET, think about this one some more
        #This instruction will never be executed, the instruction before it is a call that doesn't return
        #may have applications with malware binaries
        node = astBinja.NullNode.from_hlil(hlilOp)
    elif opvalue == 13: #HLIL_Goto
        #goto statement
        node = astBinja.GotoStmt.from_hlil(hlilOp)
    elif opvalue == 14: #HLIL_LABEL
        #dont know what this one is, gonna make null for placeholder
        node = astBinja.NullNode.from_hlil(hlilOp)
    elif opvalue == 15: #VAR_DECLARE
        #variable declaration, Get params for node
        bv = hlilOp.function.view
        dtype = typeConverter(hlilOp.var.type,bv)
        idValue = hlilOp.var.core_variable.identifier
        name = hlilOp.var.last_seen_name
        location = lt('stack')
        node = astBinja.VarDecl.from_hlil(hlilOp,idValue,name,dtype,location)
    elif opvalue == 16 or opvalue == 110: #VAR_INIT, possible changes to this one, binary operator for assignment?
        #variable initialization. setting dest to result of expreseseion where dest is declared variable, treating as DeclRefExpr
        variable = hlilOp.dest
        bv = hlilOp.function.view
        refID = variable.core_variable.identifier
        dtype = typeConverter(variable.type,bv)
        if type(dtype) == dt.FunctionType:
            decl_type = 1
        elif type(dtype) == dt.EnumType:
            decl_type = 3
        else:
            decl_type = 2
        #this should be already a ast node so this should work because all nodes should have the tudecl as the root
        tudecl = parentNode.find_root_node()
        node = astBinja.DeclRefExpr.from_hlil(hlilOp,tudecl,refID,decl_type)
    elif opvalue == 17: #ASSIGN
        #assignment operator maybe, seems like operator
        node = astBinja.BinaryOperator.from_hlil(hlilOp)
    elif opvalue == 18: #ASSIGN_UNPACK
        #unpacking assignment, no documentation on this one, seems like operator
        node = astBinja.BinaryOperator.from_hlil(hlilOp)
    elif opvalue == 19 or opvalue == 113: #VAR
        #variable reference, does that have a node?
        variable = hlilOp.var
        bv = hlilOp.function.view
        refID = variable.core_variable.identifier
        dtype = typeConverter(variable.type,bv)
        if type(dtype) == dt.FunctionType:
            decl_type = 1
        elif type(dtype) == dt.EnumType:
            decl_type = 3
        else:
            decl_type = 2
        #this should be already a ast node so this should work because all nodes should have the tudecl as the root
        tudecl = parentNode.find_root_node()
        node = astBinja.DeclRefExpr.from_hlil(hlilOp,tudecl,refID,decl_type)
    elif opvalue == 20: #StructField
        #struct field reference, with dummy sdb for now
        offset = hlilOp.offset
        try:
            var = hlilOp.src.var
        except:
            var = hlilOp.src.vars[0]
            

        arrow = False
        if type(var.type) == PointerType:
            arrow = True
            

        name = var.last_seen_name
        node = astBinja.MemberExpr.from_hlil(hlilOp,0,offset,name, arrow)
    elif opvalue == 21 or opvalue == 114: #ArrayIndex
        #array index reference
        node = astBinja.ArraySubscriptExpr.from_hlil(hlilOp)
    elif opvalue == 26: #CONSTANT
        #constant value
        node = astBinja.ConstantExpr.from_hlil(hlilOp)
    elif opvalue == 27: #CONSTANT_DATA
        #constant data, like global constant, valueDecl. VarDecl?
        #node = astBinja.ConstantExpr.from_hlil(hlilOp)
        node = None
    elif opvalue == 28: #ConstantPointer,
        #constant pointer, no documentation on this one VarDecl?
        node = astBinja.ConstantExpr.from_hlil(hlilOp)
        #node = None
    elif opvalue == 29: #ExternalPointer
        #external pointer, no documentation on this one VarDecl?
        node = astBinja.ConstantExpr.from_hlil(hlilOp)
        #node = None
    elif opvalue == 30: #FloatConstant
        #float constant, no documentation on this one, maybe new thing
        node = astBinja.ConstantExpr.from_hlil(hlilOp)
    elif opvalue == 31: #Import
        #A constant integral value representing an imported address, pointer or pointer?
        node = astBinja.ConstantExpr.from_hlil(hlilOp)
    elif opvalue == 120: #VarPhi
        #A PHI represents the combination of several prior versions of a variable when differnet basic blocks coalesce into a single destination 
        # and it's unknown which path was taken.Treated as reference to declared variable
        #variable reference, does that have a node?
        variable = hlilOp.dest.var
        bv = hlilOp.function.view
        refID = variable.core_variable.identifier
        dtype = typeConverter(variable.type,bv)
        if type(dtype) == dt.FunctionType:
            decl_type = 1
        elif type(dtype) == dt.EnumType:
            decl_type = 3
        else:
            decl_type = 2
        #this should be already a ast node so this should work because all nodes should have the tudecl as the root
        tudecl = parentNode.find_root_node()
        node = astBinja.DeclRefExpr.from_hlil(hlilOp,tudecl,refID,decl_type)
    elif opvalue == 121: #MemPhi
        #A memory PHI represents memory modifications that could have occured down different source basic blocks similar to a VAR_PHI
        #combination?
        #compound statement for now see what breaks
        node = astBinja.CompoundStmt.from_hlil(hlilOp)
    else:
        #null node for unknown operation
        node = astBinja.NullNode.from_hlil(hlilOp)

    return node

def recursiveTraversal(node, hlilOp):
    """
    Recursively traverse the HLIL tree to append nodes to the AST
    """
    parent = node
    #constants and variables/registers are the terminal nodes in the graph
    #per Binja Slack channel
    if isinstance(hlilOp, HighLevelILInstruction) or type(hlilOp) == list:
       
       #check against NOP and other non-operations in List
        if type(hlilOp) == list:
            if len(hlilOp) > 0:
                hlilOp = hlilOp[0]
            else:
                node = astBinja.NullNode()
                parent.add_child(node)
                return

        try:
            node = astNodeFromHLIL(hlilOp, parent)
            parent.add_child(node)
        except:
            print(hlilOp)

        # Recursively traverse the operands
        for operand in hlilOp.detailed_operands:
            recursiveTraversal(node, operand[1])
        return
    
    else:
        #need logic for constants and variables to create end nodes
        #following literal types per word doc
        #intLit, floatLit,charLit,stringLit
        
        if type(hlilOp) == int:
            #int literal
             # Get the number of bits required to represent the integer
            bitLength = hlilOp.bit_length()
            
            # Map the bit length to the nearest standard size
            if bitLength <= 8:
                bitLength = 8
            elif bitLength <= 16:
                bitLength = 16
            elif bitLength <= 32:
                bitLength = 32
            elif bitLength <= 64:
                bitLength = 64

            byte_length = bitLength/8

            _builtin_uints_by_size = {
                1: 'uchar',
                2: 'ushort',
                4: 'uint32',
                8: 'uint64',
                16: 'uint128',
                # NOTE: these are simply because Ghidra generates them for "functions"
                # like ZEXT, etc. and for that reason they can show up as temporary var
                # types (as well as data types for AST nodes in expressions)
                32: 'uint256',
                64: 'uint512',
            }

            node = astBinja.IntegerLiteral(hlilOp, dt.BuiltinType.from_standard_name(_builtin_uints_by_size[byte_length]), parent.instr_addr)
            parent.add_child(node)
        elif type(hlilOp) == float:
            #floats here are all 64 bit due to python rules?
            node = astBinja.FloatingLiteral(hlilOp,"", dt.BuiltinType.from_standard_name('double'), parent.instr_addr)
        else:
            
            if hlilOp:
                #variable reference, does that have a node?
                variable = hlilOp
                bv = variable.function.view
                refID = variable.core_variable.identifier
                dtype = typeConverter(variable.type,bv)
                if type(dtype) == dt.FunctionType:
                    decl_type = 1
                elif type(dtype) == dt.EnumType:
                    decl_type = 3
                else:
                    decl_type = 2
                #this should be already a ast node so this should work because all nodes should have the tudecl as the root
                tudecl = parent.find_root_node()
                node = astBinja.DeclRefExpr(tudecl,refID,decl_type,parent.instr_addr)
                parent.add_child(node)
            else:
                node = astBinja.NullNode()
                parent.add_child(node)

        
        return  

def get_ast(bv):
    for func in bv.functions:
        print(func.name)

        
        #set up the ast builder
        #first in the translation unit declaration
        tu = astBinja.TranslationUnitDecl()
        #this should get overwritten by hash of address to create unique id
        valueOfID = 0
        
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
            valueOfID = each.core_variable.identifier
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
        #only need root node to start but traverse is a generator

        for a in func.hlil.traverse(lambda x: x):
            #print(a)
            #print(a.detailed_operands)
            recursiveTraversal(funcBodyBase, a)
            
            break

        print(tu.to_dict())
        #break
        #print()
        #break


        

if __name__ == '__main__':
    testBinary = '/home/logan/Dev/IntermediateDragon/activeExperiments/ghidraEnvVarTest/rundata/run1/0.libemotion.so.1.26/0.libemotion.so.1.26'
    bv = binaryninja.load(testBinary)
    get_ast(bv)
    # flag = False
    # for func in bv.functions:
    #     for var in func.vars:
    #         if type(var.type) == EnumerationType:
    #             members = var.type.members
    #             uses = func.hlil.get_var_uses(var)
    #             if uses:
    #                 print(uses)
    #             for use in uses:
    #                 print(use.core_instr)
    #                 print(use.detailed_operands)
    #                 print(use.value.value)
    #                 print(members)

    #             flag = True
                #break
        # if flag:
        #     break

       
    #missingInts()