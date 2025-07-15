#!/usr/bin/env python3
"""
Independent IDA Pro AST Builder Test Script

This script contains a standalone version of the AST export functions from export_ast.py,
removing all Ghidra dependencies while keeping the HeadlessIDA methodology for testing.
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Any

# IDA AST builder imports
from headless_ida import HeadlessIda
from varlib.datatype import datatypes as dt
from varlib.datatype import structtype as st
from varlib.location import Location as lt
from astlib import ast

# This section of imports needs to fail to allow global IDA imports to be remapped when
# headless IDA is imported which has to happen later, but I need everything to be treated as a module
try:
    # These imports will work for IntelliSense via your VS Code extraPaths
    import idautils
    import ida_name
    import ida_hexrays
    import ida_funcs
    import ida_nalt
    import ida_bytes
    import ida_ua
    import ida_range
    import idc
    import ida_idaapi
    import ida_typeinf
    import ida_idp

    IDA_MODULES_AVAILABLE = True
except ImportError:
    # Fallback - won't happen since VS Code path is configured
    idautils = None
    ida_name = None
    ida_hexrays = None
    ida_funcs = None
    ida_nalt = None
    ida_bytes = None
    ida_ua = None
    ida_idaapi = None
    idc = None
    ida_range = None
    ida_typeinf = None
    ida_idp = None
    IDA_MODULES_AVAILABLE = False

# Declare operation dictionaries as None initially - will be lazy loaded
binaryOperations = None
unaryOperations = None
callOperations = None
castingOperations = None
reverseEngineeringOperations = None

def initialize_operation_dictionaries():
    """Initialize operation dictionaries after IDA modules are available - called only once per binary"""
    global binaryOperations, unaryOperations, callOperations, castingOperations, reverseEngineeringOperations
    
    if binaryOperations is not None:  # Already initialized
        return
    
    print("Initializing IDA operation dictionaries...")
    
    binaryOperations = {
        ida_hexrays.cot_add: '+',      # Addition
        ida_hexrays.cot_sub: '-',      # Subtraction  
        ida_hexrays.cot_mul: '*',      # Multiplication
        ida_hexrays.cot_sdiv: '/',     # Signed division
        ida_hexrays.cot_udiv: '/',     # Unsigned division
        ida_hexrays.cot_smod: '%',     # Signed modulus
        ida_hexrays.cot_umod: '%',     # Unsigned modulus
        ida_hexrays.cot_lor: '||',     # Logical OR
        ida_hexrays.cot_land: '&&',    # Logical AND
        ida_hexrays.cot_bor: '|',      # Bitwise OR
        ida_hexrays.cot_band: '&',     # Bitwise AND
        ida_hexrays.cot_xor: '^',      # Bitwise XOR
        ida_hexrays.cot_shl: '<<',     # Shift left
        ida_hexrays.cot_sshr: '>>',    # Signed shift right
        ida_hexrays.cot_ushr: '>>',    # Unsigned shift right
        ida_hexrays.cot_eq: '==',      # Equal
        ida_hexrays.cot_ne: '!=',      # Not equal
        ida_hexrays.cot_sge: '>=',     # Signed greater or equal
        ida_hexrays.cot_uge: '>=',     # Unsigned greater or equal
        ida_hexrays.cot_sle: '<=',     # Signed less or equal
        ida_hexrays.cot_ule: '<=',     # Unsigned less or equal
        ida_hexrays.cot_sgt: '>',      # Signed greater than
        ida_hexrays.cot_ugt: '>',      # Unsigned greater than
        ida_hexrays.cot_slt: '<',      # Signed less than
        ida_hexrays.cot_ult: '<',      # Unsigned less than
        ida_hexrays.cot_asg: '=',      # Assignment
        ida_hexrays.cot_asgadd: '+=',  # Addition assignment
        ida_hexrays.cot_asgsub: '-=',  # Subtraction assignment
        ida_hexrays.cot_asgmul: '*=',  # Multiplication assignment
        ida_hexrays.cot_asgsdiv: '/=', # Signed division assignment
        ida_hexrays.cot_asgudiv: '/=', # Unsigned division assignment
        ida_hexrays.cot_asgsmod: '%=', # Signed modulus assignment
        ida_hexrays.cot_asgumod: '%=', # Unsigned modulus assignment
        ida_hexrays.cot_asgbor: '|=',  # Bitwise OR assignment
        ida_hexrays.cot_asgband: '&=', # Bitwise AND assignment
        ida_hexrays.cot_asgxor: '^=',  # Bitwise XOR assignment
        ida_hexrays.cot_asgshl: '<<=', # Shift left assignment
        ida_hexrays.cot_asgsshr: '>>=',# Signed shift right assignment
        ida_hexrays.cot_asgushr: '>>=',# Unsigned shift right assignment
        ida_hexrays.cot_comma: ',',    # Comma operator
    }

    unaryOperations = {
        ida_hexrays.cot_ptr: '*',      # Dereference
        ida_hexrays.cot_ref: '&',      # Address-of
        ida_hexrays.cot_neg: '-',      # Negation
        ida_hexrays.cot_lnot: '!',     # Logical NOT
        ida_hexrays.cot_bnot: '~',     # Bitwise NOT
        ida_hexrays.cot_preinc: '',    # Pre-increment (no encoding support)
        ida_hexrays.cot_postinc: '',   # Post-increment (no encoding support)
        ida_hexrays.cot_predec: '',    # Pre-decrement (no encoding support)
        ida_hexrays.cot_postdec: '',   # Post-decrement (no encoding support)
    }

    callOperations = {
        ida_hexrays.cot_call: ''      # Direct call
        #ida_hexrays.cot_icall: '',     # Indirect call
    }

    castingOperations = {
        ida_hexrays.cot_cast: '',      # Cast
    }

    reverseEngineeringOperations = {
        ida_hexrays.cot_empty: '',     # Empty
        ida_hexrays.cot_fnum: '',      # Float number
        ida_hexrays.cot_helper: '',    # Helper
        ida_hexrays.cot_sizeof: '',    # Sizeof
    }

def generate_unique_id(address: int) -> int:
    """Generate a unique integer ID based on the address"""
    return int(hashlib.md5(str(address).encode()).hexdigest(), 16) % (10 ** 8)

def typeConverter(ida_type, tinfo=None):
    """Convert the given IDA type to a data type object"""
    if tinfo is None:
        return dt.BuiltinType.from_standard_name('void')
    
    # Handle basic types
    if tinfo.is_void():
        return dt.BuiltinType.from_standard_name('void')
    elif tinfo.is_bool():
        return dt.BuiltinType.from_standard_name('bool')
    elif tinfo.is_integral():
        size = tinfo.get_size()
        if tinfo.is_signed():
            std_name = dt._builtin_ints_by_size.get(size)
            if std_name is None:
                print(f"Warning: Unknown signed int size {size}, defaulting to int32")
                std_name = 'int32'
            return dt.BuiltinType.from_standard_name(std_name)
        else:
            std_name = dt._builtin_uints_by_size.get(size)
            if std_name is None:
                print(f"Warning: Unknown unsigned int size {size}, defaulting to uint32")
                std_name = 'uint32'
            return dt.BuiltinType.from_standard_name(std_name)
    elif tinfo.is_floating():
        size = tinfo.get_size()
        std_name = dt._builtin_floats_by_size.get(size)
        if std_name is None:
            print(f"Warning: Unknown float size {size}, defaulting to float")
            std_name = 'float'
        return dt.BuiltinType.from_standard_name(std_name)
    elif tinfo.is_ptr():
        target_type = tinfo.get_pointed_object()
        return dt.PointerType(typeConverter(None, target_type), tinfo.get_size())
    elif tinfo.is_array():
        elem_type = tinfo.get_array_element()
        count = tinfo.get_array_nelems()
        return dt.ArrayType(typeConverter(None, elem_type), count)
    elif tinfo.is_func():
        func_data = ida_typeinf.func_type_data_t()
        if tinfo.get_func_details(func_data):
            ret_type = typeConverter(None, func_data.rettype)
            param_types = [typeConverter(None, param.type) for param in func_data]
            return dt.FunctionType(ret_type, param_types, tinfo.get_type_name())
        else:
            return dt.FunctionType(dt.BuiltinType.from_standard_name('void'), [], '')
    elif tinfo.is_struct():
        sid = generate_unique_id(tinfo.get_size())
        return st.StructType(None, sid, False, tinfo.get_type_name())
    elif tinfo.is_union():
        sid = generate_unique_id(tinfo.get_size())
        return st.UnionType(None, sid, tinfo.get_type_name())
    elif tinfo.is_enum():
        return dt.EnumType(tinfo.get_type_name(), tinfo.get_size())
    else:
        return dt.BuiltinType.from_standard_name('void')

def get_var_location(lvar):
    """Create a Location object using IDA's lvar_t location information"""
    if lvar.is_stk_var():
        return lt('stack', '', lvar.location.stkoff())
    elif lvar.is_reg_var():
        reg_name = ida_idp.get_reg_name(lvar.location.reg1(), lvar.width)
        return lt('register', reg_name, None)
    elif lvar.is_scattered():
        return lt('register', f'scattered_{lvar.name}', None)
    else:
        return lt('stack', '', 0)

def astNodeFromHexRays(citem, parentNode, ast_context):
    """Construct and return a single AST node for the given citem with detailed field mapping from CTree and microcode."""
    if not citem:
        return ast.NullNode()

    op = citem.op
    node = None
    mba = ast_context.get('mba', None)
    ea = getattr(citem, 'ea', 0)

    # Helper function to get microcode instruction at address
    def get_minsn_at_ea(ea):
        if not mba or ea == 0:
            return None
        try:
            for block in mba.blocks:
                if hasattr(block, 'head') and block.head:
                    insn = block.head
                    while insn:
                        if insn.ea == ea:
                            return insn
                        insn = insn.next
        except:
            pass
        return None

    # Helper function to extract precise type from microcode operand
    def get_precise_type_from_mcode(minsn, operand_attr='l'):
        if not minsn:
            return None
        try:
            operand = getattr(minsn, operand_attr, None)
            if operand and hasattr(operand, 't') and operand.t:
                return typeConverter(None, operand.t)
        except:
            pass
        return None

    # Helper function to extract value from microcode operand
    def get_value_from_mcode(minsn, operand_attr='l'):
        if not minsn:
            return None
        try:
            operand = getattr(minsn, operand_attr, None)
            if operand:
                if hasattr(operand, 'value'):
                    return operand.value
                elif hasattr(operand, 'nnn') and hasattr(operand.nnn, 'value'):
                    return operand.nnn.value
        except:
            pass
        return None

    # Get microcode instruction for this address
    minsn = get_minsn_at_ea(ea)

    # Composite/block statements - use CTree for control flow structure
    if op == ida_hexrays.cit_block:
        node = ast.CompoundStmt()
        
    elif op == ida_hexrays.cit_if:
        node = ast.IfStmt(ea)
        
    elif op == ida_hexrays.cit_while:
        node = ast.WhileStmt(ea)
        
    elif op == ida_hexrays.cit_do:
        node = ast.DoStmt(ea)
        
    elif op == ida_hexrays.cit_for:
        node = ast.ForStmt(ea)
        
    elif op == ida_hexrays.cit_switch:
        node = ast.SwitchStmt(ea)
        
    elif op == ida_hexrays.cit_case:
        node = ast.CaseStmt()
        
    elif op == ida_hexrays.cit_default:
        node = ast.DefaultStmt()
        
    elif op == ida_hexrays.cit_break:
        node = ast.BreakStmt()
        
    elif op == ida_hexrays.cit_continue:
        node = ast.GotoStmt('continue', ea)
        
    elif op == ida_hexrays.cit_goto:
        # Try to get label from CTree first, then from microcode
        label_name = str(getattr(citem, 'label', 'unknown'))
        if label_name == 'unknown' and minsn:
            # Try to extract target address from microcode
            target_ea = get_value_from_mcode(minsn, 'l')
            if target_ea:
                label_name = f"loc_{target_ea:x}"
        node = ast.GotoStmt(label_name, ea)
        
    elif op == ida_hexrays.cit_return:
        node = ast.ReturnStmt(ea)

    # Binary operations - enhanced with microcode precision
    elif op in binaryOperations:
        opcode = binaryOperations[op]
        node = ast.BinaryOperator(opcode, ea)
        
    # Unary operations - enhanced with microcode precision
    elif op in unaryOperations:
        opcode = unaryOperations[op]
        node = ast.UnaryOperator(opcode, ea)
        
    # Function calls - use microcode for call details
    elif op in callOperations:
        node = ast.CallExpr()
        
    # Type casting - prefer microcode type information
    elif op in castingOperations:
        # Try microcode first for precise type information
        target_type = None
        if minsn:
            target_type = get_precise_type_from_mcode(minsn, 'd')  # destination type
        
        if not target_type:
            target_type = typeConverter(None, getattr(citem, 'type', None))
            
        node = ast.CStyleCastExpr(target_type, ea)
        
    # Reverse engineering operations
    elif op in reverseEngineeringOperations:
        if op == ida_hexrays.cot_sizeof:
            target_type = typeConverter(None, getattr(citem, 'type', None))
            node = ast.UnaryOperator('sizeof', ea)
        else:
            node = ast.NullNode()
            
    # Literals - enhanced with microcode precision
    elif op == ida_hexrays.cot_num:
        # Try microcode first for precise value and type
        value = get_value_from_mcode(minsn, 'l') if minsn else None
        dtype = get_precise_type_from_mcode(minsn, 'l') if minsn else None
        
        # Fallback to CTree values
        if value is None:
            value = getattr(citem, 'numval', 0)
            if hasattr(citem, 'n'):
                value = citem.n._value if hasattr(citem.n, '_value') else getattr(citem.n, 'value', value)
        
        if dtype is None:
            dtype = typeConverter(None, getattr(citem, 'type', None))
            
        node = ast.IntegerLiteral(value, dtype, ea)
        
    elif op == ida_hexrays.cot_fnum:
        # Enhanced floating point literal with microcode precision
        value = None
        dtype = None
        special_value = ''
        
        if minsn:
            # Try to get floating point value from microcode
            operand = getattr(minsn, 'l', None)
            if operand and hasattr(operand, 'fvalue'):
                value = operand.fvalue
            dtype = get_precise_type_from_mcode(minsn, 'l')
        
        # Fallback to CTree
        if value is None:
            value = getattr(citem, 'fnum', 0.0)
            if hasattr(citem, 'fpc'):
                fpc = citem.fpc
                if hasattr(fpc, 'to_double'):
                    value = fpc.to_double()
                elif hasattr(fpc, 'to_float'):
                    value = fpc.to_float()
                if hasattr(fpc, 'is_special') and fpc.is_special():
                    special_value = 'special'
        
        if dtype is None:
            dtype = typeConverter(None, getattr(citem, 'type', None))
            
        node = ast.FloatingLiteral(value, special_value, dtype, ea)
        
    elif op == ida_hexrays.cot_str:
        # String literal - try microcode for address-based string extraction
        value = ''
        
        if minsn:
            # Check microcode for string address
            str_addr = get_value_from_mcode(minsn, 'l')
            if str_addr:
                try:
                    ida_string = ida_bytes.get_strlit_contents(str_addr, -1, ida_nalt.STRTYPE_C)
                    if ida_string:
                        value = ida_string.decode('utf-8', errors='replace')
                except:
                    pass
        
        # Fallback to CTree
        if not value:
            if hasattr(citem, 'string'):
                value = citem.string
            elif hasattr(citem, 'str'):
                value = citem.str
                    
        node = ast.StringLiteral(value, ea)
        
    elif op == ida_hexrays.cot_char:
        # Character literal with microcode precision
        value = ''
        dtype = None
        
        if minsn:
            char_val = get_value_from_mcode(minsn, 'l')
            if char_val is not None:
                char_val = char_val & 0xFF
                value = chr(char_val) if 0 <= char_val <= 127 else f'\\x{char_val:02x}'
            dtype = get_precise_type_from_mcode(minsn, 'l')
        
        # Fallback to CTree
        if not value:
            if hasattr(citem, 'chr'):
                value = chr(citem.chr) if isinstance(citem.chr, int) else str(citem.chr)
            elif hasattr(citem, 'chrval'):
                value = chr(citem.chrval) if isinstance(citem.chrval, int) else str(citem.chrval)
        
        if dtype is None:
            dtype = typeConverter(None, getattr(citem, 'type', None))
            
        node = ast.CharacterLiteral(value, dtype, ea)
        
    # Variable and object references - enhanced with microcode location info
    elif op == ida_hexrays.cot_obj:
        tudecl = ast_context.get('tu')
        obj_ea = getattr(citem, 'obj_ea', 0)
        
        # Try to get more precise object address from microcode
        if minsn:
            mcode_addr = get_value_from_mcode(minsn, 'l')
            if mcode_addr and mcode_addr != 0:
                obj_ea = mcode_addr
        
        referenced_id = generate_unique_id(obj_ea) if obj_ea else -1
        
        # Determine declaration type
        decl_type = -1
        if obj_ea:
            if ida_funcs.get_func(obj_ea):
                decl_type = 1  # FunctionDecl
            else:
                decl_type = 2  # VarDecl (global variable)
                
        node = ast.DeclRefExpr(tudecl, referenced_id, decl_type, ea)
        
    elif op == ida_hexrays.cot_var:
        # Local variable reference
        tudecl = ast_context.get('tu')
        lvar = getattr(citem, 'v', None)
        referenced_id = -1
        
        if lvar:
            if lvar.name:
                referenced_id = generate_unique_id(ast_context.get('func_address', 0) + hash(lvar.name))
            else:
                defblk = getattr(lvar, 'defblk', 0) or 0
                referenced_id = generate_unique_id(ast_context.get('func_address', 0) + defblk + 3000000)
            
        decl_type = 2  # VarDecl
        node = ast.DeclRefExpr(tudecl, referenced_id, decl_type, ea)
        
    # Member access - enhanced with microcode offset precision
    elif op == ida_hexrays.cot_memref:
        member_offset = getattr(citem, 'm', 0)
        member_name = ''
        sid = -1
        is_arrow = False
        
        # Try to get more precise offset from microcode
        if minsn:
            # Check for offset in microcode operands
            mcode_offset = get_value_from_mcode(minsn, 'r')  # offset might be in right operand
            if mcode_offset is not None:
                member_offset = mcode_offset
        
        # Extract member details from CTree type info
        if hasattr(citem, 'type') and citem.type:
            try:
                if citem.type.is_ptr():
                    is_arrow = True
                    pointed_type = citem.type.get_pointed_object()
                    if pointed_type and pointed_type.is_struct():
                        sid = pointed_type.get_ordinal()
                elif citem.type.is_struct():
                    sid = citem.type.get_ordinal()
                    
                if sid != -1:
                    member_name = f"field_{member_offset:x}"
                    
            except Exception:
                pass
                
        sdb = ast_context.get('sdb', None)
        node = ast.MemberExpr(sid, member_offset, member_name, is_arrow, ea, sdb)
        
    # Assignment, address-of, dereference - treated as operators
    elif op == ida_hexrays.cot_asg:
        node = ast.BinaryOperator('=', ea)
        
    elif op == ida_hexrays.cot_ref:
        node = ast.UnaryOperator('&', ea)
        
    elif op == ida_hexrays.cot_ptr:
        node = ast.UnaryOperator('*', ea)
        
    # Parentheses
    elif op == ida_hexrays.cot_paren:
        node = ast.ParenExpr(ea)
        
    # Array subscript - enhanced with microcode bounds info
    elif op == ida_hexrays.cot_idx:
        node = ast.ArraySubscriptExpr(ea)
        
    # Expression statements
    elif op == ida_hexrays.cit_expr:
        node = ast.CompoundStmt()  # Wrap expression in compound statement
        
    # Constants and other expressions
    elif op == ida_hexrays.cot_const:
        node = ast.ConstantExpr()
        
    # Helper expressions (intrinsic calls)
    elif op == ida_hexrays.cot_helper:
        node = ast.CallExpr()
        
    # Ternary operator (conditional expression)
    elif op == ida_hexrays.cot_tern:
        # Represent as parenthesized expression for now
        node = ast.ParenExpr(ea)
        
    # Type operations
    elif op == ida_hexrays.cot_type:
        node = ast.ConstantExpr()
        
    # Empty expression
    elif op == ida_hexrays.cot_empty:
        node = ast.NullNode()
        
    # Default case
    else:
        print(f"Warning: Unhandled CTree operation {op}")
        node = ast.NullNode()

    return node


def recursiveTraversalHybrid(parent, citem, ast_context):
    """Generic walker: for each possible child field, recurse. No op checks or node type logic here."""
    if not citem or type(parent) is ast.DeclRefExpr:
        return
    try:
        node = astNodeFromHexRays(citem, parent, ast_context)
        if node is None:
            return
        parent.add_child(node)

        # Recursively process all possible child fields
        for field in ("x", "y", "z"):
            child = getattr(citem, field, None)
            if child:
                recursiveTraversalHybrid(node, child, ast_context)
        # if hasattr(citem, "cblock") and citem.cblock:
        #     for stmt in citem.cblock:
        #         recursiveTraversalHybrid(node, stmt, ast_context)
        # if hasattr(citem, "cif"):
        #     if getattr(citem.cif, "expr", None):
        #         recursiveTraversalHybrid(node, citem.cif.expr, ast_context)
        #     if getattr(citem.cif, "ithen", None):
        #         recursiveTraversalHybrid(node, citem.cif.ithen, ast_context)
        #     if getattr(citem.cif, "ielse", None):
        #         recursiveTraversalHybrid(node, citem.cif.ielse, ast_context)
        # if hasattr(citem, "cwhile"):
        #     if getattr(citem.cwhile, "expr", None):
        #         recursiveTraversalHybrid(node, citem.cwhile.expr, ast_context)
        #     if getattr(citem.cwhile, "body", None):
        #         recursiveTraversalHybrid(node, citem.cwhile.body, ast_context)
        # if hasattr(citem, "cfor"):
        #     if getattr(citem.cfor, "init", None):
        #         recursiveTraversalHybrid(node, citem.cfor.init, ast_context)
        #     if getattr(citem.cfor, "expr", None):
        #         recursiveTraversalHybrid(node, citem.cfor.expr, ast_context)
        #     if getattr(citem.cfor, "step", None):
        #         recursiveTraversalHybrid(node, citem.cfor.step, ast_context)
        #     if getattr(citem.cfor, "body", None):
        #         recursiveTraversalHybrid(node, citem.cfor.body, ast_context)
        # if hasattr(citem, "cdo"):
        #     if getattr(citem.cdo, "body", None):
        #         recursiveTraversalHybrid(node, citem.cdo.body, ast_context)
        #     if getattr(citem.cdo, "expr", None):
        #         recursiveTraversalHybrid(node, citem.cdo.expr, ast_context)
        # if hasattr(citem, "cswitch"):
        #     if getattr(citem.cswitch, "expr", None):
        #         recursiveTraversalHybrid(node, citem.cswitch.expr, ast_context)
        #     if getattr(citem.cswitch, "body", None):
        #         recursiveTraversalHybrid(node, citem.cswitch.body, ast_context)
        # if hasattr(citem, "creturn") and getattr(citem.creturn, "expr", None):
        #     recursiveTraversalHybrid(node, citem.creturn.expr, ast_context)
        # if hasattr(citem, "case_expr") and citem.case_expr:
        #     recursiveTraversalHybrid(node, citem.case_expr, ast_context)
        # if hasattr(citem, "case_body") and citem.case_body:
        #     recursiveTraversalHybrid(node, citem.case_body, ast_context)
        # if hasattr(citem, "default_body") and citem.default_body:
        #     recursiveTraversalHybrid(node, citem.default_body, ast_context)
    except Exception as e:
        print(f"Error processing citem in hybrid traversal: {e}")
        null_node = ast.NullNode()
        parent.add_child(null_node)

def recursiveLists(node, DeclRefExprList, VarDeclList):
    """Build lists of referenced and declared variables"""
    if isinstance(node, ast.DeclRefExpr) or isinstance(node, ast.EnumConstantDecl):
        DeclRefExprList.append(node)
    elif isinstance(node, ast.VarDecl) or isinstance(node, ast.ValueDecl):
        VarDeclList.append(node)

    for child in node.inner:
        recursiveLists(child, DeclRefExprList, VarDeclList)

def get_ast(funcInfo):
    """Generate AST from IDA function using hybrid CTree/microcode approach"""
    # Get function object
    func = ida_funcs.get_func(funcInfo['entry_point'])
    if not func:
        raise ValueError(f"No function found at address {funcInfo['entry_point']:x}")

    # Get decompiled function (CTree)
    try:
        cfunc = ida_hexrays.decompile(func)
        if not cfunc:
            raise ValueError(f"Failed to decompile function at {funcInfo['entry_point']:x}")
    except Exception as e:
        raise ValueError(f"Decompilation failed: {e}")
    
    # Get microcode (MMAT_LVARS level for detailed operations)
    try:
        ranges = ida_hexrays.mba_ranges_t(func)
        mba = ida_hexrays.gen_microcode(ranges, None, None, 0, ida_hexrays.MMAT_LVARS)
        if not mba:
            raise ValueError(f"Failed to generate microcode for function at {funcInfo['entry_point']:x}")
    except Exception as e:
        print(f"Warning: Could not generate microcode, falling back to CTree only: {e}")
        mba = None
    
    # Set up the AST builder
    tu = ast.TranslationUnitDecl()
    
    # Get function information
    func_name = funcInfo['name']
    func_address = funcInfo['entry_point']

    # Get function type information
    try:
        tinfo = None
        raw_tinfo = ida_typeinf.idc_get_type_raw(func_address)
        if raw_tinfo and raw_tinfo[0]:
            type_bytes, field_bytes = raw_tinfo
            tinfo = ida_typeinf.tinfo_t()
            tinfo.deserialize(ida_typeinf.get_idati(), type_bytes, field_bytes) 


        if tinfo:
            func_return_type = typeConverter(None, tinfo)
        else:
            func_return_type = dt.BuiltinType.from_standard_name('void')
    except Exception as e:
        print(f"Warning: Could not get function type: {e}")
        func_return_type = dt.BuiltinType.from_standard_name('void')
    
    # Get function parameters from CTree
    func_params_converted = []
    if cfunc.get_lvars():
        lvars = cfunc.get_lvars()
        for i, lvar in enumerate(lvars):
            if lvar.is_arg_var:  # Only include actual parameters
                param_id = generate_unique_id(func_address + i + 4000000)
                param_name = lvar.name or f"arg_{i}"
                param_type = typeConverter(None, lvar.type())
                param_location = get_var_location(lvar)
                
                param_decl = ast.ParmVarDecl(param_id, param_name, param_type, param_location)
                func_params_converted.append(param_decl)
    
    # Create function declaration
    func_id = generate_unique_id(func_address + 5000000)
    func_decl = ast.FunctionDecl(func_id, func_name, func_address, False, 
                                func_return_type, func_params_converted)
    
    # Create function body using hybrid approach
    func_body = ast.CompoundStmt()
    
    # Set up AST context for traversal
    ast_context = {
        'func': cfunc,
        'func_address': func_address,
        'mba': mba,
        'tu': tu,
        'ea_to_minsn': {},
        'minsn_to_operands': {}
    }
    
    # Traverse the CTree structure for control flow
    if cfunc.body:
        recursiveTraversalHybrid(func_body, cfunc.body, ast_context)
    
    # Handle variable declarations from CTree
        ref_vars = []
        var_decls = []
        recursiveLists(func_body, ref_vars, var_decls)

        missing_vars = [x for x in ref_vars if x not in var_decls]

        # Collect all existing VarDecl nodes found in the tree
        existing_var_decl_nodes = []

        def collect_var_decl_nodes(node):
            """Recursively collect all VarDecl nodes from the tree"""
            if isinstance(node, ast.VarDecl):
                existing_var_decl_nodes.append(node)
            for child in node.inner:
                collect_var_decl_nodes(child)

        # Collect all existing VarDecl nodes
        collect_var_decl_nodes(func_body)

        # Copy all found VarDecl nodes to the beginning of function body (keep originals in place)
        for var_decl_node in existing_var_decl_nodes:
        # Create a copy of the VarDecl node
            copied_var_decl = ast.VarDecl(
                var_decl_node.id,
                var_decl_node.name,
                var_decl_node.data_type,
                var_decl_node.location
            )

            # Create DeclStmt wrapper for the copy
            decl_stmt = ast.DeclStmt()
            decl_stmt.add_child(copied_var_decl)

            # Insert copy at beginning of function body
            func_body.inner.insert(0, decl_stmt)
            decl_stmt.parent = func_body

       # Add missing global variables (DeclRefExpr IDs not found in any VarDecl) to translation unit
        for var_id in missing_vars:
            # Find the DeclRefExpr node with this ID
            found_declref = var_id
            if found_declref:
                # Use the address to get name and type from IDA
                addr = found_declref.instr_addr
                var_name = ida_name.get_name(addr) or f"global_var_{var_id}"
                tinfo = None
                raw_tinfo = ida_typeinf.idc_get_type_raw(addr)
                if raw_tinfo and raw_tinfo[0]:
                    type_bytes, field_bytes = raw_tinfo
                    tinfo = ida_typeinf.tinfo_t()
                    tinfo.deserialize(ida_typeinf.get_idati(), type_bytes, field_bytes) 


                var_type = typeConverter(None, tinfo) if tinfo else dt.BuiltinType.from_standard_name('int')
                var_location = lt('stack', '', addr)
                
                var_node = ast.VarDecl(var_id, var_name, var_type, var_location)
                tu.add_child(var_node)

        # Assemble the final AST
        func_decl.add_child(func_body)
        tu.add_child(func_decl)
    
    return tu

def analyze_binary_with_ida(binary_path: Path, export_folder: Path, timeout_sec: int = 240, max_funcs: int = -1):
    """Analyze a binary with IDA and export ASTs"""
    
    failed_ast_exports = []
    headlessIda = None
    
    try:
        print(f"Starting IDA analysis of {binary_path}")
        headlessIda = HeadlessIda("/home/logan/ida-classroom-free-9.0/ida", str(binary_path))
        
        # Import IDA modules after HeadlessIDA is initialized
        global idautils, ida_name, ida_hexrays, ida_funcs, ida_nalt, ida_bytes, ida_ua, ida_idaapi, idc, ida_range, ida_typeinf, ida_idp
        
        import idautils as _idautils
        import ida_name as _ida_name
        import ida_hexrays as _ida_hexrays
        import ida_funcs as _ida_funcs
        import ida_nalt as _ida_nalt
        import ida_bytes as _ida_bytes
        import ida_ua as _ida_ua
        import ida_idaapi as _ida_idaapi
        import idc as _idc
        import ida_range as _ida_range
        import ida_typeinf as _ida_typeinf
        import ida_idp as _ida_idp

        # Reassign globals
        idautils = _idautils
        ida_name = _ida_name
        ida_hexrays = _ida_hexrays
        ida_funcs = _ida_funcs
        ida_nalt = _ida_nalt
        ida_bytes = _ida_bytes
        ida_ua = _ida_ua
        ida_idaapi = _ida_idaapi
        idc = _idc
        ida_range = _ida_range
        ida_typeinf = _ida_typeinf
        ida_idp = _ida_idp


        # Initialize operation dictionaries
        initialize_operation_dictionaries()

        # Get non-thunk functions
        nonthunks = []
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func and not (func.flags & ida_funcs.FUNC_THUNK):
                func_info = {
                    'entry_point': func.start_ea,
                    'name': idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}",
                    'start_addr': func.start_ea,
                    'end_addr': func.end_ea,
                    'size': func.end_ea - func.start_ea,
                    'flags': func.flags
                }
                nonthunks.append(func_info)
        
        print(f'Found {len(nonthunks)} non-thunk functions')
        print(f'Exporting function ASTs...')

        # Process functions
        for i, func in enumerate(nonthunks):
            if max_funcs > -1 and i >= max_funcs:
                break

            try:
                print(f"Processing function {i+1}/{len(nonthunks)}: {func['name']} at {func['entry_point']:x}")
                ast_result = get_ast(func)
                
                if ast_result is None:
                    addr_str = f'{func["entry_point"]:x}'
                    failed_ast_exports.append(addr_str)
                    continue
                    
                # Save AST to JSON
                filename = f'Func{func["entry_point"]:x}-{func["name"]}.json'
                for ch in "<>:\"/\\|?*":
                    filename = filename.replace(ch, '_')

                if len(filename) > 255:
                    filename = filename[:50] + filename[-200:]

                output_path = export_folder / filename
                with open(output_path, 'w') as f:
                    json.dump(ast_result.to_dict(), f, indent=2)
                    
                print(f"  Saved AST to {output_path}")
                
            except Exception as e:
                addr_str = f'{func["entry_point"]:x}'
                failed_ast_exports.append(addr_str)
                print(f"  Error processing function {func['name']}: {e}")
                continue

        # Save failed exports log
        if failed_ast_exports:
            failed_path = export_folder / f'{binary_path.name}_failed_ast_exports.txt'
            with open(failed_path, 'w') as f:
                f.write('\n'.join(failed_ast_exports))
            print(f"Failed exports logged to: {failed_path}")
            
        print(f"Analysis complete. Processed {len(nonthunks) - len(failed_ast_exports)} functions successfully.")
        
    except Exception as e:
        print(f"Error during IDA analysis: {e}")
        return 1
        
    finally:
        if headlessIda:
            try:
                del headlessIda
            except Exception as e:
                print(f"Error closing HeadlessIDA: {e}")
    
    return 0

def main():
    """Main function for debugging IDA AST export"""
    
    # Hardcoded paths for debugging
    binary_path = Path("/home/logan/Dev/IntermediateDragon/dragonBinaries/tydamin_sample/app-accessibility/at-spi2-atk-2.38.0/libatk-bridge-2.0.so.0.0.0")  # Change this to your test binary
    export_folder = Path("./debug_ast_output")
    timeout_sec = 240
    max_funcs = 5  # Limit to 5 functions for debugging
    
    if not binary_path.exists():
        print(f"Error: Binary file {binary_path} does not exist")
        print("Please update the hardcoded binary_path in main() function")
        return 1
    
    # Create export folder
    export_folder.mkdir(parents=True, exist_ok=True)
    
    print("IDA Pro AST Builder Debug Test")
    print("=" * 40)
    print(f"Binary: {binary_path}")
    print(f"Export folder: {export_folder}")
    print(f"Max functions: {max_funcs}")
    print()
    
    return analyze_binary_with_ida(binary_path, export_folder, timeout_sec, max_funcs)

if __name__ == "__main__":
    exit(main())
