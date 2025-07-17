#!/usr/bin/env python3
"""
Example usage of IDA Pro AST Builder

This script shows how to generate and work with ASTs from IDA Pro functions.
Run this script from within IDA Pro with a loaded binary.
"""

import sys
import os
from pathlib import Path

# Example usage assuming the script is in the same directory as astlib
script_dir = Path(__file__).parent
astlib_path = script_dir / "astlib" / "src"
sys.path.insert(0, str(astlib_path))

def example_single_function():
    """Generate AST for a single function"""
    try:
        import idaapi as ida
        import idc
        from idalib import get_ast
        
        # Get function at current cursor position
        func_ea = idc.here()
        func = ida.get_func(func_ea)
        
        if not func:
            print(f"No function found at {func_ea:x}")
            return None
        
        print(f"Generating AST for function: {ida.get_func_name(func.start_ea)}")
        
        # Generate the AST
        ast = get_ast(func.start_ea)
        
        print(f"✓ AST generated successfully!")
        print(f"  Root node type: {ast.kind}")
        print(f"  Total nodes: {ast.compute_size()}")
        
        # Analyze the AST
        analyze_ast(ast)
        
        # Save to JSON
        output_file = f"ast_{func.start_ea:x}.json"
        ast.to_json(Path(output_file))
        print(f"✓ AST saved to: {output_file}")
        
        return ast
        
    except ImportError:
        print("Error: This script must be run from within IDA Pro")
        return None
    except Exception as e:
        print(f"Error generating AST: {e}")
        return None

def analyze_ast(ast):
    """Analyze the generated AST and print statistics"""
    
    # Count different node types
    node_counts = {}
    def count_nodes(node):
        node_type = node.kind
        node_counts[node_type] = node_counts.get(node_type, 0) + 1
        for child in node.inner:
            count_nodes(child)
    
    count_nodes(ast)
    
    print("\n📊 AST Analysis:")
    print(f"  Node type distribution:")
    for node_type, count in sorted(node_counts.items()):
        print(f"    {node_type}: {count}")
    
    # Find function calls
    calls = []
    def find_calls(node):
        if node.kind == 'CallExpr':
            calls.append(node)
        for child in node.inner:
            find_calls(child)
    
    find_calls(ast)
    print(f"  Function calls: {len(calls)}")
    
    # Find binary operations
    binary_ops = []
    def find_binary_ops(node):
        if node.kind == 'BinaryOperator':
            binary_ops.append(node.opcode)
        for child in node.inner:
            find_binary_ops(child)
    
    find_binary_ops(ast)
    if binary_ops:
        op_counts = {}
        for op in binary_ops:
            op_counts[op] = op_counts.get(op, 0) + 1
        print(f"  Binary operations:")
        for op, count in sorted(op_counts.items()):
            print(f"    {op}: {count}")
    
    # Find variables
    vars_found = []
    def find_vars(node):
        if node.kind == 'VarDecl':
            vars_found.append(node.name)
        elif node.kind == 'DeclRefExpr':
            if hasattr(node, 'referencedDecl') and node.referencedDecl:
                if hasattr(node.referencedDecl, 'name'):
                    vars_found.append(node.referencedDecl.name)
        for child in node.inner:
            find_vars(child)
    
    find_vars(ast)
    unique_vars = set(vars_found)
    print(f"  Variables referenced: {len(unique_vars)}")
    
    # Find control flow
    control_flow = []
    def find_control_flow(node):
        if node.kind in ['IfStmt', 'WhileStmt', 'ForStmt', 'DoStmt', 'SwitchStmt']:
            control_flow.append(node.kind)
        for child in node.inner:
            find_control_flow(child)
    
    find_control_flow(ast)
    if control_flow:
        cf_counts = {}
        for cf in control_flow:
            cf_counts[cf] = cf_counts.get(cf, 0) + 1
        print(f"  Control flow:")
        for cf, count in sorted(cf_counts.items()):
            print(f"    {cf}: {count}")

def example_ast_traversal(ast):
    """Example of traversing an AST to extract information"""
    
    print("\n🔍 AST Traversal Example:")
    
    # Custom visitor to find all integer literals
    class IntegerFinder:
        def __init__(self):
            self.integers = []
        
        def visit(self, node):
            if node.kind == 'IntegerLiteral':
                self.integers.append(node.value)
            for child in node.inner:
                self.visit(child)
        
        def get_results(self):
            return sorted(set(self.integers))
    
    finder = IntegerFinder()
    finder.visit(ast)
    integers = finder.get_results()
    
    if integers:
        print(f"  Integer constants found: {integers}")
    else:
        print("  No integer constants found")
    
    # Find string literals
    strings = []
    def find_strings(node):
        if node.kind == 'StringLiteral':
            strings.append(node.value)
        for child in node.inner:
            find_strings(child)
    
    find_strings(ast)
    if strings:
        print(f"  String literals: {strings}")
    else:
        print("  No string literals found")

def example_batch_processing():
    """Example of processing multiple functions"""
    try:
        import idautils
        from idalib import get_ast
        
        print("\n📁 Batch Processing Example:")
        
        # Get first 5 functions (to avoid overwhelming output)
        function_list = list(idautils.Functions())[:5]
        
        for i, func_ea in enumerate(function_list, 1):
            try:
                print(f"  Processing function {i}/{len(function_list)} at {func_ea:x}")
                ast = get_ast(func_ea)
                print(f"    ✓ Generated AST with {ast.compute_size()} nodes")
                
                # Save each AST
                output_file = f"batch_ast_{func_ea:x}.json"
                ast.to_json(Path(output_file))
                
            except Exception as e:
                print(f"    ✗ Failed: {e}")
        
        print("  Batch processing complete!")
        
    except ImportError:
        print("Error: This script must be run from within IDA Pro")
    except Exception as e:
        print(f"Error in batch processing: {e}")

def main():
    """Main example function"""
    print("🔧 IDA Pro AST Builder Examples")
    print("=" * 50)
    
    # Example 1: Single function
    print("\n1️⃣ Single Function Example:")
    ast = example_single_function()
    
    if ast:
        # Example 2: AST traversal
        print("\n2️⃣ AST Traversal Example:")
        example_ast_traversal(ast)
    
    # Example 3: Batch processing
    print("\n3️⃣ Batch Processing Example:")
    example_batch_processing()
    
    print("\n✅ Examples completed!")
    print("\nTo use this in your own scripts:")
    print("1. Import the library: from idalib import get_ast")
    print("2. Generate AST: ast = get_ast(function_address)")
    print("3. Analyze: traverse the ast.inner nodes")
    print("4. Save: ast.to_json('output.json')")

if __name__ == "__main__":
    main()
