import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch
import numpy as np
from dataclasses import dataclass

# Add the astlib/src directory to Python path
current_dir = Path(__file__).parent
astlib_path = current_dir / 'astlib' / 'src'
sys.path.insert(0, str(astlib_path))

# Import the AST module
from astlib.ast import read_json_str, ASTNode, TranslationUnitDecl
from varlib import StructDatabase

@dataclass
class NodePosition:
    x: float
    y: float
    width: float
    height: float

class ASTVisualizer:
    def __init__(self, figsize=(20, 12)):
        self.fig, self.ax = plt.subplots(figsize=figsize)
        self.node_positions: Dict[ASTNode, NodePosition] = {}
        self.colors = {
            'TranslationUnitDecl': '#E8F4FD',
            'FunctionDecl': '#B3D9FF',
            'CompoundStmt': '#FFE6CC',
            'DeclStmt': '#D4EDDA',
            'VarDecl': '#D1ECF1',
            'ParmVarDecl': '#D1ECF1',
            'ReturnStmt': '#F8D7DA',
            'BinaryOperator': '#FFF3CD',
            'UnaryOperator': '#E2E3E5',
            'DeclRefExpr': '#F0F8FF',
            'IntegerLiteral': '#E7F3FF',
            'FloatingLiteral': '#E7F3FF',
            'StringLiteral': '#F5F5DC',
            'CharacterLiteral': '#F5F5DC',
            'CallExpr': '#FFEAA7',
            'ArraySubscriptExpr': '#DDA0DD',
            'MemberExpr': '#98FB98',
            'IfStmt': '#FFB6C1',
            'WhileStmt': '#F0E68C',
            'ForStmt': '#F0E68C',
            'DoStmt': '#F0E68C',
            'SwitchStmt': '#DEB887',
            'CaseStmt': '#F5DEB3',
            'DefaultStmt': '#F5DEB3',
            'BreakStmt': '#FFCCCB',
            'GotoStmt': '#FFCCCB',
            'LabelStmt': '#ADD8E6',
            'ParenExpr': '#E6E6FA',
            'CStyleCastExpr': '#FFDAB9',
            'ConstantExpr': '#F0FFFF',
            'NullNode': '#D3D3D3',
        }
        self.default_color = '#F0F0F0'
        
    def get_node_color(self, node: ASTNode) -> str:
        """Get color for a node based on its type"""
        return self.colors.get(node.kind, self.default_color)
    
    def get_node_label(self, node: ASTNode) -> str:
        """Generate a clean label for the node"""
        label = node.kind
        
        # Add specific information based on node type
        if hasattr(node, 'name') and node.name:
            label += f"\n{node.name}"
        
        if hasattr(node, 'opcode') and node.opcode:
            label += f"\n({node.opcode})"
            
        if hasattr(node, 'instr_addr') and node.instr_addr > 0:
            label += f"\n@{node.instr_addr:#x}"
            
        return label
    
    def calculate_tree_layout(self, root: ASTNode) -> Dict[ASTNode, NodePosition]:
        """Calculate positions for all nodes using a tree layout algorithm"""
        positions = {}
        
        def calculate_subtree_width(node: ASTNode) -> float:
            if not node.inner:
                return 1.0
            return sum(calculate_subtree_width(child) for child in node.inner)
        
        def position_nodes(node: ASTNode, x: float, y: float, width: float) -> float:
            # Position current node
            node_width = 2.0  # Reduced width since we have less text
            node_height = 1.5  # Reduced height since we have less text
            node_x = x + (width - node_width) / 2
            
            positions[node] = NodePosition(node_x, y, node_width, node_height)
            
            if node.inner:
                # Calculate positions for children
                child_y = y - 2.5  # Reduced vertical spacing
                child_start_x = x
                
                for child in node.inner:
                    child_width = max(1.0, calculate_subtree_width(child))
                    child_actual_width = position_nodes(child, child_start_x, child_y, child_width)
                    child_start_x += child_actual_width + 0.5
                
                return child_start_x - x
            else:
                return width
        
        total_width = calculate_subtree_width(root)
        position_nodes(root, 0, 0, total_width)
        
        return positions
    
    def draw_node(self, node: ASTNode, pos: NodePosition):
        """Draw a single node"""
        # Create rounded rectangle
        box = FancyBboxPatch(
            (pos.x, pos.y), pos.width, pos.height,
            boxstyle="round,pad=0.1",
            facecolor=self.get_node_color(node),
            edgecolor='black',
            linewidth=1
        )
        self.ax.add_patch(box)
        
        # Add text label
        label = self.get_node_label(node)
        self.ax.text(
            pos.x + pos.width/2, pos.y + pos.height/2,
            label,
            ha='center', va='center',
            fontsize=8,  # Slightly increased font size since we have less text
            wrap=True,
            bbox=dict(boxstyle="round,pad=0.1", facecolor='white', alpha=0.8)
        )
    
    def draw_edge(self, parent_pos: NodePosition, child_pos: NodePosition):
        """Draw an edge between parent and child nodes"""
        # Connect from bottom of parent to top of child
        parent_x = parent_pos.x + parent_pos.width / 2
        parent_y = parent_pos.y
        child_x = child_pos.x + child_pos.width / 2
        child_y = child_pos.y + child_pos.height
        
        self.ax.plot([parent_x, child_x], [parent_y, child_y], 
                    'k-', linewidth=1, alpha=0.7)
    
    def visualize(self, root: ASTNode, title: str = "AST Visualization"):
        """Main visualization method"""
        # Calculate layout
        self.node_positions = self.calculate_tree_layout(root)
        
        # Draw all nodes
        for node, pos in self.node_positions.items():
            self.draw_node(node, pos)
        
        # Draw all edges
        for node, pos in self.node_positions.items():
            for child in node.inner:
                if child in self.node_positions:
                    self.draw_edge(pos, self.node_positions[child])
        
        # Set up the plot
        if self.node_positions:
            all_x = [pos.x for pos in self.node_positions.values()]
            all_y = [pos.y for pos in self.node_positions.values()]
            all_width = [pos.width for pos in self.node_positions.values()]
            all_height = [pos.height for pos in self.node_positions.values()]
            
            min_x = min(all_x) - 1
            max_x = max(x + w for x, w in zip(all_x, all_width)) + 1
            min_y = min(y for y in all_y) - 1
            max_y = max(y + h for y, h in zip(all_y, all_height)) + 1
            
            self.ax.set_xlim(min_x, max_x)
            self.ax.set_ylim(min_y, max_y)
        
        self.ax.set_aspect('equal')
        self.ax.axis('off')
        self.ax.set_title(title, fontsize=16, fontweight='bold')
        
        plt.tight_layout()
        
    def save(self, filename: str):
        """Save the visualization to a file"""
        self.fig.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"Visualization saved to {filename}")
    
    def show(self):
        """Display the visualization"""
        plt.show()

def create_legend():
    """Create a legend showing node type colors"""
    visualizer = ASTVisualizer()
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Group node types by category
    categories = {
        'Declarations': ['TranslationUnitDecl', 'FunctionDecl', 'VarDecl', 'ParmVarDecl'],
        'Statements': ['CompoundStmt', 'DeclStmt', 'ReturnStmt', 'BreakStmt', 'GotoStmt', 'LabelStmt'],
        'Control Flow': ['IfStmt', 'WhileStmt', 'ForStmt', 'DoStmt', 'SwitchStmt', 'CaseStmt', 'DefaultStmt'],
        'Expressions': ['BinaryOperator', 'UnaryOperator', 'DeclRefExpr', 'CallExpr', 'ArraySubscriptExpr', 'MemberExpr'],
        'Literals': ['IntegerLiteral', 'FloatingLiteral', 'StringLiteral', 'CharacterLiteral'],
        'Other': ['ParenExpr', 'CStyleCastExpr', 'ConstantExpr', 'NullNode']
    }
    
    y_pos = 0.9
    for category, node_types in categories.items():
        ax.text(0.02, y_pos, category, fontsize=14, fontweight='bold')
        y_pos -= 0.05
        
        for node_type in node_types:
            if node_type in visualizer.colors:
                # Draw color box
                rect = patches.Rectangle((0.05, y_pos-0.02), 0.03, 0.03, 
                                       facecolor=visualizer.colors[node_type],
                                       edgecolor='black')
                ax.add_patch(rect)
                
                # Add label
                ax.text(0.1, y_pos, node_type, fontsize=10)
                y_pos -= 0.04
        
        y_pos -= 0.02
    
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    ax.set_title('AST Node Type Legend', fontsize=16, fontweight='bold')
    
    return fig

def main():
    """Main function to handle command line usage"""
    if len(sys.argv) < 2:
        print("Usage: python astFuncVisual.py <json_file> [output_file]")
        print("Example: python astFuncVisual.py ast_tree.json ast_visualization.png")
        return
    
    json_file = Path(sys.argv[1])
    if not json_file.exists():
        print(f"Error: File {json_file} not found")
        return
    
    try:
        # Read and parse the JSON AST
        with open(json_file, 'r') as f:
            json_content = f.read()
        
        # Create struct database (you might need to adjust this based on your setup)
        sdb = StructDatabase()
        
        # Parse the AST
        ast_root = read_json_str(json_content, sdb)
        
        # Create visualization
        visualizer = ASTVisualizer(figsize=(24, 16))
        title = f"AST Visualization - {json_file.name}"
        
        if hasattr(ast_root, 'inner') and ast_root.inner:
            # If it's a TranslationUnitDecl, visualize the function
            func_decl = None
            for child in ast_root.inner:
                if hasattr(child, 'kind') and child.kind == 'FunctionDecl':
                    func_decl = child
                    break
            
            if func_decl and hasattr(func_decl, 'name'):
                title += f" - Function: {func_decl.name}"
        
        visualizer.visualize(ast_root, title)
        
        # Save or show
        if len(sys.argv) > 2:
            output_file = sys.argv[2]
            visualizer.save(output_file)
            
            # Also create and save legend
            legend_fig = create_legend()
            legend_file = output_file.replace('.png', '_legend.png').replace('.pdf', '_legend.pdf')
            legend_fig.savefig(legend_file, dpi=300, bbox_inches='tight')
            print(f"Legend saved to {legend_file}")
        else:
            visualizer.show()
            
            # Show legend in separate window
            create_legend()
            plt.show()
            
    except Exception as e:
        print(f"Error processing {json_file}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()