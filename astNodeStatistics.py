import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np
from collections import defaultdict, Counter
import math
import statistics

# Add the astlib/src directory to Python path
current_dir = Path(__file__).parent
astlib_path = current_dir / 'astlib' / 'src'
sys.path.insert(0, str(astlib_path))

# Import the AST module
from astlib.ast import read_json_str, ASTNode, TranslationUnitDecl
from varlib import StructDatabase

class ASTStatistics:
    def __init__(self):
        self.functions = []
        self.total_functions = 0
        self.total_nodes = 0
        self.total_declref_nodes = 0
        
        # Per-function statistics
        self.function_node_counts = []
        self.function_declref_counts = []
        self.function_depths = []
        self.function_entropies = []
        self.function_names = []
    
    def count_nodes(self, node: ASTNode) -> int:
        """Recursively count all nodes in the AST"""
        count = 1  # Count current node
        for child in node.inner:
            count += self.count_nodes(child)
        return count
    
    def count_declref_nodes(self, node: ASTNode) -> int:
        """Recursively count DeclRefExpr nodes in the AST"""
        count = 0
        if node.kind == 'DeclRefExpr':
            count = 1
        
        for child in node.inner:
            count += self.count_declref_nodes(child)
        return count
    
    def calculate_depth(self, node: ASTNode) -> int:
        """Calculate the maximum depth of the AST"""
        if not node.inner:
            return 1
        
        max_child_depth = max(self.calculate_depth(child) for child in node.inner)
        return 1 + max_child_depth
    
    def collect_node_types(self, node: ASTNode, node_types: Counter):
        """Collect all node types for entropy calculation"""
        node_types[node.kind] += 1
        for child in node.inner:
            self.collect_node_types(child, node_types)
    
    def calculate_entropy(self, node: ASTNode) -> float:
        """Calculate Shannon entropy of node types in the AST"""
        node_types = Counter()
        self.collect_node_types(node, node_types)
        
        total_nodes = sum(node_types.values())
        if total_nodes <= 1:
            return 0.0
        
        entropy = 0.0
        for count in node_types.values():
            probability = count / total_nodes
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_function(self, ast_root: ASTNode, filename: str):
        """Analyze a single function AST"""
        # Find the function declaration
        func_decl = None
        func_name = filename
        
        if hasattr(ast_root, 'inner') and ast_root.inner:
            for child in ast_root.inner:
                if hasattr(child, 'kind') and child.kind == 'FunctionDecl':
                    func_decl = child
                    if hasattr(child, 'name') and child.name:
                        func_name = child.name
                    break
        
        # Use the function declaration if found, otherwise use the whole AST
        analysis_root = func_decl if func_decl else ast_root
        
        # Calculate statistics
        node_count = self.count_nodes(analysis_root)
        declref_count = self.count_declref_nodes(analysis_root)
        depth = self.calculate_depth(analysis_root)
        entropy = self.calculate_entropy(analysis_root)
        
        # Store statistics
        self.function_names.append(func_name)
        self.function_node_counts.append(node_count)
        self.function_declref_counts.append(declref_count)
        self.function_depths.append(depth)
        self.function_entropies.append(entropy)
        
        # Update totals
        self.total_functions += 1
        self.total_nodes += node_count
        self.total_declref_nodes += declref_count
        
        return {
            'function_name': func_name,
            'nodes': node_count,
            'declref_nodes': declref_count,
            'depth': depth,
            'entropy': entropy
        }
    
    def calculate_summary_statistics(self) -> Dict:
        """Calculate summary statistics across all functions"""
        if not self.function_node_counts:
            return {}
        
        # Convert to numpy arrays for easier calculation
        node_counts = np.array(self.function_node_counts)
        declref_counts = np.array(self.function_declref_counts)
        depths = np.array(self.function_depths)
        entropies = np.array(self.function_entropies)
        
        return {
            'total_functions': self.total_functions,
            'total_nodes': self.total_nodes,
            'total_declref_nodes': self.total_declref_nodes,
            
            # Node count statistics
            'avg_nodes_per_function': np.mean(node_counts),
            'median_nodes_per_function': np.median(node_counts),
            'std_nodes_per_function': np.std(node_counts),
            
            # DeclRefExpr statistics
            'avg_declref_per_function': np.mean(declref_counts),
            'median_declref_per_function': np.median(declref_counts),
            'std_declref_per_function': np.std(declref_counts),
            
            # Depth statistics
            'avg_depth': np.mean(depths),
            'median_depth': np.median(depths),
            'std_depth': np.std(depths),
            
            # Entropy statistics
            'avg_entropy': np.mean(entropies),
            'median_entropy': np.median(entropies),
            'std_entropy': np.std(entropies),
            
            # Additional statistics
            'min_nodes': np.min(node_counts),
            'max_nodes': np.max(node_counts),
            'min_declref': np.min(declref_counts),
            'max_declref': np.max(declref_counts),
            'min_depth': np.min(depths),
            'max_depth': np.max(depths),
            'min_entropy': np.min(entropies),
            'max_entropy': np.max(entropies),
        }

def analyze_directory(json_dir: Path, output_file: str = None) -> Dict:
    """Analyze all JSON files in a directory"""
    if not json_dir.exists() or not json_dir.is_dir():
        print(f"Error: Directory {json_dir} does not exist or is not a directory")
        return {}
    
    stats = ASTStatistics()
    sdb = StructDatabase()
    
    # Find all JSON files
    json_files = list(json_dir.glob("*.json"))
    if not json_files:
        print(f"No JSON files found in {json_dir}")
        return {}
    
    print(f"Found {len(json_files)} JSON files to analyze...")
    
    # Analyze each JSON file
    successful_analyses = 0
    failed_analyses = []
    
    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                json_content = f.read()
            
            # Parse the AST
            ast_root = read_json_str(json_content, sdb)
            
            # Analyze this function
            func_stats = stats.analyze_function(ast_root, json_file.stem)
            successful_analyses += 1
            
            if successful_analyses % 100 == 0:
                print(f"Processed {successful_analyses} files...")
                
        except Exception as e:
            failed_analyses.append((json_file.name, str(e)))
            print(f"Error processing {json_file.name}: {e}")
    
    print(f"\nSuccessfully analyzed {successful_analyses} functions")
    if failed_analyses:
        print(f"Failed to analyze {len(failed_analyses)} files")
    
    # Calculate summary statistics
    summary = stats.calculate_summary_statistics()
    
    # Print results
    print_results(summary, failed_analyses)
    
    # Save detailed results if requested
    if output_file:
        save_detailed_results(stats, summary, failed_analyses, output_file)
    
    return summary

def print_results(summary: Dict, failed_analyses: List[Tuple[str, str]]):
    """Print formatted results to console"""
    print("\n" + "="*60)
    print("AST STATISTICS SUMMARY")
    print("="*60)
    
    print(f"\nOverall Counts:")
    print(f"  Total Functions: {summary['total_functions']:,}")
    print(f"  Total Nodes: {summary['total_nodes']:,}")
    print(f"  Total DeclRefExpr Nodes: {summary['total_declref_nodes']:,}")
    
    print(f"\nNodes per Function:")
    print(f"  Mean: {summary['avg_nodes_per_function']:.2f}")
    print(f"  Median: {summary['median_nodes_per_function']:.2f}")
    print(f"  Std Dev: {summary['std_nodes_per_function']:.2f}")
    print(f"  Range: {summary['min_nodes']} - {summary['max_nodes']}")
    
    print(f"\nDeclRefExpr per Function:")
    print(f"  Mean: {summary['avg_declref_per_function']:.2f}")
    print(f"  Median: {summary['median_declref_per_function']:.2f}")
    print(f"  Std Dev: {summary['std_declref_per_function']:.2f}")
    print(f"  Range: {summary['min_declref']} - {summary['max_declref']}")
    
    print(f"\nTree Depth:")
    print(f"  Mean: {summary['avg_depth']:.2f}")
    print(f"  Median: {summary['median_depth']:.2f}")
    print(f"  Std Dev: {summary['std_depth']:.2f}")
    print(f"  Range: {summary['min_depth']} - {summary['max_depth']}")
    
    print(f"\nEntropy:")
    print(f"  Mean: {summary['avg_entropy']:.4f}")
    print(f"  Median: {summary['median_entropy']:.4f}")
    print(f"  Std Dev: {summary['std_entropy']:.4f}")
    print(f"  Range: {summary['min_entropy']:.4f} - {summary['max_entropy']:.4f}")
    
    if failed_analyses:
        print(f"\nFailed Analyses ({len(failed_analyses)}):")
        for filename, error in failed_analyses[:10]:  # Show first 10 errors
            print(f"  {filename}: {error}")
        if len(failed_analyses) > 10:
            print(f"  ... and {len(failed_analyses) - 10} more")

def save_detailed_results(stats: ASTStatistics, summary: Dict, failed_analyses: List, output_file: str):
    """Save detailed results to files"""
    output_path = Path(output_file)
    
    # Save summary statistics
    summary_file = output_path.with_suffix('.summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to: {summary_file}")
    
    # Save per-function details
    details_file = output_path.with_suffix('.details.json')
    function_details = []
    for i in range(len(stats.function_names)):
        function_details.append({
            'function_name': stats.function_names[i],
            'nodes': stats.function_node_counts[i],
            'declref_nodes': stats.function_declref_counts[i],
            'depth': stats.function_depths[i],
            'entropy': stats.function_entropies[i]
        })
    
    with open(details_file, 'w') as f:
        json.dump(function_details, f, indent=2)
    print(f"Function details saved to: {details_file}")
    
    # Save CSV for analysis
    csv_file = output_path.with_suffix('.csv')
    with open(csv_file, 'w') as f:
        f.write("function_name,nodes,declref_nodes,depth,entropy\n")
        for detail in function_details:
            f.write(f"{detail['function_name']},{detail['nodes']},{detail['declref_nodes']},{detail['depth']},{detail['entropy']:.6f}\n")
    print(f"CSV data saved to: {csv_file}")
    
    # Save failed analyses
    if failed_analyses:
        error_file = output_path.with_suffix('.errors.txt')
        with open(error_file, 'w') as f:
            f.write("Failed Analyses:\n")
            f.write("================\n\n")
            for filename, error in failed_analyses:
                f.write(f"{filename}: {error}\n")
        print(f"Error log saved to: {error_file}")

def main():
    """Main function to handle command line usage"""
    if len(sys.argv) < 2:
        print("Usage: python astNodeStatistics.py <json_directory> [output_prefix]")
        print("Example: python astNodeStatistics.py /path/to/json/files results")
        return
    
    json_dir = Path(sys.argv[1])
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Analyze the directory
    summary = analyze_directory(json_dir, output_file)
    
    if not summary:
        print("No analysis results generated.")
        return

if __name__ == "__main__":
    main()