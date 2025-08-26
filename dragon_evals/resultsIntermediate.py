import pandas as pd
import re
from pathlib import Path

def normalize_benchmark_name(benchmark_name):
    """Normalize benchmark names by removing _bench_ and _ben_ markers"""
    if benchmark_name is None:
        return None
    
    # Remove _ben_ and _bench_ markers to get the base name
    normalized = benchmark_name.replace('_ben_', '_').replace('_bench_', '_')
    
    # Clean up any double underscores that might result
    while '__' in normalized:
        normalized = normalized.replace('__', '_')
    
    return normalized

def extract_benchmark_components(benchmark_name):
    """Extract base name, architecture, and optimization level from benchmark name"""
    if benchmark_name is None:
        return None, None, None
    
    # Pattern: base_arch_opt_hops (e.g., coreutils_x64_O0_5hops)
    parts = benchmark_name.split('_')
    
    if len(parts) >= 4:
        base_name = parts[0]  # e.g., 'coreutils'
        architecture = parts[1]  # e.g., 'x64', 'x86', 'arm64'
        optimization = parts[2]  # e.g., 'O0', 'O1', 'O2', 'O3'
        
        return base_name, architecture, optimization
    else:
        # Handle cases like 'tydamin_sample_5hops'
        return benchmark_name, 'unknown', 'unknown'

def determine_experiment_type(run_name, model_name):
    """Determine the experiment type based on run name and model name"""
    run_name_lower = run_name.lower()
    model_name_lower = model_name.lower() if model_name else ""
    
    # Determine model IL type from model name
    if 'ida' in model_name_lower:
        model_il = 'ida'
    elif 'binja' in model_name_lower:
        model_il = 'binja'
    elif 'replicate' in model_name_lower or 'tydamin' in model_name_lower:
        model_il = 'ghidra'  # Original dragon models are ghidra
    else:
        model_il = 'ghidra'  # Default to ghidra instead of unknown
    
    # Determine dataset IL type from run name
    if 'replication' in run_name_lower:
        dataset_il = 'ghidra'  # Replication uses ghidra datasets
    elif 'ida' in run_name_lower and 'ondrag' not in run_name_lower:
        dataset_il = 'ida'  # ida_eval_results = ida datasets
    elif 'binja' in run_name_lower and 'ondrag' not in run_name_lower:
        dataset_il = 'binja'  # binja_eval_results = binja datasets
    elif 'ondragoriginal' in run_name_lower or 'dragon' in run_name_lower:
        dataset_il = 'ghidra'  # "OnDragonOriginalDatasets" = ghidra datasets
    else:
        dataset_il = 'ghidra'  # Default to ghidra instead of unknown
    
    # Create experiment type description
    if model_il == dataset_il:
        return f'same_IL_{model_il}'  # Same IL for model and dataset
    else:
        return f'{model_il}_model_on_{dataset_il}_data'  # Cross-IL evaluation

def classify_benchmark_completeness(df):
    """Classify benchmarks as complete or incomplete based on available experiment types"""
    # Get all experiment types
    all_experiment_types = set(df['experiment_type'].unique())
    
    # For each benchmark, count how many experiment types it has
    benchmark_completeness = df.groupby('benchmark_ordered')['experiment_type'].nunique().reset_index()
    benchmark_completeness.columns = ['benchmark_ordered', 'num_experiment_types']
    
    # Determine the maximum number of experiment types (complete benchmarks)
    max_experiment_types = benchmark_completeness['num_experiment_types'].max()
    
    # Classify benchmarks
    complete_benchmarks = benchmark_completeness[
        benchmark_completeness['num_experiment_types'] == max_experiment_types
    ]['benchmark_ordered'].tolist()
    
    incomplete_benchmarks = benchmark_completeness[
        benchmark_completeness['num_experiment_types'] < max_experiment_types
    ]['benchmark_ordered'].tolist()
    
    return complete_benchmarks, incomplete_benchmarks

def create_organized_benchmark_order(df):
    """Create properly ordered benchmark names, separating complete and incomplete evaluations"""
    # Get complete and incomplete benchmarks
    complete_benchmarks, incomplete_benchmarks = classify_benchmark_completeness(df)
    
    # Get unique combinations
    unique_combos = df[['base_name', 'architecture', 'benchmark_ordered']].drop_duplicates()
    
    # Define order
    opt_order = ['O0', 'O1', 'O2', 'O3']
    arch_order = ['arm64', 'armv7', 'x86', 'x64']
    
    def order_benchmarks_by_category(benchmark_list):
        """Order benchmarks within a category (complete or incomplete)"""
        category_df = unique_combos[unique_combos['benchmark_ordered'].isin(benchmark_list)]
        ordered = []
        
        for base_name in sorted(category_df['base_name'].unique()):
            if base_name != 'unknown':
                base_combos = category_df[category_df['base_name'] == base_name]
                
                # Sort architectures according to our preferred order
                architectures = base_combos['architecture'].unique()
                sorted_archs = [arch for arch in arch_order if arch in architectures] + \
                              [arch for arch in architectures if arch not in arch_order and arch != 'unknown']
                
                for arch in sorted_archs:
                    for opt in opt_order:
                        benchmark_name = f"{base_name}_{arch}_{opt}"
                        if benchmark_name in benchmark_list:
                            ordered.append(benchmark_name)
        return ordered
    
    # Order complete benchmarks first, then incomplete
    ordered_complete = order_benchmarks_by_category(complete_benchmarks)
    ordered_incomplete = order_benchmarks_by_category(incomplete_benchmarks)
    
    # Combine with complete benchmarks first
    all_ordered = ordered_complete + ordered_incomplete
    
    return all_ordered, len(ordered_complete)

def parse_eval_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    results = []
    run_name = Path(filepath).stem
    
    # Current benchmark state
    current_model = None
    current_benchmark = None
    current_dataset_size = None
    current_accuracy = None
    current_runtime = None
    
    for line_num, line in enumerate(lines):
        line = line.strip()
        
        # Skip empty lines and irrelevant content
        if not line or line.startswith('─') or line.startswith('Arguments') or line.startswith('100%|') or 'Warning:' in line:
            continue
            
        # Extract model name - this persists across multiple benchmarks
        model_match = re.search(r'Running dragon model (\S+)\.pt', line)
        if model_match:
            current_model = model_match.group(1)
            continue
            
        # Extract model name from summary line (backup method)
        summary_match = re.match(r'DRAGON (\S+) - Summary', line)
        if summary_match:
            current_model = summary_match.group(1)
            continue
            
        # Extract dataset size
        dataset_match = re.search(r'dataset size = ([\d,]+)', line)
        if dataset_match:
            current_dataset_size = int(dataset_match.group(1).replace(',', ''))
            continue
            
        # Extract accuracy
        accuracy_match = re.search(r'Accuracy: ([\d\.]+)%', line)
        if accuracy_match:
            current_accuracy = float(accuracy_match.group(1))
            continue
            
        # Extract benchmark name and runtime (this triggers row completion)
        runtime_match = re.match(r'(.+?) Runtime: ([\d:]+)', line)
        if runtime_match:
            raw_benchmark = runtime_match.group(1).strip()
            current_benchmark = normalize_benchmark_name(raw_benchmark)
            runtime_str = runtime_match.group(2)
            
            # Convert runtime to seconds
            parts = [int(x) for x in runtime_str.split(':')]
            if len(parts) == 3:
                current_runtime = parts[0] * 3600 + parts[1] * 60 + parts[2]
            elif len(parts) == 2:
                current_runtime = parts[0] * 60 + parts[1]
            else:
                current_runtime = parts[0]
            
            # Determine experiment type
            experiment_type = determine_experiment_type(run_name, current_model)
            
            # Extract benchmark components
            base_name, architecture, optimization = extract_benchmark_components(current_benchmark)
            
            # We have a complete row - save it
            if current_model and current_benchmark and current_runtime is not None:
                results.append({
                    'run_name': run_name,
                    'model_name': current_model,
                    'benchmark_name': current_benchmark,
                    'benchmark_name_original': raw_benchmark,
                    'base_name': base_name,
                    'architecture': architecture,
                    'optimization': optimization,
                    'dataset_size': current_dataset_size,
                    'accuracy': current_accuracy,
                    'runtime': current_runtime,
                    'experiment_type': experiment_type
                })
                
                # Reset only benchmark-specific fields (keep model_name for next benchmark)
                current_benchmark = None
                current_dataset_size = None
                current_accuracy = None
                current_runtime = None
                
            continue
    
    return results

# Scan current directory for .txt files
txt_files = list(Path('.').glob('*.txt'))
print(f"Found {len(txt_files)} .txt files: {[f.name for f in txt_files]}")

all_results = []
for file in txt_files:
    print(f"Processing {file.name}...")
    file_results = parse_eval_file(file)
    print(f"  Found {len(file_results)} benchmark results")
    all_results.extend(file_results)

# Create DataFrame
df = pd.DataFrame(all_results)
print(f"\nTotal results: {len(df)} rows")
print("\nDataFrame:")
print(df)

# Show experiment type distribution
if not df.empty:
    print("\nExperiment type distribution:")
    exp_type_counts = df['experiment_type'].value_counts()
    for exp_type, count in exp_type_counts.items():
        print(f"  {exp_type}: {count} results")
    
    print("\nBenchmark name normalization:")
    unique_benchmarks = df[['benchmark_name', 'benchmark_name_original']].drop_duplicates()
    for _, row in unique_benchmarks.iterrows():
        if row['benchmark_name'] != row['benchmark_name_original']:
            print(f"  {row['benchmark_name_original']} -> {row['benchmark_name']}")

if not df.empty:
    import seaborn as sns
    import matplotlib.pyplot as plt

    if 'accuracy' in df.columns and df['accuracy'].notna().any():
        # Create organized benchmark order
        df['benchmark_ordered'] = df['base_name'] + '_' + df['architecture'] + '_' + df['optimization']
        ordered_benchmarks, num_complete = create_organized_benchmark_order(df)
        
        # Convert to categorical with proper order
        df['benchmark_ordered_cat'] = pd.Categorical(df['benchmark_ordered'], 
                                                    categories=ordered_benchmarks, 
                                                    ordered=True)
        
        # Plot 1: Overall comparison (old histograms/boxplots)
        plt.figure(figsize=(25, 10))
        
        # Subplot 1: Accuracy by experiment type
        plt.subplot(2, 1, 1)
        sns.boxplot(data=df, x='experiment_type', y='accuracy')
        plt.xticks(rotation=45, ha='right')
        plt.title('Accuracy Distribution by Experiment Type')
        
        # Subplot 2: Accuracy by benchmark and experiment type - ORGANIZED
        plt.subplot(2, 1, 2)
        ax = sns.barplot(data=df, x='benchmark_ordered_cat', y='accuracy', hue='experiment_type')
        plt.xticks(rotation=45, ha='right')
        plt.title('Model Performance by Benchmark and Experiment Type - Organized by Architecture and Optimization')
        plt.xlabel('Benchmark (Base_Architecture_Optimization)')
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        
        plt.tight_layout()
        plt.show()
        
        # NEW: Cool-warm heatmap visualization for Ghidra data
        ghidra_data = df[df['experiment_type'].str.contains('ghidra', case=False)].copy()  # Fix: Use .copy()
        
        if not ghidra_data.empty:
            # Get unique base_name + architecture combinations
            ghidra_data['benchmark_arch'] = ghidra_data['base_name'] + '_' + ghidra_data['architecture']
            unique_benchmark_archs = ghidra_data['benchmark_arch'].unique()
            
            # Filter to only benchmark_archs that have data and exclude tydamin
            valid_benchmark_archs = []
            for bench_arch in unique_benchmark_archs:
                if (bench_arch != 'unknown_unknown' and 
                    not bench_arch.startswith('tydamin')):  # Exclude tydamin
                    bench_subset = ghidra_data[ghidra_data['benchmark_arch'] == bench_arch]
                    # Check for valid accuracy data and optimization levels
                    if (len(bench_subset) > 0 and 
                        bench_subset['accuracy'].notna().sum() > 0 and
                        bench_subset['optimization'].nunique() > 1):  # Must have multiple optimization levels
                        valid_benchmark_archs.append(bench_arch)
            
            # Sort to ensure consistent ordering and prioritize armhf
            arch_priority = ['armhf', 'arm64', 'armv7', 'x86', 'x64']
            def arch_sort_key(bench_arch):
                base, arch = bench_arch.split('_', 1)
                try:
                    return (arch_priority.index(arch), base)
                except ValueError:
                    return (len(arch_priority), base)
            
            valid_benchmark_archs.sort(key=arch_sort_key)
            
            # Create subplots - 2x2 grid for up to 4 benchmark_arch combinations
            num_plots = min(len(valid_benchmark_archs), 4)
            if num_plots > 0:
                fig, axes = plt.subplots(2, 2, figsize=(16, 12))
                if num_plots == 1:
                    axes = [axes.flatten()[0]]
                else:
                    axes = axes.flatten()
                
                for i, benchmark_arch in enumerate(valid_benchmark_archs[:4]):
                    # Filter data for this benchmark_arch
                    bench_data = ghidra_data[ghidra_data['benchmark_arch'] == benchmark_arch]
                    
                    if not bench_data.empty and bench_data['accuracy'].notna().sum() > 0:
                        # Create pivot table for heatmap
                        # Rows: experiment_type (decompiler performance)
                        # Cols: optimization level
                        pivot_data = bench_data.pivot_table(
                            values='accuracy', 
                            index='experiment_type', 
                            columns='optimization', 
                            aggfunc='mean'
                        )
                        
                        # Check if pivot_data has any values
                        if not pivot_data.empty and not pivot_data.isnull().all().all():
                            # Ensure optimization levels are in order
                            opt_cols = ['O0', 'O1', 'O2', 'O3']
                            available_opts = [opt for opt in opt_cols if opt in pivot_data.columns]
                            if available_opts:
                                pivot_data = pivot_data[available_opts]
                            
                            # Calculate center value safely
                            center_value = None
                            if not pivot_data.empty and not pivot_data.isnull().all().all():
                                valid_values = pivot_data.values[~pd.isnull(pivot_data.values)]
                                if len(valid_values) > 0:
                                    center_value = valid_values.mean()
                            
                            # Create heatmap with cool-warm colormap
                            sns.heatmap(
                                pivot_data, 
                                annot=True, 
                                fmt='.2f', 
                                cmap='coolwarm',
                                center=center_value,  # Use safe center value
                                ax=axes[i],
                                cbar_kws={'label': 'Accuracy (%)'}
                            )
                            
                            axes[i].set_title(f'{benchmark_arch} - Accuracy Heatmap')
                            axes[i].set_xlabel('Optimization Level')
                            axes[i].set_ylabel('Experiment Type')
                            
                            # Rotate y-axis labels for better readability
                            axes[i].tick_params(axis='y', rotation=0)
                            axes[i].tick_params(axis='x', rotation=0)
                        else:
                            # Hide subplot if no valid data
                            axes[i].set_visible(False)
                            print(f"No valid data for {benchmark_arch} heatmap")
                    else:
                        # Hide subplot if no data
                        axes[i].set_visible(False)
                        print(f"No data for {benchmark_arch} heatmap")
                
                # Hide unused subplots
                for j in range(num_plots, 4):
                    if j < len(axes):
                        axes[j].set_visible(False)
                
                plt.suptitle('Ghidra Data Performance Heatmaps by Benchmark and Architecture', fontsize=16)
                plt.tight_layout()
                plt.show()
            else:
                print("No valid benchmark_arch combinations found for Ghidra heatmap")
        else:
            print("No Ghidra data found for heatmap")
        
        # Individual plots for each decompiler, organized properly
        decompilers = ['ida', 'binja', 'ghidra']
        
        for decompiler in decompilers:
            # Filter data for this decompiler (either as model or dataset)
            decompiler_data = df[
                df['experiment_type'].str.contains(decompiler, case=False)
            ]
            
            if not decompiler_data.empty:
                plt.figure(figsize=(25, 8))
                
                # Organized bar plot with proper ordering
                ax = sns.barplot(data=decompiler_data, x='benchmark_ordered_cat', y='accuracy', 
                               hue='experiment_type', ci=None)
                plt.xticks(rotation=45, ha='right')
                plt.title(f'{decompiler.upper()} Model Performance - Organized by Architecture and Optimization')
                plt.xlabel('Benchmark (Base_Architecture_Optimization)')
                plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
                
                plt.tight_layout()
                plt.show()
            else:
                print(f"No data found for {decompiler}")
        
        # Runtime comparison (old histogram/boxplot)
        plt.figure(figsize=(15, 8))
        sns.boxplot(data=df, x='experiment_type', y='runtime')
        plt.xticks(rotation=45, ha='right')
        plt.title('Runtime Distribution by Experiment Type')
        plt.ylabel('Runtime (seconds)')
        plt.tight_layout()
        plt.show()
        
    else:
        print("No accuracy data available for plotting")
else:
    print("No data found - check file formats and regex patterns")