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
        # Handle special cases like 'tydamin_sample_5hops' - keep the full name as base_name
        # Don't add unknown tags for non-standard benchmarks
        return benchmark_name, '', ''

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
    
    # Create experiment type description with new naming convention
    if model_il == dataset_il:
        if model_il == 'ida':
            return 'Only IDA Pro'
        elif model_il == 'binja':
            return 'Only Binary Ninja'
        elif model_il == 'ghidra':
            return 'Only Ghidra'
    else:
        if model_il == 'ida' and dataset_il == 'ghidra':
            return 'IDA Pro on Ghidra'
        elif model_il == 'binja' and dataset_il == 'ghidra':
            return 'Binary Ninja on Ghidra'
        elif model_il == 'ghidra' and dataset_il == 'ida':
            return 'Ghidra on IDA Pro'
        elif model_il == 'ghidra' and dataset_il == 'binja':
            return 'Ghidra on Binary Ninja'
        else:
            # Fallback for any unexpected combinations
            return f'{model_il.title()} on {dataset_il.title()}'

def classify_benchmark_completeness(df):
    """Classify benchmarks as complete or incomplete based on available experiment types"""
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
    
    # Get unique combinations - use only benchmark_ordered since that's what we have
    unique_combos = df[['benchmark_ordered']].drop_duplicates()
    
    # Define order for parsing benchmark names
    opt_order = ['O0', 'O1', 'O2', 'O3']
    arch_order = ['arm64', 'armv7', 'x86', 'x64', 'armhf']
    
    def order_benchmarks_by_category(benchmark_list):
        """Order benchmarks within a category (complete or incomplete)"""
        ordered = []
        standard_benchmarks = []
        non_standard_benchmarks = []
        
        # Separate standard and non-standard benchmarks
        for benchmark in benchmark_list:
            parts = benchmark.split('_')
            if len(parts) >= 3 and parts[-1] in opt_order:
                # This looks like a standard benchmark with optimization level
                standard_benchmarks.append(benchmark)
            else:
                # This is non-standard (like tydamin)
                non_standard_benchmarks.append(benchmark)
        
        # Sort standard benchmarks by base_name, then architecture, then optimization
        def standard_sort_key(benchmark):
            parts = benchmark.split('_')
            if len(parts) >= 3:
                base_name = parts[0]
                arch = parts[1]
                opt = parts[2]
                
                arch_priority = arch_order.index(arch) if arch in arch_order else len(arch_order)
                opt_priority = opt_order.index(opt) if opt in opt_order else len(opt_order)
                
                return (base_name, arch_priority, opt_priority)
            else:
                return (benchmark, 999, 999)
        
        ordered.extend(sorted(standard_benchmarks, key=standard_sort_key))
        
        # Add non-standard benchmarks at the end
        ordered.extend(sorted(non_standard_benchmarks))
        
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

# Export to CSV for LaTeX table generation
if not df.empty:
    # Save the full dataframe
    df.to_csv('evaluation_results.csv', index=False)
    print(f"\nFull dataset exported to: evaluation_results.csv")
    
    # Create a summary table for easy LaTeX conversion
    summary_df = df.groupby(['experiment_type', 'base_name', 'architecture', 'optimization']).agg({
        'accuracy': ['mean', 'std', 'count']
    }).round(2)
    
    # Flatten column names
    summary_df.columns = ['_'.join(col).strip() for col in summary_df.columns.values]
    summary_df = summary_df.reset_index()
    
    # Save summary table
    summary_df.to_csv('evaluation_results_summary.csv', index=False)
    print(f"Summary table exported to: evaluation_results_summary.csv")
    
    # Create a clean table for LaTeX (experiment type vs benchmark performance)
    if 'accuracy' in df.columns:
        latex_table = df.pivot_table(
            values='accuracy', 
            index=['base_name', 'architecture', 'optimization'], 
            columns='experiment_type', 
            aggfunc='mean'
        ).round(2)
        
        latex_table.to_csv('evaluation_results_latex_table.csv')
        print(f"LaTeX-ready pivot table exported to: evaluation_results_latex_table.csv")
    
    print("\nCSV files created for LaTeX table generation:")
    print("  - evaluation_results.csv: Full raw data")
    print("  - evaluation_results_summary.csv: Grouped summary with mean/std/count")
    print("  - evaluation_results_latex_table.csv: Pivot table format for LaTeX")

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
    
    # Set matplotlib to use non-interactive backend
    plt.ioff()

    # Define consistent color palette for experiment types
    experiment_colors = {
        'Only IDA Pro': '#1f77b4',  # Blue - IDA same IL
        'IDA Pro on Ghidra': '#87ceeb',  # Light blue - IDA model on Ghidra
        'Only Ghidra': '#2ca02c',  # Green - Ghidra same IL
        'Only Binary Ninja': '#d62728',  # Red - Binja same IL
        'Binary Ninja on Ghidra': '#ff7f7f',  # Light red - Binja model on Ghidra
        # Add fallback colors for any other experiment types
        'Ghidra on IDA Pro': '#90ee90',  # Light green - Ghidra model on IDA
        'Ghidra on Binary Ninja': '#98df8a',  # Another light green variant
    }

    # Helper function to get colors for plotting
    def get_experiment_colors(experiment_types):
        """Get colors for experiment types, using defaults for unknown types"""
        colors = []
        default_colors = ['#ff7f0e', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
        default_idx = 0
        
        for exp_type in experiment_types:
            if exp_type in experiment_colors:
                colors.append(experiment_colors[exp_type])
            else:
                colors.append(default_colors[default_idx % len(default_colors)])
                default_idx += 1
        return colors

    if 'accuracy' in df.columns and df['accuracy'].notna().any():
        # Create organized benchmark order - FIXED to handle non-standard benchmarks
        def create_benchmark_ordered(row):
            if row['architecture'] == '' and row['optimization'] == '':
                # For non-standard benchmarks like tydamin, use the original benchmark name
                return row['base_name']
            else:
                # For standard benchmarks, use the structured format
                return f"{row['base_name']}_{row['architecture']}_{row['optimization']}"
        
        df['benchmark_ordered'] = df.apply(create_benchmark_ordered, axis=1)
        
        # Filter out any remaining problematic entries and ensure we have valid data
        df = df[~df['benchmark_ordered'].isin(['unknown_unknown_unknown', '_unknown_unknown', ''])].copy()
        df = df[df['accuracy'].notna()].copy()  # Remove rows with NaN accuracy
        
        if df.empty:
            print("No valid data found after filtering")
        else:
            ordered_benchmarks, num_complete = create_organized_benchmark_order(df)
            
            # Convert to categorical with proper order
            df['benchmark_ordered_cat'] = pd.Categorical(df['benchmark_ordered'], 
                                                        categories=ordered_benchmarks, 
                                                        ordered=True)
            
            # Plot 1a: Accuracy distribution with custom order and consistent colors
            plt.figure(figsize=(15, 8))
            
            # Define the specific order requested: Only Binary Ninja, Binary Ninja on Ghidra, Only Ghidra, IDA Pro on Ghidra, Only IDA Pro
            desired_order = ['Only Binary Ninja', 'Binary Ninja on Ghidra', 'Only Ghidra', 'IDA Pro on Ghidra', 'Only IDA Pro']

            # Filter data to only include experiments that exist and are in our desired order
            available_experiments = df['experiment_type'].unique()
            ordered_experiments = [exp for exp in desired_order if exp in available_experiments]
            
            # Add any additional experiments not in our desired order at the end
            remaining_experiments = [exp for exp in available_experiments if exp not in desired_order]
            final_order = ordered_experiments + remaining_experiments
            
            if len(final_order) > 0 and df['accuracy'].notna().sum() > 0:
                # Filter and reorder data, removing experiment types with no data to avoid gaps
                df_ordered = df[df['experiment_type'].isin(final_order)].copy()
                experiment_types_with_data = df_ordered['experiment_type'].unique()
                compressed_order = [exp for exp in final_order if exp in experiment_types_with_data]
                
                df_ordered['experiment_type'] = pd.Categorical(df_ordered['experiment_type'], 
                                                             categories=compressed_order, 
                                                             ordered=True)
                
                # Get colors for the compressed order
                colors = get_experiment_colors(compressed_order)
                
                sns.boxplot(data=df_ordered, x='experiment_type', y='accuracy', order=compressed_order, palette=colors)
                plt.xticks(rotation=45, ha='right')
                plt.title('Accuracy Distribution by Experiment Type (Ordered)')
                plt.xlabel('Experiment Type')
                plt.ylabel('Accuracy (%)')
                plt.grid(axis='y', alpha=0.3)
                
                # Print the compressed order for verification
                print(f"Graph 1a using compressed experiment order: {compressed_order}")
            else:
                plt.text(0.5, 0.5, 'No valid data for boxplot', ha='center', va='center', transform=plt.gca().transAxes)
                plt.title('Accuracy Distribution by Experiment Type - No Data')
            
            plt.tight_layout()
            plt.savefig('01a_accuracy_distribution.png', dpi=300, bbox_inches='tight')
            plt.close()
            print("Saved: 01a_accuracy_distribution.png")
            
            # Plot 1b: Performance by benchmark and experiment type
            plt.figure(figsize=(25, 10))
            
            if (len(ordered_benchmarks) > 0 and 
                df['benchmark_ordered_cat'].notna().sum() > 0 and 
                df['accuracy'].notna().sum() > 0):
                try:
                    # Filter to only include experiment types that have data, maintaining the order
                    df_bench_ordered = df[df['experiment_type'].isin(final_order)].copy()
                    
                    # Remove experiment types that have no data to avoid gaps
                    experiment_types_with_data = df_bench_ordered['experiment_type'].unique()
                    compressed_order = [exp for exp in final_order if exp in experiment_types_with_data]
                    
                    # Apply the compressed ordering
                    df_bench_ordered['experiment_type'] = pd.Categorical(df_bench_ordered['experiment_type'], 
                                                                       categories=compressed_order, 
                                                                       ordered=True)
                    
                    # Get colors for the compressed order
                    colors = get_experiment_colors(compressed_order)
                    
                    # Create the barplot with compressed ordering (no gaps)
                    ax = sns.barplot(data=df_bench_ordered, x='benchmark_ordered_cat', y='accuracy', 
                                   hue='experiment_type', hue_order=compressed_order, palette=colors, ci=None)
                    plt.xticks(rotation=45, ha='right')
                    plt.title('Model Performance by Benchmark and Experiment Type - Organized by Architecture and Optimization')
                    plt.xlabel('Benchmark (Base_Architecture_Optimization)')
                    plt.ylabel('Accuracy (%)')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', title='Experiment Type')
                    plt.grid(axis='y', alpha=0.3)
                    
                    # Print the compressed order for verification
                    print(f"Graph 1b using compressed experiment order: {compressed_order}")
                    
                except Exception as e:
                    plt.text(0.5, 0.5, f'Error creating barplot: {str(e)}', ha='center', va='center', transform=plt.gca().transAxes)
                    plt.title('Model Performance - Error in Data')
                    print(f"Error in 1b plotting: {str(e)}")
            else:
                plt.text(0.5, 0.5, 'No valid data for barplot', ha='center', va='center', transform=plt.gca().transAxes)
                plt.title('Model Performance - No Data')
            
            plt.tight_layout()
            plt.savefig('01b_benchmark_performance.png', dpi=300, bbox_inches='tight')
            plt.close()
            print("Saved: 01b_benchmark_performance.png")
            
            # Individual plots for each decompiler, organized properly (Figure 2)
            decompilers = ['ida', 'binja', 'ghidra']
            
            for idx, decompiler in enumerate(decompilers):
                # Filter data for this decompiler (either as model or dataset) - UPDATED FOR NEW NAMES
                if decompiler == 'ida':
                    decompiler_data = df[
                        df['experiment_type'].str.contains('IDA Pro', case=False)
                    ]
                elif decompiler == 'binja':
                    decompiler_data = df[
                        df['experiment_type'].str.contains('Binary Ninja', case=False)
                    ]
                elif decompiler == 'ghidra':
                    decompiler_data = df[
                        df['experiment_type'].str.contains('Ghidra', case=False)
                    ]
                
                if not decompiler_data.empty and decompiler_data['accuracy'].notna().sum() > 0:
                    plt.figure(figsize=(25, 8))
                    
                    try:
                        # Get unique experiment types for this decompiler
                        decompiler_exp_types = decompiler_data['experiment_type'].unique()
                        colors = get_experiment_colors(decompiler_exp_types)
                        
                        # Organized bar plot with proper ordering
                        ax = sns.barplot(data=decompiler_data, x='benchmark_ordered_cat', y='accuracy', 
                                       hue='experiment_type', palette=colors, ci=None)
                        plt.xticks(rotation=45, ha='right')
                        plt.title(f'{decompiler.upper()} Model Performance - Organized by Architecture and Optimization')
                        plt.xlabel('Benchmark (Base_Architecture_Optimization)')
                        plt.ylabel('Accuracy (%)')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
                        plt.grid(axis='y', alpha=0.3)
                        
                        # Print the compressed order for verification
                        print(f"Graph 1b using compressed experiment order: {compressed_order}")
                        
                    except Exception as e:
                        plt.text(0.5, 0.5, f'Error creating barplot: {str(e)}', ha='center', va='center', transform=plt.gca().transAxes)
                        plt.title('Model Performance - Error in Data')
                        print(f"Error in individual decompiler plotting: {str(e)}")
                else:
                    print(f"No valid data found for {decompiler}")
            
            # Runtime comparison (old histogram/boxplot)
            if 'runtime' in df.columns and df['runtime'].notna().sum() > 0:
                plt.figure(figsize=(15, 8))
                
                # Get unique experiment types and their colors
                runtime_exp_types = df['experiment_type'].unique()
                colors = get_experiment_colors(runtime_exp_types)
                
                sns.boxplot(data=df, x='experiment_type', y='runtime', palette=colors)
                plt.xticks(rotation=45, ha='right')
                plt.title('Runtime Distribution by Experiment Type')
                plt.ylabel('Runtime (seconds)')
                plt.tight_layout()
                plt.savefig('06_runtime_comparison.png', dpi=300, bbox_inches='tight')
                plt.close()
                print("Saved: 06_runtime_comparison.png")
            else:
                print("No runtime data available for plotting")
            
            # Dataset size visualization - separated plots
            if 'dataset_size' in df.columns and df['dataset_size'].notna().any():
                # Create dataset type column based on experiment type - UPDATED LOGIC
                def classify_dataset_type(experiment_type):
                    if 'Only Ghidra' in experiment_type or 'on Ghidra' in experiment_type:
                        return 'Ghidra'
                    elif 'Only IDA Pro' in experiment_type:
                        return 'IDA'
                    elif 'Only Binary Ninja' in experiment_type:
                        return 'Binja'
                    elif 'on IDA Pro' in experiment_type:
                        return 'IDA'
                    elif 'on Binary Ninja' in experiment_type:
                        return 'Binja'
                    else:
                        return 'Unknown'
                
                # Create model type column to show which model generated the accuracy
                def classify_model_type(experiment_type):
                    if 'IDA Pro' in experiment_type and 'on' not in experiment_type:
                        return 'IDA Model'
                    elif 'IDA Pro' in experiment_type and 'on' in experiment_type:
                        return 'IDA Model'
                    elif 'Binary Ninja' in experiment_type and 'on' not in experiment_type:
                        return 'Binja Model'
                    elif 'Binary Ninja' in experiment_type and 'on' in experiment_type:
                        return 'Binja Model'
                    elif 'Only Ghidra' in experiment_type:
                        return 'Ghidra Model'
                    elif 'Ghidra on' in experiment_type:
                        return 'Ghidra Model'
                    else:
                        return 'Unknown Model'
                
                df['dataset_type'] = df['experiment_type'].apply(classify_dataset_type)
                df['model_type'] = df['experiment_type'].apply(classify_model_type)
                
                # Filter out unknown dataset types
                dataset_viz_df = df[df['dataset_type'] != 'Unknown']
                
                if not dataset_viz_df.empty:
                    # Plot 1: Dataset size distribution histogram
                    plt.figure(figsize=(10, 6))
                    sns.boxplot(data=dataset_viz_df, x='dataset_type', y='dataset_size')
                    plt.title('Dataset Size Distribution by Dataset Type')
                    plt.ylabel('Dataset Size (number of samples)')
                    plt.tight_layout()
                    plt.savefig('07_dataset_size_distribution.png', dpi=300, bbox_inches='tight')
                    plt.close()
                    print("Saved: 07_dataset_size_distribution.png")
                    
                    # Plot 2: Dataset size vs Accuracy scatter plot with model type symbols
                    plt.figure(figsize=(12, 8))
                    
                    # Get colors for experiment types in the data
                    exp_types_in_data = dataset_viz_df['experiment_type'].unique()
                    colors = get_experiment_colors(exp_types_in_data)
                    exp_color_map = dict(zip(exp_types_in_data, colors))
                    
                    sns.scatterplot(data=dataset_viz_df, x='dataset_size', y='accuracy', 
                                   hue='experiment_type', style='model_type', alpha=0.7, s=60,
                                   palette=exp_color_map)
                    plt.title('Dataset Size vs Accuracy by Dataset and Model Type')
                    plt.xlabel('Dataset Size (number of samples)')
                    plt.ylabel('Accuracy (%)')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
                    plt.tight_layout()
                    plt.savefig('08_dataset_size_vs_accuracy.png', dpi=300, bbox_inches='tight')
                    plt.close()
                    print("Saved: 08_dataset_size_vs_accuracy.png")
                else:
                    print("No valid dataset type data for visualization")
            else:
                print("No dataset size data available for plotting")
            
            print("\nAll plots saved to current directory!")
            
            # ADDITIONAL PUBLICATION-QUALITY VISUALIZATIONS
            
            # 1. Performance Delta Chart - Show cross-IL performance only (exclude Only_ experiments)
            cross_il_data = df[~df['experiment_type'].str.contains('Only', case=False, na=False)]
            if not cross_il_data.empty:
                # Use Only Ghidra as baseline where available, otherwise use overall mean
                if any(df['experiment_type'].str.contains('Only Ghidra', case=False, na=False)):
                    baseline_exp = df[df['experiment_type'].str.contains('Only Ghidra', case=False, na=False)]['experiment_type'].iloc[0]
                    baseline_acc = df[df['experiment_type'] == baseline_exp].groupby('benchmark_ordered')['accuracy'].mean()
                else:
                    # Use cross-IL mean as baseline
                    baseline_acc = cross_il_data.groupby('benchmark_ordered')['accuracy'].mean()
                
                cross_il_data = cross_il_data.copy()
                cross_il_data['accuracy_delta'] = cross_il_data.apply(
                    lambda row: row['accuracy'] - baseline_acc.get(row['benchmark_ordered'], cross_il_data['accuracy'].mean()), 
                    axis=1
                )
                
                plt.figure(figsize=(16, 8))
                
                # Get colors for cross-IL experiment types
                cross_il_exp_types = cross_il_data['experiment_type'].unique()
                colors = get_experiment_colors(cross_il_exp_types)
                
                sns.barplot(data=cross_il_data, x='benchmark_ordered_cat', y='accuracy_delta', 
                           hue='experiment_type', palette=colors, ci=None)
                plt.axhline(y=0, color='red', linestyle='--', linewidth=1, alpha=0.7)
                plt.title('Cross-IL Performance Relative to Baseline (Δ Accuracy)', fontsize=14)
                plt.ylabel('Accuracy Difference (%)', fontsize=12)
                plt.xlabel('Benchmark', fontsize=12)
                plt.xticks(rotation=45, ha='right')
                plt.legend(title='Cross-IL Experiments', bbox_to_anchor=(1.05, 1))
                plt.grid(axis='y', alpha=0.3)
                plt.tight_layout()
                plt.savefig('09_performance_delta_clean.png', dpi=300, bbox_inches='tight')
                plt.close()
                print("Saved: 09_performance_delta_clean.png")
            
            # 6. Statistical Distribution Comparison
            fig, axes = plt.subplots(1, 2, figsize=(16, 6))
            
            # Left: Distribution shapes
            dist_exp_types = df['experiment_type'].unique()
            colors = get_experiment_colors(dist_exp_types)
            
            sns.violinplot(data=df, x='experiment_type', y='accuracy', ax=axes[0], palette=colors)
            axes[0].set_title('Accuracy Distribution Shapes', fontsize=14)
            axes[0].set_xlabel('Experiment Type', fontsize=12)
            axes[0].set_ylabel('Accuracy (%)', fontsize=12)
            axes[0].tick_params(axis='x', rotation=45)
            
            # Right: Runtime efficiency (if runtime data exists)
            if 'runtime' in df.columns and df['runtime'].notna().sum() > 0:
                scatter_exp_types = df['experiment_type'].unique()
                colors = get_experiment_colors(scatter_exp_types)
                exp_color_map = dict(zip(scatter_exp_types, colors))
                
                sns.scatterplot(data=df, x='runtime', y='accuracy', hue='experiment_type', 
                               alpha=0.7, s=60, ax=axes[1], palette=exp_color_map)
                axes[1].set_title('Accuracy vs Runtime Trade-off', fontsize=14)
                axes[1].set_xlabel('Runtime (seconds)', fontsize=12)
                axes[1].set_ylabel('Accuracy (%)', fontsize=12)
                axes[1].legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            else:
                # If no runtime data, create a different plot
                summary_stats = df.groupby('experiment_type')['accuracy'].agg(['mean', 'std']).reset_index()
                x_pos = range(len(summary_stats))
                
                # Get colors for experiment types
                error_exp_types = summary_stats['experiment_type'].tolist()
                colors = get_experiment_colors(error_exp_types)
                
                for i, (pos, color) in enumerate(zip(x_pos, colors)):
                    axes[1].errorbar(pos, summary_stats.iloc[i]['mean'], yerr=summary_stats.iloc[i]['std'],
                                    fmt='o', capsize=5, capthick=2, linewidth=2, markersize=8, color=color)
                
                axes[1].set_xlabel('Experiment Type', fontsize=12)
                axes[1].set_ylabel('Accuracy (%) ± Standard Deviation', fontsize=12)
                axes[1].set_title('Model Performance with Uncertainty Bounds', fontsize=14)
                axes[1].set_xticks(x_pos)
                axes[1].set_xticklabels(summary_stats['experiment_type'], rotation=45, ha='right')
                axes[1].grid(axis='y', alpha=0.3)
                axes[1].set_ylim(0, 100)
            
            plt.tight_layout()
            plt.savefig('14_distribution_and_tradeoff.png', dpi=300, bbox_inches='tight')
            plt.close()
            print("Saved: 14_distribution_and_tradeoff.png")
            
            # 10. Bubble Chart - Performance vs Complexity (bubble size ∝ dataset_size)
            if 'dataset_size' in df.columns and df['dataset_size'].notna().sum() > 0:
                plt.figure(figsize=(12, 8))
                
                # Create a complexity score based on optimization level
                complexity_map = {'O0': 1, 'O1': 2, 'O2': 3, 'O3': 4}
                df_bubble = df.copy()
                df_bubble['complexity_score'] = df_bubble['optimization'].map(complexity_map)
                df_bubble = df_bubble[df_bubble['complexity_score'].notna()]
                
                if not df_bubble.empty:
                    bubble_exp_types = df_bubble['experiment_type'].unique()
                    colors = get_experiment_colors(bubble_exp_types)
                    color_map = dict(zip(bubble_exp_types, colors))
                    
                    for exp_type in bubble_exp_types:
                        subset = df_bubble[df_bubble['experiment_type'] == exp_type]
                        if not subset.empty and subset['dataset_size'].notna().sum() > 0:
                            # Normalize dataset size for bubble size (min 20, max 300)
                            min_size, max_size = df_bubble['dataset_size'].min(), df_bubble['dataset_size'].max()
                            if max_size > min_size:
                                normalized_size = 20 + (subset['dataset_size'] - min_size) / (max_size - min_size) * 280
                            else:
                                normalized_size = pd.Series([100] * len(subset), index=subset.index)
                            
                            plt.scatter(subset['complexity_score'], subset['accuracy'], 
                                       s=normalized_size, alpha=0.6, label=exp_type,
                                       color=color_map[exp_type])
                    
                    plt.xlabel('Optimization Complexity (1=O0, 4=O3)', fontsize=12)
                    plt.ylabel('Accuracy (%)', fontsize=12)
                    plt.title('Performance vs Optimization Complexity (bubble size ∝ dataset size)', fontsize=14)
                    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
                    plt.grid(True, alpha=0.3)
                    plt.xticks([1, 2, 3, 4], ['O0', 'O1', 'O2', 'O3'])
                    plt.xlim(0.5, 4.5)
                    plt.ylim(0, 100)
                    plt.tight_layout()
                    plt.savefig('18_bubble_chart.png', dpi=300, bbox_inches='tight')
                    plt.close()
                    print("Saved: 18_bubble_chart.png")
                else:
                    # Fallback: use architecture diversity as x-axis
                    arch_diversity = df.groupby('experiment_type')['architecture'].nunique().reset_index()
                    arch_diversity.columns = ['experiment_type', 'arch_count']
                    df_merged = df.merge(arch_diversity, on='experiment_type')
                    
                    plt.figure(figsize=(12, 8))
                    
                    fallback_exp_types = df_merged['experiment_type'].unique()
                    colors = get_experiment_colors(fallback_exp_types)
                    color_map = dict(zip(fallback_exp_types, colors))
                    
                    for exp_type in fallback_exp_types:
                        subset = df_merged[df_merged['experiment_type'] == exp_type]
                        if not subset.empty:
                            # Use dataset size for bubble size
                            if 'dataset_size' in subset.columns and subset['dataset_size'].notna().sum() > 0:
                                min_size, max_size = df_merged['dataset_size'].min(), df_merged['dataset_size'].max()
                                if max_size > min_size:
                                    normalized_size = 20 + (subset['dataset_size'] - min_size) / (max_size - min_size) * 280
                                else:
                                    normalized_size = pd.Series([100] * len(subset), index=subset.index)
                            else:
                                normalized_size = pd.Series([100] * len(subset), index=subset.index)
                            
                            plt.scatter(subset['arch_count'], subset['accuracy'], 
                                       s=normalized_size, alpha=0.6, label=exp_type,
                                       color=color_map[exp_type])
                    
                    plt.xlabel('Architecture Diversity (number of architectures tested)', fontsize=12)
                    plt.ylabel('Accuracy (%)', fontsize=12)
                    plt.title('Performance vs Architecture Diversity (bubble size ∝ dataset size)', fontsize=14)
                    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
                    plt.grid(True, alpha=0.3)
                    plt.tight_layout()
                    plt.savefig('18_bubble_chart.png', dpi=300, bbox_inches='tight')
                    plt.close()
                    print("Saved: 18_bubble_chart.png")
            
            # ADD HEATMAP VISUALIZATIONS WITH UPDATED NAMING
            
            # Heatmap 1: Experiment Type vs Architecture Performance (Figure 16)
            if len(df['architecture'].unique()) > 1 and len(df['experiment_type'].unique()) > 1:
                plt.figure(figsize=(12, 8))
                
                # Create pivot table for heatmap
                heatmap_data = df.pivot_table(values='accuracy', 
                                            index='experiment_type', 
                                            columns='architecture', 
                                            aggfunc='mean')
                
                # Apply the same ordering as figure 1a for rows
                row_order = [exp for exp in desired_order if exp in heatmap_data.index]
                remaining_rows = [exp for exp in heatmap_data.index if exp not in desired_order]
                final_row_order = row_order + remaining_rows
                
                if final_row_order:
                    heatmap_data = heatmap_data.loc[final_row_order]
                
                # Calculate actual min/max for relative scaling
                data_min = heatmap_data.min().min()
                data_max = heatmap_data.max().max()
                data_center = (data_min + data_max) / 2
                
                # Create heatmap with relative scaling based on actual data range
                sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='RdBu_r', 
                           cbar_kws={'label': 'Accuracy (%)'}, 
                           square=False, linewidths=0.5,
                           vmin=data_min, vmax=data_max, center=data_center)
                
                plt.title(f'Performance Heatmap: Experiment Type vs Architecture', fontsize=14)
                plt.xlabel('Architecture', fontsize=12)
                plt.ylabel('Experiment Type', fontsize=12)
                plt.xticks(rotation=45)
                plt.yticks(rotation=0)
                plt.tight_layout()
                plt.savefig('16_heatmap_experiment_vs_architecture.png', dpi=300, bbox_inches='tight')
                plt.close()
                print("Saved: 16_heatmap_experiment_vs_architecture.png")
            
            # Heatmap 2: Experiment Type vs Optimization Level Performance (Figure 17)
            if len(df['optimization'].unique()) > 1 and len(df['experiment_type'].unique()) > 1:
                plt.figure(figsize=(10, 8))
                
                # Create pivot table for heatmap
                heatmap_data = df.pivot_table(values='accuracy', 
                                            index='experiment_type', 
                                            columns='optimization', 
                                            aggfunc='mean')
                
                # Reorder columns to O0, O1, O2, O3 if they exist
                opt_order = ['O0', 'O1', 'O2', 'O3']
                available_opts = [opt for opt in opt_order if opt in heatmap_data.columns]
                remaining_opts = [opt for opt in heatmap_data.columns if opt not in opt_order]
                final_opt_order = available_opts + remaining_opts
                
                if final_opt_order:
                    heatmap_data = heatmap_data[final_opt_order]
                
                # Apply the same ordering as figure 1a for rows
                row_order = [exp for exp in desired_order if exp in heatmap_data.index]
                remaining_rows = [exp for exp in heatmap_data.index if exp not in desired_order]
                final_row_order = row_order + remaining_rows
                
                if final_row_order:
                    heatmap_data = heatmap_data.loc[final_row_order]
                
                # Calculate actual min/max for relative scaling
                data_min = heatmap_data.min().min()
                data_max = heatmap_data.max().max()
                data_center = (data_min + data_max) / 2
                
                # Create heatmap with relative scaling based on actual data range
                sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='RdBu_r', 
                           cbar_kws={'label': 'Accuracy (%)'}, 
                           square=False, linewidths=0.5,
                           vmin=data_min, vmax=data_max, center=data_center)
                
                plt.title(f'Performance Heatmap: Experiment Type vs Optimization Level\n', fontsize=14)
                plt.xlabel('Optimization Level', fontsize=12)
                plt.ylabel('Experiment Type', fontsize=12)
                plt.xticks(rotation=0)
                plt.yticks(rotation=0)
                plt.tight_layout()
                plt.savefig('17_heatmap_experiment_vs_optimization.png', dpi=300, bbox_inches='tight')
                plt.close()
                print("Saved: 17_heatmap_experiment_vs_optimization.png")
            
            # Heatmap 3: Base Benchmark vs Experiment Type Performance
            if len(df['base_name'].unique()) > 1 and len(df['experiment_type'].unique()) > 1:
                plt.figure(figsize=(14, 10))
                
                # Create pivot table for heatmap
                heatmap_data = df.pivot_table(values='accuracy', 
                                            index='base_name', 
                                            columns='experiment_type', 
                                            aggfunc='mean')
                
                # Apply the same ordering as figure 1a for columns
                col_order = [exp for exp in desired_order if exp in heatmap_data.columns]
                remaining_cols = [exp for exp in heatmap_data.columns if exp not in desired_order]
                final_col_order = col_order + remaining_cols
                
                if final_col_order:
                    heatmap_data = heatmap_data[final_col_order]
                
                # Calculate actual min/max for relative scaling
                data_min = heatmap_data.min().min()
                data_max = heatmap_data.max().max()
                data_center = (data_min + data_max) / 2
                
                # Create heatmap with relative scaling based on actual data range
                sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='RdBu_r', 
                           cbar_kws={'label': 'Accuracy (%)'}, 
                           square=False, linewidths=0.5,
                           vmin=data_min, vmax=data_max, center=data_center)
                
                plt.title(f'Performance Heatmap: Base Benchmark vs Experiment Type\n', fontsize=14)
                plt.xlabel('Experiment Type', fontsize=12)
                plt.ylabel('Base Benchmark', fontsize=12)
                plt.xticks(rotation=45, ha='right')
                plt.yticks(rotation=0)
                plt.tight_layout()
                plt.savefig('19_heatmap_benchmark_vs_experiment.png', dpi=300, bbox_inches='tight')
                plt.close()
                print("Saved: 19_heatmap_benchmark_vs_experiment.png")

            # Multi-panel Heatmap: Ghidra Data Performance by Benchmark and Architecture (4 subplots)
            ghidra_data = df[df['experiment_type'].str.contains('Ghidra', case=False)]
            if not ghidra_data.empty and len(ghidra_data['base_name'].unique()) > 1:
                # Specifically target coreutils with the 4 main architectures
                target_benchmark = 'coreutils'
                target_architectures = ['armhf', 'arm64', 'x86', 'x64']
                
                plot_combos = []
                for arch in target_architectures:
                    combo_data = ghidra_data[
                        (ghidra_data['base_name'] == target_benchmark) & 
                        (ghidra_data['architecture'] == arch)
                    ]
                    if not combo_data.empty:
                        plot_combos.append(f"{target_benchmark}_{arch}")
                    else:
                        plot_combos.append(None)
                
                # Ensure we have exactly 4 slots
                while len(plot_combos) < 4:
                    plot_combos.append(None)
                plot_combos = plot_combos[:4]
                
                fig, axes = plt.subplots(2, 2, figsize=(16, 12))
                fig.suptitle('Ghidra Data Performance Heatmaps by Benchmark and Architecture', fontsize=16)
                
                # Calculate global min/max for consistent color scaling across all subplots
                global_min = ghidra_data['accuracy'].min()
                global_max = ghidra_data['accuracy'].max()
                global_center = (global_min + global_max) / 2
                
                for idx in range(4):
                    row = idx // 2
                    col = idx % 2
                    ax = axes[row, col]
                    
                    if plot_combos[idx] is not None:
                        # Parse the combination
                        combo_parts = plot_combos[idx].split('_')
                        benchmark = combo_parts[0]
                        architecture = combo_parts[1]
                        
                        # Filter data for this specific benchmark-architecture combination
                        benchmark_data = ghidra_data[
                            (ghidra_data['base_name'] == benchmark) & 
                            (ghidra_data['architecture'] == architecture)
                        ]
                        
                        if not benchmark_data.empty:
                            # Create pivot table for this benchmark-architecture combination
                            heatmap_data = benchmark_data.pivot_table(
                                values='accuracy',
                                index='experiment_type', 
                                columns='optimization',
                                aggfunc='mean'
                            )
                            
                            # Reorder optimization levels
                            opt_order = ['O0', 'O1', 'O2', 'O3']
                            available_opts = [opt for opt in opt_order if opt in heatmap_data.columns]
                            if available_opts:
                                heatmap_data = heatmap_data[available_opts]
                            
                            # Apply experiment type ordering
                            row_order = [exp for exp in desired_order if exp in heatmap_data.index]
                            remaining_rows = [exp for exp in heatmap_data.index if exp not in desired_order]
                            final_row_order = row_order + remaining_rows
                            
                            if final_row_order:
                                heatmap_data = heatmap_data.loc[final_row_order]
                            
                            # Create heatmap with consistent global scaling
                            sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='RdBu_r',
                                       ax=ax, cbar_kws={'label': 'Accuracy (%)'}, 
                                       square=False, linewidths=0.5,
                                       vmin=global_min, vmax=global_max, center=global_center)
                            
                            ax.set_title(f'{benchmark}_{architecture} - Accuracy Heatmap', fontsize=12)
                            ax.set_xlabel('Optimization Level', fontsize=10)
                            ax.set_ylabel('Experiment Type', fontsize=10)
                            
                            # Rotate labels for better readability
                            ax.tick_params(axis='x', rotation=0)
                            ax.tick_params(axis='y', rotation=0)
                        else:
                            ax.text(0.5, 0.5, f'No data for {benchmark}_{architecture}', 
                                   ha='center', va='center', transform=ax.transAxes)
                            ax.set_title(f'{benchmark}_{architecture} - No Data', fontsize=12)
                            ax.set_xticks([])
                            ax.set_yticks([])
                    else:
                        # Empty subplot
                        ax.text(0.5, 0.5, 'No Data', ha='center', va='center', transform=ax.transAxes)
                        ax.set_title('No Data', fontsize=12)
                        ax.set_xticks([])
                        ax.set_yticks([])
                
                plt.tight_layout()
                plt.savefig('20_ghidra_data_heatmaps_4panel.png', dpi=300, bbox_inches='tight')
                plt.close()
                print("Saved: 20_ghidra_data_heatmaps_4panel.png")
            else:
                print("Not enough Ghidra data for 4-panel heatmap")
