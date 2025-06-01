#!/usr/bin/env python3
from pathlib import Path
from rich.console import Console
import subprocess
from typing import List

from wildebeest.utils import print_runtime

def eval_model_on_benchmarks(benchmarks:List[Path], model_path:Path, out_folder:Path, test_split:bool=False):
    for bm in benchmarks:
        eval_outfolder = Path(f'{out_folder/bm.name}.dragon')
        if eval_outfolder.exists():
            print(f'Eval output folder {eval_outfolder} already exists! Skipping...')
            continue
        with print_runtime(f'{bm.name}'):
            cmd =  ['eval_simple_types', str(eval_outfolder), '--dataset', str(bm), '--dragon', str(model_path)]
            if test_split:
                cmd.append('--test-split')
            subprocess.call(cmd)
            # print(' '.join(cmd))

def main():
    # run from top-level dragon folder: ./scripts/run_dragon_benchmarks.py
    datasets_folder = Path('dragonData').absolute()
    models_folder = Path('evalModels').absolute()
    out_folder = Path('dragon_evals').absolute()
    ##################################################

    console = Console()
    out_folder.mkdir(exist_ok=True)

    coreutils_ds_list = list(datasets_folder.glob('coreutils_*5hops'))
    complex_ds = datasets_folder/'complex_5hops'
    resym_ds = datasets_folder/'resym_test_5hops'
    test_split_ds = datasets_folder/'tydamin_sample_5hops'  # for test split

    tydamin_model = models_folder/'replicate_tydamin_ep35.pt'
    resym_model = models_folder/'replicate_resym_train_ep35.pt'

    # tydamin model
    console.rule(f'Eval [green]{tydamin_model.name}[/] on [cyan]TyDAmin Test Split')
    eval_model_on_benchmarks([test_split_ds], tydamin_model, out_folder, test_split=True)

    console.rule(f'Eval [green]{tydamin_model.name}[/] on [cyan]Coreutils Benchmarks')
    eval_model_on_benchmarks(coreutils_ds_list, tydamin_model, out_folder)

    console.rule(f'Eval [green]{tydamin_model.name}[/] on [cyan]Complex Benchmark')
    eval_model_on_benchmarks([complex_ds], tydamin_model, out_folder)

    # resym model
    console.rule(f'Eval [orange1]{resym_model.name}[/] on [cyan]ReSym Benchmark')
    eval_model_on_benchmarks([resym_ds], resym_model, out_folder)


if __name__ == '__main__':
    main()
