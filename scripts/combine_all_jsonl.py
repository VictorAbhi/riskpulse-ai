# combine_all_jsonl.py
from pathlib import Path
import shutil
import glob

def combine_jsonl_files(input_folder_or_list, output_path):
    if isinstance(input_folder_or_list, str):
        jsonl_files = glob.glob(f"{input_folder_or_list}/*.jsonl")
    else:
        jsonl_files = input_folder_or_list  # list of file paths
    
    jsonl_files = sorted(jsonl_files)  # optional: alphabetical order
    
    total_lines = 0
    with open(output_path, 'wb') as outfile:
        for file_path in jsonl_files:
            print(f"Adding {file_path}...")
            with open(file_path, 'rb') as infile:
                shutil.copyfileobj(infile, outfile)
            # Count lines (optional)
            with open(file_path, 'r', encoding='utf-8') as count_f:
                total_lines += sum(1 for _ in count_f)
    
    print(f"\nCombined {len(jsonl_files)} files into {output_path} ({total_lines:,} lines)")

# Usage examples
# Option 1: All .jsonl in a folder
combine_jsonl_files("data\\raw", "master_all_datasets.jsonl")