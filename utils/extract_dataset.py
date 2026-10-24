import os
from pathlib import Path
import pandas as pd


def extract_dataset(path_to_results, list_of_models, output_file):

    # new columns:
    # id -> number
    # benchmark_origin -> benchmark name
    # old_benchmark_id -> id of task in benchmark
    # prompt -> prompt
    # cwes_by_all_models -> 'CWE-<NUMBER>' that all models produced

    all_results = []

    for file_path in path_to_results.glob("*_result_pivoted.csv"):
        # extract benchmark name from the filename
        benchmark = file_path.name.removesuffix("_result_pivoted.csv")

        # Read the input CSV
        df = pd.read_csv(file_path)

        # keep rows where all models produced vulnerable code = ther are CWEs
        mask = (
                df[list_of_models]
                .notna()
                .all(axis=1)
                & df[list_of_models]
                .apply(lambda col: col.astype(str).str.strip().ne(""))
                .all(axis=1)
        )
        df = df[mask]

        for _, row in df.iterrows():
            # get cwe numbers (separated by newlines)
            cwe_sets = [
                set(value.strip() for value in str(row[col]).splitlines() if value.strip())
                for col in list_of_models
            ]

            # get cwes that were produced by all models
            cwe_numbers = set.intersection(*cwe_sets)

            # Sort and add the CWE- prefix
            sorted_cwes = sorted(cwe_numbers, key=int)
            cwe_string = "\n".join(f"CWE-{cwe}" for cwe in sorted_cwes)

            all_results.append({
                "benchmark": benchmark,
                "old_id": row["id"],
                "prompt": row["prompt"],
                "cwes_by_all_models": cwe_string,
            })

    # assign ascending IDs
    result_df = pd.DataFrame(all_results)
    result_df.insert(0, "id", range(1, len(result_df) + 1))

    result_df.to_csv(output_file, index=False)

    print(f"Saved {len(result_df)} rows to {output_file}")

    pass

if __name__ == "__main__":
    path_to_results = Path(os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results", "raw_results")))
    list_of_models = ["deepseek/deepseek-v3.2", "openai/gpt-4o-mini", "qwen/qwen3-coder-30b-a3b-instruct"]
    output_file = Path(os.path.abspath(os.path.join(__file__, "..", "..", "extracted_dataset", "dataset.csv")))

    #read from raw results -> pivoted
    extract_dataset(path_to_results, list_of_models, output_file)