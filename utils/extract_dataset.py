import os
from pathlib import Path
import pandas as pd
import glob


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

def extract_cat_b_c(extracted_dataset, output_file, path_to_categorized_results):
    df = pd.read_csv(extracted_dataset, dtype={"old_id": str})
    output_dataset = []

    csv_files = glob.glob(os.path.join(path_to_categorized_results, "*.csv"))

    #check all results from categorizer
    for file in csv_files:
        categorized_data = []

        print("Process", file)
        cat_df = pd.read_csv(file, usecols=["id", "Category"], dtype={"id": str})
        categorized_data.append(cat_df)

        if categorized_data:
            categorized_df = pd.concat(categorized_data, ignore_index=True)

            # only take id and category because there are duplicates for every distinct model used
            categorized_df = categorized_df.drop_duplicates(
                subset=["id", "Category"]
            )

            # Keep only those categories containing categories B and C
            categorized_df = categorized_df[
                categorized_df["Category"].str.contains(
                    r"B - CWE-|C - CWE-",
                    case=False,
                    na=False
                )
            ]

            # Keep those problems from extracted dataset that were categorized with B or C
            for _, category_row in categorized_df.iterrows():
                matching_rows = df[df["old_id"] == category_row["id"]]

                for _, extracted_row in matching_rows.iterrows():
                    result_row = extracted_row.to_dict()
                    result_row["Category"] = category_row["Category"]
                    output_dataset.append(result_row)

    result_df = pd.DataFrame(output_dataset)
    # new id start with 0
    result_df["id"] = range(len(result_df))
    result_df.to_csv(output_file, index=False)

if __name__ == "__main__":
    path_to_results = Path(os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results", "raw_results")))
    list_of_models = ["deepseek/deepseek-v3.2", "openai/gpt-4o-mini", "qwen/qwen3-coder-30b-a3b-instruct"]
    dataset_file = Path(os.path.abspath(os.path.join(__file__, "..", "..", "extracted_dataset", "dataset.csv")))
    reduced_dataset_file = Path(os.path.abspath(os.path.join(__file__, "..", "..", "extracted_dataset", "dataset_cat_b_c.csv")))
    path_to_categorized_results = Path(os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results", "categorizer")))

    print(path_to_categorized_results)
    #read from raw results -> pivoted
    extract_dataset(path_to_results, list_of_models, dataset_file)

    # extract problems where detected vulnerabilities for B and C exist
    extract_cat_b_c(dataset_file, reduced_dataset_file, path_to_categorized_results)