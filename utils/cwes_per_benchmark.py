import os
from pathlib import Path
from collections import Counter
import pandas as pd





def count_cwes_per_benchmark(folder_path):
    folder = Path(folder_path)

    # collect all csv file ending with "_result.csv"
    csv_files = list(folder.glob("*_result.csv"))

    if not csv_files:
        print("No matching CSV files found.")
        return

    counter_dict = {}

    # read and combine all CSV files
    for file in csv_files:
        cwe_counter = Counter()

        df = pd.read_csv(file)

        benchmark_name = file.name.removesuffix("_result.csv")


        ############################################################
        # Cwes in all cases
        ############################################################
        """
        for value in df["conjunction_bandit_codeql"].dropna():
            cwes = str(value).splitlines()
            cwe_counter.update(cwes)
        """
        ############################################################



        #################################################################
        # Cwes in cases where all models failed
        #################################################################
        model_count = df["model"].nunique()

        # Find IDs where every model has vulnerabilities
        valid_ids = (
            df.groupby("id")["conjunction_bandit_codeql"]
            .apply(lambda values: values.notna().sum() == model_count)
        )

        valid_ids = valid_ids[valid_ids].index

        for _, row in df[df["id"].isin(valid_ids)].iterrows():
            cwes = str(row["conjunction_bandit_codeql"]).splitlines()
            cwe_counter.update(cwes)

        ##################################################################

        counter_dict[benchmark_name] = cwe_counter

    all_numbers = set()

    for counter in counter_dict.values():
        all_numbers.update(counter.keys())

    result = pd.DataFrame({
        "CWE": sorted(all_numbers, key=int)
    })

    for file, counter in counter_dict.items():
        result[file] = result["CWE"].map(counter).fillna(0).astype(int).replace(0, "-")

    print(result.to_string(index=False))




def main():
    folder_path = os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results", "raw_results"))
    count_cwes_per_benchmark(folder_path)


if __name__ == "__main__":
    main()