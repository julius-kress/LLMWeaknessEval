import os
import re
from typing import Any

import pandas as pd
import json
from pathlib import Path

def parse_lines(value):
    if pd.isna(value):
        return set()

    return {
        line.strip()
        for line in str(value).splitlines()
        if line.strip()
    }

def extract_cwes_from_section(cell):

    cwe_pattern = re.compile(r"CWE-(\d+)")
    cwes = set()

    matches = cwe_pattern.findall(cell)
    for match in matches:
        normalized = str(int(match))  # removes leading zeros
        cwes.add(normalized)

    return cwes

def combine_evaluations(bandit_value, codeql_value):

    bandit = extract_cwes_from_section(bandit_value)
    codeql = extract_cwes_from_section(codeql_value)

    conjunction = bandit | codeql
    intersection = bandit & codeql

    return (
        "\n".join(sorted(conjunction, key=int)),
        "\n".join(sorted(intersection, key=int)),
    )

def process_file(path):
    print(f"Processing: {path}")

    df = pd.read_csv(path)

    # Some hacky addition of target cwes afterward
    benchmark = os.path.basename(path).replace("_result.csv", "")

    path = Path(path)
    print("benchmark:", benchmark)
    id_cwe_dict = {}
    if benchmark == "CyberSecEval":
        with open(path.parent.parent.parent / "benchmarks" / "CyberSecEval" / "instruct-v2.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        counter = 0
        for entry in data:
            global_sample_id = str(entry["prompt_id"])
            cwe_id = entry["cwe_identifier"]
            language = entry["language"]
            if language == "python":
                id_cwe_dict[str(counter)] = cwe_id
                counter += 1

    elif benchmark == "SecCodePLT":
        with open(path.parent.parent.parent / "benchmarks" / "SecCodePLT" / "data.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        for entry in data:
            global_sample_id = str(entry["global_sample_id"])
            cwe_id = entry["cwe_id"]
            id_cwe_dict[global_sample_id] = cwe_id

    def get_target_cwe(row):
        row_id = row["id"]

        match benchmark:
            case "SecurityEval":
                return row_id.split("_", 1)[0]
            case "CodeLMSec":
                return row_id.split(":", 1)[0]
            case "LLMSecEval":
                return row_id.split("_", 1)[0]
            case "CyberSecEval":
                return id_cwe_dict[str(row_id)]
            case "SecCodePLT":
                return "CWE-" + id_cwe_dict[str(row_id)]
            case _:
                return ""

    df["target_cwe"] = df.apply(get_target_cwe, axis=1)
    columns = list(df.columns)
    columns.remove("target_cwe")
    columns.insert(1, "target_cwe")
    df = df[columns]

    results = df.apply(
        lambda row: combine_evaluations(
            row["bandit_evaluation"],
            row["codeql_evaluation"],
        ),
        axis=1,
    )

    df["conjunction_bandit_codeql"] = results.apply(lambda x: x[0])
    df["intersection_bandit_codeql"] = results.apply(lambda x: x[1])

    # Overwrite the original CSV.
    df.to_csv(path, index=False)

    print(f"  Done: {len(df)} rows")

def main():
    folder_path = "../evaluation_results/raw_results"

    if not os.path.isdir(folder_path):
        raise SystemExit(f"Not a directory: {folder_path}")

    files = sorted([
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if f.endswith("_result.csv")
    ])

    if not files:
        print(f"No *_result.csv files found in {folder_path}")
        return

    for path in files:
        process_file(path)


if __name__ == "__main__":
    main()