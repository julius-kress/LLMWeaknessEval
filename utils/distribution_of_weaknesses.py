import os
import csv
from collections import defaultdict
from enum import Enum

import pandas as pd

from utils.evaluation_utils import get_cwe_bandit_output, get_cwe_codeql_output

class WeaknessClass(Enum):
    NO_WEAKNESS = 0
    EXECUTION_OF_UNTRUSTED_INPUT = 1
    UNSAFE_PARSING_FILE_PROCESSING = 2
    WEB_SANITIZATION_FAILURE = 3
    MISMANAGEMENT_SECRETS_CRYPTOGRAPHY = 4
    UNSAFE_DEFAULT_CONFIGURATION = 5
    OTHER = 6

def pivot_evaluations(csv_path: str) -> str:
    df = pd.read_csv(csv_path)

    # Process evaluations
    df["bandit_evaluation"] = df["bandit_evaluation"].apply(lambda x: "\n".join(get_cwe_bandit_output(x) or []))
    df["codeql_evaluation"] = df["codeql_evaluation"].apply(lambda x: "\n".join(get_cwe_codeql_output(x) or []))

    # Combine both evaluations into one string per model
    df["cwe_evaluation"] = (
        df["bandit_evaluation"] + "\n" +
        df["codeql_evaluation"]
    )

    # Pivot
    pivot_df = df.pivot_table(
        index=["id", "prompt"],
        columns="model",
        values="cwe_evaluation",
        aggfunc="first"
    ).reset_index()

    pivot_df.columns.name = None

    # Save new csv
    dir_name = os.path.dirname(csv_path)
    base_name = os.path.splitext(os.path.basename(csv_path))[0]
    output_path = os.path.join(dir_name, f"{base_name}_pivoted.csv")

    pivot_df.to_csv(output_path, index=False)

    return output_path

def _check_weakness_class(list_of_cwes: str) -> list[WeaknessClass]:
    result_set = set()

    if list_of_cwes.strip() == "":
        result_set.add(WeaknessClass.NO_WEAKNESS)
    else:
        cwes = list_of_cwes.splitlines()

        # Checking all detected cwes on vulnerability classes I defined in the thesis
        for cwe in cwes:
            match cwe.strip():
                case "":
                    # Empty line, ignore it
                    pass
                case "78" | "94" | "95":
                    result_set.add(WeaknessClass.EXECUTION_OF_UNTRUSTED_INPUT)
                case "22" | "377" | "502" | "611" | "827":
                    result_set.add(WeaknessClass.UNSAFE_PARSING_FILE_PROCESSING)
                case "20" | "79" | "116" | "601":
                    result_set.add(WeaknessClass.WEB_SANITIZATION_FAILURE)
                case "259" | "327" | "328" | "916":
                    result_set.add(WeaknessClass.MISMANAGEMENT_SECRETS_CRYPTOGRAPHY)
                case "88" | "209" | "215" | "489" | "497":
                    result_set.add(WeaknessClass.UNSAFE_DEFAULT_CONFIGURATION)
                case _:
                    #_print_to_distribution_results(f"not in a weakness class: {cwe}")
                    result_set.add(WeaknessClass.OTHER)

    return list(result_set)


def benchmark_distribution(csv_path: str):
    result : str = ""
    dir_name = os.path.dirname(csv_path)
    base_name = os.path.splitext(os.path.basename(csv_path))[0]
    output_path = os.path.join(dir_name, f"{base_name}.txt")

    distribution = defaultdict(lambda: defaultdict(int))


    df = pd.read_csv(csv_path)
    number_of_models = len(df.columns) - 2
    cases_in_total = 0
    cases_all_models_vulnerable = 0

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        cases_in_total += 1

        #print(row_dict["id"])
        #print(row_dict["prompt"])
        vulnerable_models = 0

        # list(model_name, list(detected_weakness_class))
        temp_list_of_weaknesses: list[tuple[str, list[WeaknessClass]]] = []

        for col, val in row_dict.items():

            if col in ["id", "prompt"]:
                continue

            # Only consider cases where all models produced vulnerabilities
            if val.strip() != "":
                vulnerable_models += 1
                temp_list_of_weaknesses.append((col, _check_weakness_class(val)))
            else:
                break

            #print(f"{col}: {val}")


        # Only consider cases where all models produced vulnerabilities
        if vulnerable_models == number_of_models:
            cases_all_models_vulnerable += 1
            for model_name, weakness_classes in temp_list_of_weaknesses:
                #if len(weakness_classes) > 1:
                    #print(model_name + ": " + str(len(weakness_classes)) + " -> " + str(weakness_classes))
                for w in weakness_classes:
                    distribution[model_name][w] += 1

    _print_to_distribution_results("Benchmark: " + base_name.removesuffix("_result_pivoted"))
    _print_to_distribution_results("Total testcases: " + str(cases_in_total))
    _print_to_distribution_results("Cases where all models produced vulnerable code: " +  str(cases_all_models_vulnerable))
    _print_to_distribution_results("Weakness Classes for models (some cases may provoke more than one single vulnerability class):")
    for model, weakness_classes in distribution.items():
        _print_to_distribution_results(model)

        # Sort by enum value
        for w_class, count in sorted(weakness_classes.items(),key=lambda item: item[0].value):
            _print_to_distribution_results(f"  {w_class.name}: {count}")
        _print_to_distribution_results("\n")



def _print_to_distribution_results(text: str):
    output_path = os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results", "distribution_results.txt"))
    with open(output_path, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def _clear_distribution_results():
    output_path = os.path.abspath(
        os.path.join(__file__, "..", "..", "evaluation_results", "distribution_results.txt")
    )
    open(output_path, "w", encoding="utf-8").close()

def main():
    output_path = os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results"))

    print("clear distribution.txt")
    _clear_distribution_results()

    print("Evaluate *_result_csv files")
    pivot_evaluations(os.path.join(output_path, "CodeLMSec_result.csv"))
    pivot_evaluations(os.path.join(output_path, "LLMSecEval_result.csv"))
    pivot_evaluations(os.path.join(output_path, "SecurityEval_result.csv"))

    print("Create distribution")
    _print_to_distribution_results("""Explanation of Weakness Classes:
EXECUTION_OF_UNTRUSTED_INPUT:
    The model allows possible attacker-controlled input data be turned into executable behavior
    -> covers Code / Command / SQL Injection, arbitrary code evaluation
UNSAFE_PARSING_FILE_PROCESSING:
    Handling of archives, XML or system paths without safely constraining
    -> covers Unsafe deserialization, Path traversal, tar/archives, Insecure temporary files, XXE
WEB_SANITIZATION_FAILURE:
    Model accepts request data, redirects it or uses it in responses without proper encoding or validation
    -> covers Open Redirect, Reflected XSS, improper input validation
MISMANAGEMENT_SECRETS_CRYPTOGRAPHY:
    About insecure protection of sensitive data or weak security primitives in general
    -> covers Weak cryptographic hashing, Hard-coded credentials
UNSAFE_DEFAULT_CONFIGURATION:
    Leak of stack traces / filepaths / config data because of the configuration the model did
    -> covers Information Exposure, debug mode, stack trace exposure
OTHER:
    Additional weaknesses that were not automatically sorted into the classes above.
"""
          )

    _print_to_distribution_results("-"*45)
    benchmark_distribution(os.path.join(output_path, "CodeLMSec_result_pivoted.csv"))
    _print_to_distribution_results("-"*45)
    benchmark_distribution(os.path.join(output_path, "LLMSecEval_result_pivoted.csv"))
    _print_to_distribution_results("-"*45)
    benchmark_distribution(os.path.join(output_path, "SecurityEval_result_pivoted.csv"))


if __name__ == "__main__":
    main()