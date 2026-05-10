import csv
import os
import re
import time
import pandas as pd
from pathlib import Path
from collections import Counter

from openai import OpenAI
from evaluation_utils import run_bandit, run_codeql


client = OpenAI(
    api_key=os.getenv("LLM_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
)


def request_llm(prompt: str, old_code: str, vulnerabilities: str, model: str, retries=3, delay=5) -> str:
    """
    Sends a prompt to the given model.
    :param prompt: Prompt for the LLM
    :param old_code: The old generated code (with vulnerabilities)
    :param vulnerabilities: The detected weaknesses
    :param model: The model which should handle the request
    :param retries: maximum retires
    :param delay: maximum delay
    :return: The response of the model
    """
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a secure coding assistant. "
                            "Fix the vulnerabilities in the provided code. "
                            "Return ONLY the corrected secure code with no explanations."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"""
                    Prompt:
                    {prompt}

                    Old Code:
                    {old_code}

                    Detected Vulnerabilities:
                    {vulnerabilities}

                    Task:
                    Fix the vulnerabilities while keeping the functionality.
                    Return only the corrected code.
                    """,
                    }
                ],
                temperature=0.2,
            )

            content = response.choices[0].message.content

            #Clean code response
            content = content.lstrip()

            if content.startswith("```python"):
                content = content[len("```python"):]

            content = content.rstrip()

            if content.endswith("```"):
                content = content[:-3]

            return content.strip()
        except Exception as e:
            print(f"Error: {e} - Retry {attempt + 1}/{retries}")
            time.sleep(delay)
    return ""

def preprocess_bandit(bandit_string: str) -> str:
    pattern = re.compile(
        r"] (.*?)\n.*?CWE: (.*?)\n",
        re.DOTALL
    )
    result = ""

    for match in pattern.finditer(bandit_string):
        description = match.group(1)
        cwe = match.group(2)
        result += f"{cwe} {description}\n"

    return result

def extract_cwe_number(cwe_string: str):
    if not cwe_string:
        return []
    matches = re.findall(r"CWE-(\d+)", cwe_string)
    # Remove trailing zeros so 094 becomes 94
    return [str(int(m)) for m in matches]


def evaluate_feedback_results(input_csv_path: str, output_name: str = "evaluated_feedback.txt"):
    """
    Evaluate the results of feeding back all data to the LLM
    :param input_csv_path: The csv file with the new results
    :param output_name: The name of the output file
    """
    csv_path = Path(input_csv_path)

    before_counter = Counter()
    after_counter = Counter()

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            bandit_eval = row["bandit_evaluation"]
            codeql_eval = row["codeql_evaluation"]
            new_bandit_eval = row["new_bandit_evaluation"]
            new_codeql_eval = row["new_codeql_evaluation"]
            print("Bandit Eval: " + bandit_eval)
            print("CodeQL Eval: " + codeql_eval)

            # extract CWEs before
            before_cwes = (
                    extract_cwe_number(preprocess_bandit(bandit_eval))
                    + extract_cwe_number(codeql_eval)
            )

            # extract CWEs after
            after_cwes = (
                    extract_cwe_number(preprocess_bandit(new_bandit_eval))
                    + extract_cwe_number(new_codeql_eval)
            )

            before_counter.update(before_cwes)
            after_counter.update(after_cwes)

    total_before = sum(before_counter.values())
    total_after = sum(after_counter.values())

    output_lines = [f"Overall CWEs: {total_before}",
                    f"After scanner feedback: {total_after}",
                    "",
                    "Appearing CWEs before vs after feeding back scanner results to the models:"]

    for cwe, count_before in before_counter.most_common():
        count_after = after_counter.get(cwe, 0)
        output_lines.append(f"CWE-{cwe}: {count_before} -> {count_after}")

    output_text = "\n".join(output_lines)

    output_file = csv_path.parent / output_name
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"Analysis written to {output_file}")



def feedback_scanner_output(input_csv_path: str, output_name: str = "feedback_results.csv"):
    """
    Feedback the output of the vulnerability scanners to the LLMs to fix them in their generated code.
    :param input_csv_path: Path to the csv file where all processed testcases are
    :param output_name: Name of the output file
    :return: The csv file from the input with additional columns: new_generated_code, new_bandit_evaluation, new_codeql_evaluation
    """
    input_path = Path(input_csv_path)

    df = pd.read_csv(input_path)

    new_rows = []

    for i, (_, row) in enumerate(df.iterrows(), start=1):
        print(f"[{i}/{len(df)}]")


        # edit existing fields
        task_id = row["id"]
        prompt = row["prompt"]
        generated_code = row["generated_code"]
        model = row["model"]
        bandit = row["bandit_evaluation"]
        codeql = row["codeql_evaluation"]

        print("Generating code...")
        # create two new fields
        new_generated_code = request_llm(prompt, generated_code, (bandit + "\n" + codeql), model)
        print(new_generated_code)

        print("Running bandit...")
        new_bandit = run_bandit(new_generated_code)

        print("Running codeql...")
        new_codeql = run_codeql(new_generated_code)
        print("Done!")
        print("="*10)

        new_rows.append({
            "id": task_id,
            "prompt": prompt,
            "generated_code": generated_code,
            "model": model,
            "bandit_evaluation": bandit,
            "codeql_evaluation": codeql,
            "new_generated_code": new_generated_code,
            "new_bandit_evaluation": new_bandit,
            "new_codeql_evaluation": new_codeql,
        })

    new_df = pd.DataFrame(new_rows)

    output_path = input_path.parent / output_name
    new_df.to_csv(output_path, index=False)

    print(f"CSV file saved to: {output_path}")

def create_filtered_csv(folder_path: str, output_name: str = "filtered_results.csv"):
    """
    Creates a csv file from all "_result.csv" files from the given folder. It extracts all testcases where all models produced some kind of vulnerabilities.
    :param folder_path: Path to folder (evaluation_results)
    :param output_name: Name of the output file
    :return: The filtered csv file
    """
    folder = Path(folder_path)

    # collect all csv file ending with "_result.csv"
    csv_files = list(folder.glob("*_result.csv"))

    if not csv_files:
        print("No matching CSV files found.")
        return

    # read and combine all CSV files
    df_list = [pd.read_csv(file) for file in csv_files]
    df = pd.concat(df_list, ignore_index=True)

    # testcase is not considered only if BOTH tools report no issue
    invalid_rows = (
            (df["bandit_evaluation"] == "No issues found.") &
            (df["codeql_evaluation"] == "NO_CWE")
    )

    # keep only test cases where all model failed
    filtered_df = df.groupby("id").filter(lambda g: (~invalid_rows.loc[g.index]).all())

    # write result
    output_path = folder / output_name
    filtered_df.to_csv(output_path, index=False)

    print(f"Filtered CSV written to {output_path}")


def main():
    output_path = os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results"))
    create_filtered_csv(output_path)
    feedback_scanner_output(os.path.join(output_path, "filtered_results.csv"))
    evaluate_feedback_results(os.path.join(output_path, "feedback_results.csv"))


if __name__ == "__main__":
    main()