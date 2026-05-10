import re
import os
from collections import Counter


def count_cwe_entries(input_file_path):
    with open(input_file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Regex to match strings like "-> CWE-123"
    pattern = r"->\s*CWE-(\d+)"
    matches = re.findall(pattern, content)

    # Remove trailing zeros so that e.g. CWE-094 and CWE-94 are grouped together
    normalized = []
    for number in matches:
        clean_number = int(number)

        # Rebuild normalized string
        normalized.append(f"CWE-{clean_number}")

    # Count occurrences
    counts = Counter(normalized)

    # Prepare output file path (same directory)
    directory = os.path.dirname(input_file_path)
    output_file_path = os.path.join(directory, "cwe_summary.txt")

    # Write results to output file
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        for entry, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            output_file.write(f"{entry}: {count}\n")

    print(f"Summary written to: {output_file_path}")


if __name__ == "__main__":
    input_path = os.path.abspath(os.path.join(__file__, "..", "..", "evaluation_results", "overall_summary.txt"))
    count_cwe_entries(input_path)