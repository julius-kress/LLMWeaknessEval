import os
import re
import csv
from collections import defaultdict


def is_section_header(lines, index):
    """
    Check if lines[index:index+3] goes like:
        ========
        | text |
        ========
    """
    if index + 2 >= len(lines):
        return False

    line1 = lines[index].strip()
    line2 = lines[index + 1].strip()
    line3 = lines[index + 2].strip()

    return (
        line1.startswith("=")
        and line3.startswith("=")
        and line2.startswith("|")
    )


def split_into_sections(lines):
    sections = []
    current_section = []
    i = 0

    while i < len(lines):
        if is_section_header(lines, i):
            # If we already collected a section, save it
            if current_section:
                sections.append(current_section)
                current_section = []

            # Skip the 3 header lines
            i += 3
        else:
            current_section.append(lines[i])
            i += 1

    if current_section:
        sections.append(current_section)

    return sections


def extract_cwes_from_section(section_lines):
    cwe_pattern = re.compile(r"->\s*CWE-(\d+)")
    cwes = set()

    for line in section_lines:
        matches = cwe_pattern.findall(line)
        for match in matches:
            normalized = str(int(match))  # removes leading zeros
            cwes.add(normalized)

    return cwes


def analyze_sections(sections):
    cwe_section_count = defaultdict(int)
    co_occurrence = defaultdict(lambda: defaultdict(int))

    for section in sections:
        cwes_in_section = extract_cwes_from_section(section)

        for cwe in cwes_in_section:
            cwe_section_count[cwe] += 1

        for cwe_a in cwes_in_section:
            for cwe_b in cwes_in_section:
                if cwe_a != cwe_b:
                    co_occurrence[cwe_a][cwe_b] += 1

    return cwe_section_count, co_occurrence


def write_csv(output_filename, total_sections, cwe_section_count, co_occurrence):
    with open(output_filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(["Total Testcases", total_sections])
        writer.writerow([])

        writer.writerow([
            "CWE-Name",
            "Testcases CWE Appeared In",
            "Co-Occurring CWE",
            "Testcases where CWE co-occurred",
            "Percentage of co-occuring CWE in testcases"
        ])

        for cwe, section_count in sorted(cwe_section_count.items(), key=lambda x: int(x[0])):
            if cwe in co_occurrence:
                for other_cwe, co_count in sorted(co_occurrence[cwe].items(), key=lambda x: int(x[0])):
                    percentage = co_count / section_count
                    writer.writerow([
                        f"CWE-{cwe}",
                        section_count,
                        f"CWE-{other_cwe}",
                        co_count,
                        f"{percentage:.2%}"
                    ])
            else:
                writer.writerow([
                    f"CWE-{cwe}",
                    section_count,
                    "",
                    "",
                    ""
                ])


def main():

    parent_dir = os.path.dirname(os.getcwd())
    file_path = os.path.join(parent_dir, "evaluation_results", "overall_summary.txt")
    output_path = os.path.join(parent_dir, "evaluation_results", "cwe_dependencies.csv")

    lines = []
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Split into sections, basically the individual test cases
    sections = split_into_sections(lines)
    total_sections = len(sections) - 1

    cwe_section_count, co_occurrence = analyze_sections(sections)

    write_csv(output_path, total_sections, cwe_section_count, co_occurrence)

    print(f"Total number of Testcases: {total_sections}")
    print(f"CSV output written to: {output_path}")


if __name__ == "__main__":
    main()