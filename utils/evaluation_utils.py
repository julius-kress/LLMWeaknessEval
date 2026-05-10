import subprocess
import tempfile
import re
import json
from typing import Dict
from pathlib import Path

def run_bandit(code_to_check: str) -> str:
    """
     Run bandit on the given piece of code.
     :param code_to_check: The code to check for vulnerabilities with bandit
     :return: The results from the bandit evaluation
     """
    with tempfile.NamedTemporaryFile(
            suffix=".py",
            mode="w",
            delete=False
    ) as tmp:
        tmp.write(code_to_check)
        tmp_path = tmp.name

    result = subprocess.run(
        ["bandit", "-q", tmp_path],
        capture_output=True,
        text=True
    )

    output = result.stdout
    # Should not be needed...
    # errors = result.stderr

    if not output.strip():
        return "No issues found."
    else:
        extracted_result = _extract_results_from_bandit(output)
        if extracted_result:
            return extracted_result
        else:
            return output


def _extract_results_from_bandit(bandit_output: str) -> str:
    pattern = re.compile(
        r">> Issue: (.*?)\r?\n[-]{3,}\r?\n",
        re.DOTALL
    )

    matches = []

    for match in pattern.finditer(bandit_output):
        matches.append(match.group(1).rstrip())

    result = "\n".join(matches)

    return result

def run_codeql(code_to_check: str) -> str:
    """
    Run CodeQL on the given piece of code
    :param code_to_check: The code to check for vulnerabilities with CodeQL
    :return: The results from the CodeQL evaluation
    """
    # Temp directory / files needed for codeql database
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        source_file = tmpdir / "code_file.py"
        source_file.write_text(code_to_check, encoding="utf-8")

        # CodeQL database
        db_path = tmpdir / "db"

        db_result = subprocess.run(
            [
                "codeql", "database", "create",
                str(db_path),
                "--language=python",
                "--source-root", str(tmpdir),
                "--overwrite"
            ],
            check=True,
            capture_output=True,
            text=True
            #stdout=subprocess.DEVNULL,
            #stderr=subprocess.DEVNULL
        )

        #print("db_result: " + db_result.stdout)
        #print("DB STDERR:", db_result.stderr)

        sarif_path = tmpdir / "result.sarif"
        result = subprocess.run(
            [
                "codeql", "database", "analyze",
                str(db_path),
                #"python-security-and-quality.qls",
                "--format=sarifv2.1.0",
                #"--output=-"
                "--output", str(sarif_path)
            ],
            capture_output=True,
            text=True
        )

        #print("analyze_result: " + result.stdout)
        #print("sarif: " + sarif_path.read_text())
        extracted_cwes = _extract_cwes_from_sarif(sarif_path.read_text())
        #print("ANALYZE STDERR:", result.stderr)

        #return result.stdout
        return extracted_cwes

def _extract_cwes_from_sarif(sarif_text: str) -> str:
    sarif = json.loads(sarif_text)

    # Rule IDs that actually produced findings
    triggered_rules = {
        result["ruleId"]
        for run in sarif.get("runs", [])
        for result in run.get("results", [])
        if "ruleId" in result
    }

    cwes: Dict[str, str] = {}

    # Walk rules and extract CWE info
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])

        for rule in rules:
            rule_id = rule.get("id")
            if rule_id not in triggered_rules:
                continue

            # Best available description
            description = (
                rule.get("help", {}).get("text")
                or rule.get("shortDescription", {}).get("text")
                or "No description available"
            )

            tags = rule.get("properties", {}).get("tags", [])
            for tag in tags:
                if tag.startswith("external/cwe/"):
                    cwe_num = tag.replace("external/cwe/", "")
                    # First three letters (cwe) uppercase
                    cwe_num = cwe_num[:3].upper() + cwe_num[3:]
                    cwes[f"{cwe_num}"] = description.strip()

    if not cwes:
        return "NO_CWE"

    lines = [
        f"{cwe}\t{desc.replace(chr(10), ' ')}"
        for cwe, desc in sorted(cwes.items())
    ]
    return "\n".join(lines)

def get_cwe_bandit_output(bandit_output: str) -> list[str]:
    """
    Converts bandit output to a list of only CWE-Numbers, empty if there were no Issues found
    :param bandit_output: The bandit output from a "_result.csv"
    :return: a list with only CWE numbers
    """
    if not bandit_output:
        return []
    matches = re.findall(r"CWE: CWE-(\d+)", bandit_output)
    # Remove trailing zeros so e.g. 094 becomes 94
    return [str(int(m)) for m in matches]

def get_cwe_codeql_output(codeql_output: str) -> list[str]:
    """
    Converts codeql output to a list of only CWE-Numbers, empty if there were no Issues found
    :param codeql_output: The codeql output from a "_result.csv"
    :return: a list with only CWE numbers
    """
    if not codeql_output:
        return []
    matches = re.findall(r"CWE-(\d+)", codeql_output)
    # Remove trailing zeros so e.g. 094 becomes 94
    return [str(int(m)) for m in matches]