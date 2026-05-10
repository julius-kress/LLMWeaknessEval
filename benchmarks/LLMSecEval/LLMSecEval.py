from benchmarks.BenchmarkRunner import BenchmarkRunner
import os
from typing import Dict, List, Any
import json
from tqdm import tqdm
import time

class LLMSecEval(BenchmarkRunner):
    """
    Benchmark LLMSecEval
    """
    def __init__(self):
        super().__init__()
        self.BENCHMARK_ROOT = os.path.join(self.PROJECT_ROOT, "benchmarks", "LLMSecEval")

        self.init_folder_structure()
        self.DATASET_FILE = os.path.join(self.BENCHMARK_ROOT, "LLMSecEval-Prompts_dataset.json")

    def load_dataset(self) -> List[Dict[str, Any]]:
        """Load the LLMSecEval dataset and filter for Python entries."""
        with open(self.DATASET_FILE, 'r') as f:
            dataset = json.load(f)

        # Filter for Python only
        python_entries = [entry for entry in dataset if entry.get('Language') == 'Python']

        print(f"Loaded {len(dataset)} total entries")
        print(f"Filtered to {len(python_entries)} Python entries")

        return python_entries

    # Override
    def get_benchmark_root(self) -> str:
        return self.BENCHMARK_ROOT

    # Override
    def generate_code(self, model: str):
        dataset = self.load_dataset()
        model_type = model.split("/", 1)[0]

        self.save_log(f"Starting generation for {len(dataset)} prompts...")

        for idx, entry in enumerate(tqdm(dataset, desc="Generating code")):

            prompt_id = entry.get('Prompt ID')
            prompt = entry.get('Manually-fixed NL Prompt') or entry.get('LLM-generated NL Prompt')
            cwe_name = entry.get('CWE Name', 'Unknown')
            vulnerable = entry.get('Vulnerable', False)
            out_json_path = os.path.join(self.JSON_OUTPUT_DIR, f"{prompt_id}_{model_type}.json")

            if os.path.exists(out_json_path):
                self.save_log(f"[{idx + 1}/{len(dataset)}] Skipping ID {prompt_id}_{model_type} (already done)")
                continue

            # Replace <language> placeholder from dataset with Python
            prompt = prompt.replace('<language>', 'Python').replace('<lanuage>', 'Python')

            self.save_log(f"[{idx + 1}/{len(dataset)}] Generating code for ID {prompt_id}_{model_type}")

            generated_code = self.request_llm(prompt, model)
            generated_code = self.clean_python_code(generated_code)

            if not generated_code:
                self.save_log(f"[{idx + 1}/{len(dataset)}] Failed to generate code for ID {prompt_id}_{model_type}")

            # Save JSON
            self.save_json_result(out_json_path, prompt_id + ": " + cwe_name + " Vulnerable: " + str(vulnerable), prompt, generated_code, model)

            self.save_log(f"[{idx + 1}/{len(dataset)}] Successfully generated code for ID {prompt_id}_{model_type}")

            # Sleep to respect rate limits
            time.sleep(1)
