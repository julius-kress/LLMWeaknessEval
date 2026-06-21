from benchmarks.BenchmarkRunner import BenchmarkRunner
import os
import json
from tqdm import tqdm
import time

class CodeLMSec(BenchmarkRunner):
    """
    Benchmark CodeLMSec
    """
    def __init__(self):
        super().__init__()
        self.BENCHMARK_ROOT = os.path.join(self.PROJECT_ROOT, "benchmarks", "CodeLMSec")

        self.init_folder_structure()
        # Prompts I got from Anshul
        self.DATASET_FILE = os.path.join(self.BENCHMARK_ROOT, "prompt_code_pairs.json")

    def load_dataset(self):
        with open(self.DATASET_FILE, 'r') as f:
            dataset = json.load(f)

        python_data = dataset.get('py', {})

        print(f"Loaded {len(python_data)} total entries")

        return python_data

    # Override
    def get_benchmark_root(self) -> str:
        return self.BENCHMARK_ROOT

    # Override
    def generate_code(self, model: str):
        python_data = self.load_dataset()
        model_type = model.split("/", 1)[0]

        self.save_log("Starting generation for CodeLMSec...")

        for cwe_id, cwe_data in tqdm(python_data.items(), desc="Processing CWEs"):
            prompts = cwe_data.get('prompts', [])

            for idx, prompt in enumerate(prompts):

                out_json_path = os.path.join(self.JSON_OUTPUT_DIR, f"{cwe_id}_{idx}_{model_type}.json")

                if os.path.exists(out_json_path):
                    self.save_log(f"[Skipping ID {cwe_id}_{idx}_{model_type} (already done)")
                    continue

                self.save_log(f"Generating code for ID {cwe_id}_{idx}_{model_type}")

                generated_code = self.request_llm(prompt, model)
                generated_code = self.clean_python_code(generated_code)

                if not generated_code:
                    self.save_log(
                        f"Failed to generate code for ID {cwe_id}_{idx}_{model_type}. Prompt: {prompt}")
                    continue

                # Save JSON
                self.save_json_result(out_json_path, cwe_id + ":" + str(idx), prompt, generated_code, model)

                self.save_log(f"Successfully generated code for ID {cwe_id}_{idx}_{model_type}")

                # Sleep to respect rate limits
                time.sleep(1)

        self.save_log(f"Generation completed. Results saved to {self.JSON_OUTPUT_DIR}/")
