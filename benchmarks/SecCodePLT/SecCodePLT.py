from benchmarks.BenchmarkRunner import BenchmarkRunner
import os
import json
from tqdm import tqdm

class SecCodePLT(BenchmarkRunner):
    """
    Benchmark SecCodePLT
    """
    def __init__(self):
        super().__init__()
        self.BENCHMARK_ROOT = os.path.join(self.PROJECT_ROOT, "benchmarks", "SecCodePLT")

        self.init_folder_structure()
        self.DATASET_FILE = os.path.join(self.BENCHMARK_ROOT, "data.json")


    def get_benchmark_root(self) -> str:
        return self.BENCHMARK_ROOT

    def generate_code(self, model: str):
        with open(self.DATASET_FILE, "r", encoding="utf-8") as f:
            dataset = json.load(f)

        model_type = model.split("/", 1)[0]

        self.save_log(f"Starting generation for {len(dataset)} prompts...")


        for task in tqdm(dataset):


            global_sample_id = task["global_sample_id"]
            cwe_id = task["cwe_id"]
            prompt = task["prompt"]

            out_json_path = os.path.join(self.JSON_OUTPUT_DIR, f"{global_sample_id}_{cwe_id}_{model_type}.json")

            if os.path.exists(out_json_path):
                self.save_log(f"[{global_sample_id + 1}/{len(dataset)}] Skipping ID {global_sample_id}_{cwe_id}_{model_type} (already done)")
                continue

            self.save_log(f"[{global_sample_id + 1}/{len(dataset)}] Generating code for ID {global_sample_id}_{cwe_id}_{model_type}")

            gen_code = self.request_llm(prompt, model)
            gen_code = self.clean_python_code(gen_code)

            if not gen_code:
                self.save_log(f"[{global_sample_id + 1}/{len(dataset)}] Failed to generate code for ID {global_sample_id}_{cwe_id}_{model_type}. Prompt: {prompt}")
                continue

            # Save JSON
            self.save_json_result(out_json_path, global_sample_id, prompt, gen_code, model)

            self.save_log(f"[{global_sample_id + 1}/{len(dataset)}] Successfully generated code for ID {global_sample_id}_{cwe_id}_{model_type}")

            self.save_log(f"Generation completed. Results saved to {self.JSON_OUTPUT_DIR}/")
