import os
import time
from datasets import load_dataset
from tqdm import tqdm

from benchmarks.BenchmarkRunner import BenchmarkRunner

class SecurityEval(BenchmarkRunner):
    """
    Benchmark SecurityEval
    """
    def __init__(self):
        super().__init__()
        self.BENCHMARK_ROOT = os.path.join(self.PROJECT_ROOT, "benchmarks", "SecurityEval")

        self.init_folder_structure()
        self.dataset = load_dataset("s2e-lab/SecurityEval", split="train")


    # Override
    def get_benchmark_root(self):
        return self.BENCHMARK_ROOT

    # Override
    def generate_code(self, model: str):

        self.save_log(f"Starting generation for {len(self.dataset)} prompts...")

        model_type = model.split("/", 1)[0]

        for idx, item in enumerate(tqdm(self.dataset)):

            id_ = item["ID"]
            id_ = id_.removesuffix(".py")
            id_ = id_ + "_py"

            prompt = item["Prompt"]
            out_json_path = os.path.join(self.JSON_OUTPUT_DIR, f"{id_}_{model_type}.json")

            if os.path.exists(out_json_path):
                self.save_log(f"[{idx + 1}/{len(self.dataset)}] Skipping ID {id_}_{model_type} (already done)")
                continue

            self.save_log(f"[{idx + 1}/{len(self.dataset)}] Generating code for ID {id_}_{model_type}")

            gen_code = self.request_llm(prompt, model)
            gen_code = self.clean_python_code(gen_code)
            if not gen_code:
                self.save_log(f"[{idx + 1}/{len(self.dataset)}] Failed to generate code for ID {id_}_{model_type}. Prompt: {prompt}")
                continue

            # Save JSON
            self.save_json_result(out_json_path, id_, prompt, gen_code, model)

            self.save_log(f"[{idx + 1}/{len(self.dataset)}] Successfully generated code for ID {id_}_{model_type}")

            # Sleep to respect rate limits
            time.sleep(1)

        self.save_log(f"Generation completed. Results saved to {self.JSON_OUTPUT_DIR}/")


