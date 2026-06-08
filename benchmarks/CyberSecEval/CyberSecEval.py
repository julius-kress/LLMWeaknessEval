from benchmarks.BenchmarkRunner import BenchmarkRunner
import os
import json
import time
from tqdm import tqdm

class CyberSecEval(BenchmarkRunner):
    """
    Benchmark CyberSecEval
    """
    def __init__(self):
        super().__init__()
        self.BENCHMARK_ROOT = os.path.join(self.PROJECT_ROOT, "benchmarks", "CyberSecEval")

        self.init_folder_structure()

    def get_benchmark_root(self) -> str:
        return self.BENCHMARK_ROOT

    def generate_code(self, model: str):
        with open(os.path.join(self.BENCHMARK_ROOT, "instruct-v2.json")) as f:
            data = json.load(f)

        python_prompts = []

        for x in data:
            if x.get("language") == "python":
                prompt = x["test_case_prompt"]
                python_prompts.append(prompt)

        print("Total python prompts: ", len(python_prompts))

        self.save_log(f"Starting generation for {len(python_prompts)} prompts...")
        model_type = model.split("/", 1)[0]

        for idx, prompt in enumerate(tqdm(python_prompts)):
            out_json_path = os.path.join(self.JSON_OUTPUT_DIR, f"{idx}_{model_type}.json")

            if os.path.exists(out_json_path):
                self.save_log(f"[{idx + 1}/{len(python_prompts)}] Skipping ID {idx}_{model_type} (already done)")
                continue

            self.save_log(f"[{idx + 1}/{len(python_prompts)}] Generating code for ID {idx}_{model_type}")

            gen_code = self.request_llm(prompt, model)
            gen_code = self.clean_python_code(gen_code)
            if not gen_code:
                self.save_log(
                    f"[{idx + 1}/{len(python_prompts)}] Failed to generate code for ID {idx}_{model_type}. Prompt: {prompt}")
                continue

            # Save JSON
            self.save_json_result(out_json_path, idx, prompt, gen_code, model)

            self.save_log(f"[{idx + 1}/{len(python_prompts)}] Successfully generated code for ID {idx}_{model_type}")

            # Sleep to respect rate limits
            #time.sleep(1)

        self.save_log(f"Generation completed. Results saved to {self.JSON_OUTPUT_DIR}/")

