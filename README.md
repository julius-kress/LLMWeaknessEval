# LLMWeaknessEval

## About this project
This project analyzes vulnerabilities in LLM generated program code. As it is still work in progress, for now only my temporary results are published. Later on I will add my code (when its a bit more cleaned up). The prompts I used are from different benchmarks `SecurityEval`, `LLMSecEval` and `CodeLMSec`. I currently check the generated code with `bandit` and `CodeQL`. 

(Links to all will be provided soon)

## The results

### [Raw results](./evaluation_results/raw_results)
These are the raw results I got from sending prompts to the LLMs and checking the generated code for vulnerabilities.
They consist of:
- `<benchmark>_result.csv`-files for each benchmark used, consists of the task id, prompt, generated code, model and results from vulnerability scanners
- `<benchmark>_result_pivoted.csv`-files for each benchmark used, consists of task id, prompt and the numbers of found CWEs for each model used
- `filtered_results.csv` contains all testcases from all benchmarks combined where all models generated vulnerable code

### [Processed results](./evaluation_results/processed_results)
These are some further processed results all based on the raw results. Because we are most interested in the tasks where all models produced vulnerable code I mainly focused on these cases in the following.
- `overall_summary.txt` Summary of all benchmarks how many models failed a task. Lists the prompts and found CWEs of the tasks where all models failed
- `<benchmark>_summary.txt` Overview of testcases and number of failed models (part of `overall_summary.txt`)
- `cwe_summary.txt` Total number of CWEs from tasks where all models failed
- `cwe_dependencies.csv` Analysis of co-occurring CWEs
- `feedback_results.csv` I fed back the found vulnerabilities to the models and told them to fix their code and these are the results
- `evaluated_feedback.txt` A comparison of the detected CWEs before and after I fed back the scanner output to the models
- `distribution_results.txt` A first attempt to find patterns and group all individual cases
