# LLMWeaknessEval

---

## About this project
This project analyzes vulnerabilities in LLM generated program code.
As it is still work in progress, for now only my temporary code and results are published.
The prompts I used, are from different benchmarks [SecurityEval](https://github.com/s2e-lab/SecurityEval), [LLMSecEval](https://github.com/tuhh-softsec/LLMSecEval) and [CodeLMSec](https://github.com/codelmsec/codelmsec).
I currently check the generated code with [Bandit](https://bandit.readthedocs.io/en/latest/) and [CodeQL](https://codeql.github.com/) for vulnerabilities. 

## Project structure
This project aims to prompt different LLMs, let them generate code and check it for security vulnerabilities.
The prompts are taken from the benchmarks mentioned above. 
To run this project make sure to:
1. Clone the project
2. (Optional but recommended) Set up your virtual environment
3. Install all requirements from `requirements.txt` e.g. with `pip install -r requirements.txt`
4. Set your API-Key for the LLMs (I used [OpenRouter](https://openrouter.ai/)) like this: `export LLM_API_KEY="sk-or-v1-1234567890abcdef`
5. Run `main.py` to run all benchmarks (may take some time)
6. Run more scripts from `utils` to further process the results

In the following there is more explanation on the project structure and additional scripts to process the data.
Note that the project is still work in progress, things might change.

### Benchmarks
Contains all the benchmarks where the code is generated from. 
In `BenchmarkRunner.py` is an abstract base class which provide some sort of python interface for how to use the benchmarks.
The other subfolders contain implementations for each individual benchmark that is used. At this point thanks to a predecessor of this work [Anshul](https://github.com/breath24/Anshul) who also delt with the benchmarks and where I got the benchmarks from.

### Evaluation results
Here are the results saved, I uploaded a run of the results I got and split it into raw and processed results.
#### [Raw results](./evaluation_results/raw_results)
These are the raw results I got from sending prompts to the LLMs and checking the generated code for vulnerabilities.
They consist of:
- `<benchmark>_result.csv`-files for each benchmark used, consists of the task id, prompt, generated code, model and results from vulnerability scanners
- `<benchmark>_result_pivoted.csv`-files for each benchmark used, consists of task id, prompt and the numbers of found CWEs for each model used
- `filtered_results.csv` contains all testcases from all benchmarks combined where all models generated vulnerable code

#### [Processed results](./evaluation_results/processed_results)
These are some further processed results all based on the raw results. Because we are most interested in the tasks where all models produce vulnerable code, I mainly focused on these cases in the following.
- `overall_summary.txt` Summary of all benchmarks and how many models failed a task. Lists prompts and found CWEs of the tasks where all models failed
- `<benchmark>_summary.txt` Overview of testcases and number of failed models (part of `overall_summary.txt`)
- `cwe_summary.txt` Total number of CWEs from tasks where all models failed
- `cwe_dependencies.csv` Analysis of co-occurring CWEs
- `feedback_results.csv` I fed back the found vulnerabilities to the models and told them to fix their code and these are the results
- `evaluated_feedback.txt` A comparison of the detected CWEs before and after I fed back the scanner output to the models
- `distribution_results.txt` A first attempt to find patterns and group all individual cases

#### More analysis
In files [analysis.ipynb](utils/analysis.ipynb) there is some general analysis by Parsa and in [manual_analysis](utils/manual_analysis.ipynb) is analysis regarding the vulnerability categories. It involves the results gathered from the manual tagging.

#### Manual tagging
I manually tagged all tasks where all models failed to generate secure code and uploaded them into [Manual results](evaluation_results/manual_checks).

### Utils
This folder contains some python scripts to further process the collected data (prompts, generated code, detected vulnerabilities, ...)
The individual scripts have the following purposes:
- `check_cwe_dependencies.py` processes the data to extract dependencies between individual detected CWEs of the testcases where all models failed to produce secure code.
- `cwe_counter.py` counts all appearances of CWEs from test cases where all models failed to produce secure code.
- `distribution_of_weaknesses.py` aims to group all cases into categories of weaknesses to find patterns in a first attempt. Also generates pivoted result files where results are portrayed different with focus on CWE comparison between models.
- `evaluation_utils.py` is not a script but a utils file which provides functionality for running the vulnerability scanners as well as cleaning their output.
- `feedback_scanner_output.py` takes the prompts, generated code and found vulnerabilities from old runs and feeds them back to the LLMs to fix those weaknesses. It evaluates how effective this approach was.
