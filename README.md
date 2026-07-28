# crash-dedup

Deduplicates sanitizer-enforced program crashes by grouping inputs that produce identical stack traces, helping to efficiently identify distinct bugs.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Development](#development)

## Requirements

- Python 3.10+
- [Poetry](https://python-poetry.org/docs/#installation) (Python package and dependency manager)

## Installation

1. Clone the repository and navigate to the project directory.

2. Install dependencies:

    ```bash
    poetry install
    ```

## Configuration

Review the [`config.yaml`](config.yaml) file for input file filtering options (e.g., excluding files by specific name patterns).

## Usage

To view all available commands and options:

```bash
poetry run crash-dedup --help
```

### Run Crash Deduplication

Runs a sanitizer-instrumented target program against a set of input files and deduplicates the resulting crashes based on their stack traces. Add `--parallel` to run the deduplication concurrently:

```bash
poetry run crash-dedup run \
    --command "<TARGET_EXECUTABLE> @@" \
    --input <CRASH_INPUTS_DIR> \
    --output <OUTPUT_DIR> \
    --frames 5 \
    --parallel
```

> **Note:** Use `@@` in the command string as a placeholder for the input file path.

Alternatively, if you already have sanitizer output files on disk, you can skip program execution and pass them directly:

```bash
poetry run crash-dedup run \
    --sanitizer-dir <SANITIZER_OUTPUTS_DIR> \
    --output <OUTPUT_DIR> \
    --frames 5
```

The output is a CSV summary file written to the directory specified by `--output` (e.g., `<OUTPUT_DIR>/summary_nf5.csv` when `--frames 5` is used). Each row represents one crash input, grouped under a `bug_id` shared by inputs that deduplicate to the same stack trace.

**Example Output:**

```csv
bug_id,n_dedup_frames,consider_filepaths,consider_lines,input_file,sanitizer,vuln_type,stack_trace,n_total_frames
0,5,false,false,/path/to/file01,addresssanitizer,segv,#0:outputscript.c:outputSWF_TEXT_RECORD:1429=...,5
0,5,false,false,/path/to/file03,addresssanitizer,segv,#0:outputscript.c:outputSWF_TEXT_RECORD:1429=...,5
1,5,false,false,/path/to/file02,addresssanitizer,segv,#0:decompile.c:OpCode:868=...,9
```

In this example, the input files `file01` and `file03` share `bug_id=0` because their top-5 stack frames are identical, while `file02` produces a distinct crash (`bug_id=1`).

By default, deduplication is based solely on function names. Use `--consider-filepaths` and/or `--consider-lines` to include source file paths and line numbers in the comparison.

### Merge Deduplication Results

Merges multiple summary CSV files produced by the `run` command into a single deduplicated summary:

```bash
poetry run crash-dedup merge \
    --input <INPUT_CSV_1> \
    --input <INPUT_CSV_2> \
    --output <OUTPUT_CSV>
```

## Development

### Code Quality and Testing

- Format the code:

    ```bash
    poetry run isort src
    poetry run black src
    ```

- Run static checks and linting:

    ```bash
    poetry run mypy src
    poetry run bandit --recursive src
    ```

- Run tests:

    ```bash
    poetry run pytest
    ```

- Run tests with coverage:

    ```bash
    poetry run pytest --cov=crash_dedup
    ```
