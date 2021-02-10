# Crash Dedup

## Usage

```bash
$ crash-dedup --help
Usage: crash-dedup [OPTIONS] COMMAND [ARGS]...

  All commands.

Options:
  --version  Version
  --help     Show this message and exit.

Commands:
  find-crash-clusters  Find clusters of crashes from different programs,...
```

### find-crash-clusters

```bash
$ crash-dedup find-crash-clusters --help
Usage: crash-dedup find-crash-clusters [OPTIONS]

  Find clusters of crashes from different programs, different fuzzers,
  different metrics, different epsilons.

Options:
  -O, --overwrite                 If this flag is passed, the script will
                                  clean the output directory.

  -M, --max-no-of-crashes-per-fuzzer INTEGER
                                  You can limit the amount of crashes.
  -t, --target-program [ffmpeg|gif2png|jsoncpp|freetype2|jasper|libpcap|zlib|readelf|objdump|size|strings|nm]
                                  All programs you want to test. You can pass
                                  multiple programs.

  -f, --fuzzer [afl|aflfast|aflpp|aflsmart|fairfuzz|honggfuzz|mopt_afl|mopt_aflpp]
                                  All the fuzzers you want to test. You can
                                  pass multiple fuzzers.

  -e, --epsilon FLOAT             The epsilon.
  -o, --output-directory DIRECTORY
                                  The directory in which the script stores the
                                  result.

  -i, --input-directory DIRECTORY
                                  The directory with the crashes.
  -m, --distance-metric [sorensen|levenstein]
                                  The distance metric the tool should use.
  --help                          Show this message and exit.
```

Example

```bash
crash-dedup find-crash-clusters --input-directory /path/to/fuzzer_crashes --fuzzer afl --fuzzer aflfast --target-program gif2png --distance-metric levenstein --max-no-of-crashes-per-fuzzer 50
```
