from typing import Mapping, Sequence

from strsimpy import NormalizedLevenshtein, SorensenDice

OUTPUT_CSV_FILE_NAME = "fuzzer_crashes.csv"
DEFAULT_EPSILONS: Mapping[str, float] = {"sorensen": 0.1, "levenstein": 0.15}
TARGETS: Sequence[str] = (
    "ffmpeg",
    "gif2png",
    "jsoncpp",
    "freetype2",
    "jasper",
    "libpcap",
    "zlib",
    "readelf",
    "objdump",
    "size",
    "strings",
    "nm",
)
FUZZERS: Sequence[str] = (
    "afl",
    "aflfast",
    "aflpp",
    "aflsmart",
    "fairfuzz",
    "honggfuzz",
    "mopt_afl",
    "mopt_aflpp",
)
N_FRAMES = 3
SEEDS = ["02"]
"""
Dictionary with functions to the respective similarity metrics
"""
DISTANCE_METRICS = {
    # "cosine"      : Cosine(2).distance,
    # "jaro-winkler": JaroWinkler().distance,
    "sorensen": SorensenDice(2).distance,
    "levenstein": NormalizedLevenshtein().distance,
}
