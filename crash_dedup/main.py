import os, shutil, multiprocessing
import re, json, itertools

import numpy as np
import pandas as pd

from typing import Callable, Optional, Iterable, Tuple, Dict, List, Set, Any

from os import path
from functools import reduce

# from kneebow.rotor import Rotor

from strsimpy.cosine import Cosine
from strsimpy.jaro_winkler import JaroWinkler
from strsimpy.sorensen_dice import SorensenDice
from strsimpy.normalized_levenshtein import NormalizedLevenshtein

from sklearn.cluster import DBSCAN

# from sklearn.neighbors import NearestNeighbors
from sklearn.feature_extraction.text import TfidfVectorizer

from matplotlib import pyplot as plt
from matplotlib_venn import venn2


def read(file: str, mode: str = "r") -> str:
    """Opens 'file' with 'mode', reads it and then returns its contents."""
    with open(file, mode) as fh:
        return fh.read()


def read_lines(file: str, mode: str = "r") -> List[str]:
    """Opens 'file' with 'mode', reads each line seperately and then returns its contents as list."""
    with open(file, mode) as fh:
        return [line for line in fh.readlines()]


def write(file: str, text: str, mode: str = "w") -> None:
    """Opens 'file' with 'mode' and writes 'text' to it."""
    with open(file, mode) as fh:
        fh.write(text)


def append(file: str, line: str) -> None:
    """Appends 'line' to 'file'."""
    write(file, line + os.linesep, "a")


def write_json(file: str, data: Dict) -> None:
    """Write 'data' into JSON 'file'."""
    write(file, json.dumps(data, indent=4))


def read_json(file: str) -> Dict:
    """Read data stored in JSON 'file'."""
    return json.loads(read(file))


def find_files(
    source_dir: str,
    file_exts: List[str] = None,
    exclude_dirs: List[str] = [],
    exclude_files: List[str] = [],
    recursive: bool = False,
) -> List[str]:
    def not_in(s: str, l: List[str]) -> bool:
        for v in l:
            if s.endswith(v):
                return False
        return True

    source_files = []

    if file_exts is None:
        pattern = re.compile(".*")
    else:
        pattern = re.compile("^.*\.({0})$".format("|".join(file_exts)))

    for root, _, files in os.walk(path.expanduser(source_dir)):
        if root not in exclude_dirs:
            for file in filter(lambda f: pattern.match(f), files):
                source_files.append(path.join(root, file))

        if not recursive:
            break

    return list(filter(lambda f: not_in(f, exclude_files), source_files))


def mkdir(dir_path: str, overwrite: bool = False) -> None:
    if not path.exists(dir_path):
        os.makedirs(dir_path)
    else:
        if overwrite:
            shutil.rmtree(dir_path)
            os.makedirs(dir_path)


targets = [
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
]
fuzzers = [
    "afl",
    "aflfast",
    "aflpp",
    "aflsmart",
    "fairfuzz",
    "honggfuzz",
    "mopt_afl",
    "mopt_aflpp",
]
seeds = ["02"]

crash_root = "/kaggle/working/fuzzer_crashes"
output_dir = "/kaggle/working/graphs"

mkdir(output_dir)

# Dictionary with functions to the respective similarity metrics
distance_metrics = {
    # "cosine"      : Cosine(2).distance,
    # "jaro-winkler": JaroWinkler().distance,
    "sorensen": SorensenDice(2).distance,
    "levenstein": NormalizedLevenshtein().distance,
}

epsilons = [0.10, 0.15]


def get_crash_clusters(
    crashes: List[str], epsilon: float, distance_metric: Callable[[str, str], float]
) -> List[int]:
    """
    Return cluster IDs of 'crashes' using DBSCAN with 'distance_metric'
    and 'epsilon'.
    """

    def metric(x, y):
        i, j = int(x[0]), int(y[0])
        return distance_metric(crashes[i], crashes[j])

    model = DBSCAN(metric=metric, min_samples=1, eps=epsilon, algorithm="brute")
    model.fit(np.arange(len(crashes)).reshape(-1, 1))

    return model.labels_
