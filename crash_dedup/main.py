"""
Main.
"""
import itertools
import json
import multiprocessing
import os
import shutil
from logging import INFO, basicConfig, getLogger
from os import path
from pathlib import Path as pathlib_Path
from re import compile as re_compile
from sys import exc_info, stdout
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Pattern,
    Sequence,
    Set,
    Tuple,
    TypedDict,
)

import numpy as np
import pandas as pd
from click import Choice
from click import Path as click_Path
from click import echo, group, option
from matplotlib import pyplot as plt

from crash_dedup import __version__
from matplotlib_venn import venn2
from sklearn.cluster import DBSCAN
from strsimpy.normalized_levenshtein import NormalizedLevenshtein
from strsimpy.sorensen_dice import SorensenDice

# from kneebow.rotor import Rotor
# from sklearn.neighbors import NearestNeighbors

basicConfig(
    format="%(levelname)s: %(asctime)s: %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=INFO,
    stream=stdout,
)

_LOGGER = getLogger(__name__)

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

_FUZZER_TYPES = Literal[
    "afl",
    "aflfast",
    "aflpp",
    "aflsmart",
    "fairfuzz",
    "honggfuzz",
    "mopt_afl",
    "mopt_aflpp",
]
_METRIC_TYPES = Literal["sorensen", "levenstein"]
_TARGET_TYPES = Literal[
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


class Crash(TypedDict):
    """
    Crash.
    """

    fuzzer: _FUZZER_TYPES
    file_path: str
    file_content: str
    cluster_id: int


def read_crashes(
    fuzzer: str, crash_dir: pathlib_Path, n_frames: int = None
) -> List[Crash]:
    """Read all (stack-)traces in 'crash_dir'."""

    def get_file_content(file: str) -> str:
        if n_frames is None:
            file_content = read(file)
        else:
            file_content = " ".join(read_lines(file)[:n_frames])

        return file_content

    crashes: List[Crash] = [
        {
            "fuzzer": fuzzer,
            "file_path": crash_dir,
            "file_content": get_file_content(file),
            "cluster_id": -1,  # ... will be set later
        }
        for file in find_files(crash_dir, file_exts=["trace"], recursive=True)
    ]

    return list(filter(lambda d: len(d["file_content"]) > 0, crashes))


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


def not_in(s: str, l: List[str]) -> bool:
    for v in l:
        if s.endswith(v):
            return False
    return True


def create_matcher_for_file_extensions(
    file_extensions: Optional[List[str]],
) -> Callable[[str], bool]:
    """

    :param file_extensions:
    :return:
    """
    patterns: List[Pattern] = []
    if file_extensions is None:
        patterns.append(re_compile(".*"))
    else:
        patterns = [
            re_compile(rf"^.*\.({file_extension})$")
            for file_extension in file_extensions
        ]

    def _matches(file_name: str) -> bool:
        for pattern in patterns:
            if pattern.match(file_name):
                return True
        return False

    return _matches


def find_files(
    source_dir: pathlib_Path,
    file_exts: Optional[List[str]] = None,
    exclude_dirs: Optional[List[str]] = None,
    exclude_files: Optional[List[str]] = None,
    recursive: bool = False,
) -> List[str]:
    """

    :param source_dir:
    :param file_exts:
    :param exclude_dirs:
    :param exclude_files:
    :param recursive:
    :return:
    """
    if exclude_files is None:
        exclude_files = []
    if exclude_dirs is None:
        exclude_dirs = []

    source_files = []
    extension_matcher = create_matcher_for_file_extensions(file_exts)
    if recursive:
        source_files = [
            path.join(root, file)
            for root, _, files in os.walk(source_dir)
            if root not in exclude_dirs
            for file in [f for f in files if extension_matcher(f)]
        ]
    else:
        source_files = [f for f in source_dir.iterdir() if extension_matcher(f.name)]
    return list(filter(lambda f: not_in(f, exclude_files), source_files))


def mkdir(dir_path: str, overwrite: bool = False) -> None:
    if not path.exists(dir_path):
        os.makedirs(dir_path)
    else:
        if overwrite:
            shutil.rmtree(dir_path)
            os.makedirs(dir_path)


# Dictionary with functions to the respective similarity metrics
distance_metrics = {
    # "cosine"      : Cosine(2).distance,
    # "jaro-winkler": JaroWinkler().distance,
    "sorensen": SorensenDice(2).distance,
    "levenstein": NormalizedLevenshtein().distance,
}


def draw_venn_diagram(
    fuzzer1: str,
    cluster_ids1: Set[int],
    fuzzer2: str,
    cluster_ids2: Set[int],
    venn_title: str,
    venn_file: str,
) -> None:
    """
    Draw Venn diagram showing if 'fuzzer1' and 'fuzzer2' detected
    similar / different bugs.
    """
    plt.figure()
    plt.title(venn_title)

    venn2([cluster_ids1, cluster_ids2], set_labels=(fuzzer1, fuzzer2))

    plt.savefig(venn_file)


def filter_cluster_ids(fuzzer: _FUZZER_TYPES, crashes: List[Crash]) -> Set[int]:
    """

    :param fuzzer:
    :param crashes:
    :return:
    """
    return set(crash["cluster_id"] for crash in crashes if crash["fuzzer"] == fuzzer)


def get_diff_crash_cov(
    fuzzer1: _FUZZER_TYPES,
    crashes1: List[Crash],
    fuzzer2: _FUZZER_TYPES,
    crashes2: List[Crash],
    epsilon: float,
    distance_metric: Callable[[str, str], float],
) -> Dict:
    """
    Return unique crash (resp. cluster) IDs in 'crashes1' and 'crashes2'.
    """

    all_crashes = crashes1 + crashes2

    assert len(all_crashes) > 0

    clusters = get_crash_clusters(
        [crash["file_content"] for crash in all_crashes], epsilon, distance_metric
    )

    assert len(all_crashes) == len(clusters)

    for i in range(len(all_crashes)):
        all_crashes[i]["cluster_id"] = clusters[i]

    return {
        fuzzer1: filter_cluster_ids(fuzzer1, all_crashes),
        fuzzer2: filter_cluster_ids(fuzzer2, all_crashes),
    }


def get_crash_clusters(
    crashes: List[str], epsilon: float, distance_metric: Callable[[str, str], float]
) -> List[int]:
    """
    Return cluster IDs of 'crashes' using DBSCAN with 'distance_metric'
    and 'epsilon'.
    """

    def _metric(x, y):
        i, j = int(x[0]), int(y[0])
        return distance_metric(crashes[i], crashes[j])

    model = DBSCAN(metric=_metric, min_samples=1, eps=epsilon, algorithm="brute")
    model.fit(np.arange(len(crashes)).reshape(-1, 1))

    return model.labels_


def get_crash_dir(
    crash_root: pathlib_Path, fuzzer: _FUZZER_TYPES, target: str, seed: str
) -> pathlib_Path:
    """

    :param crash_root:
    :param fuzzer:
    :param target:
    :param seed:
    :return:
    """
    return pathlib_Path(
        path.join(
            crash_root,
            fuzzer,
            target,
            "stacktraces" if seed == "-" else path.join("stacktraces", f"seed_{seed}"),
        )
    )


def crash_analysis_worker(
    crash_root: pathlib_Path,
    target: str,
    fuzzer1: _FUZZER_TYPES,
    fuzzer2: _FUZZER_TYPES,
    seed: str,
    metric: Dict,
    epsilon: float,
    n_frames: int,
    output_dir: pathlib_Path,
    draw_venn: bool,
) -> Dict:
    """
    Worker routine which (1) reads and clusters the crash-stacktraces of both
    fuzzers, (2) draws a Venn diagram (if 'draw_venn' is set to true) and (3)
    finally returns some key figures of the crash analysis.
    """

    def to_string(c: Iterable, sep: str = ",") -> str:
        return sep.join([str(v) for v in c])

    crashes1 = read_crashes(
        fuzzer1, get_crash_dir(crash_root, fuzzer1, target, seed), n_frames
    )
    crashes2 = read_crashes(
        fuzzer2, get_crash_dir(crash_root, fuzzer2, target, seed), n_frames
    )

    if len(crashes1 + crashes2) == 0:
        cluster_ids1 = set()
        cluster_ids2 = set()
    else:
        try:
            cluster_dict = get_diff_crash_cov(
                fuzzer1, crashes1, fuzzer2, crashes2, epsilon, metric["function"]
            )

            cluster_ids1 = cluster_dict[fuzzer1]
            cluster_ids2 = cluster_dict[fuzzer2]

            if draw_venn:
                venn_title = f"Unique bugs found in {target} by {fuzzer1} and/or {fuzzer2}\n(metric: {metric['name']}, epsilon (DBSCAN): {epsilon:.2f})"
                venn_file = path.join(
                    output_dir,
                    f"venn_{target}_{fuzzer1}-{fuzzer2}{'_' if seed == '-' else f'_s{seed}_'}{metric['name']}_eps{epsilon:.2f}.svg",
                )

                draw_venn_diagram(
                    fuzzer1, cluster_ids1, fuzzer2, cluster_ids2, venn_title, venn_file
                )
        except:
            print("Unexpected error:", exc_info()[0])

            cluster_ids1 = set()
            cluster_ids2 = set()

    shared_cluster_ids = cluster_ids1 & cluster_ids2

    return {
        "Target": target,
        "Fuzzer 1": fuzzer1,
        "Fuzzer 2": fuzzer2,
        "Seed": seed,
        "Metric": metric["name"],
        "Epsilon (DBSCAN)": epsilon,
        "#Frames (Stacktraces)": "all" if n_frames is None else n_frames,
        "#Bugs (Fuzzer 1)": len(cluster_ids1),
        "#Bugs (Fuzzer 2)": len(cluster_ids2),
        "Cluster IDs (Fuzzer 1)": to_string(cluster_ids1),
        "Cluster IDs (Fuzzer 2)": to_string(cluster_ids1),
        "#Unique Bugs (Fuzzer 1)": len(cluster_ids1 - shared_cluster_ids),
        "#Unique Bugs (Fuzzer 2)": len(cluster_ids2 - shared_cluster_ids),
        "#Shared Bugs (Fuzzer 1 & 2)": len(shared_cluster_ids),
    }


def _starter(t: Tuple) -> Dict:
    return crash_analysis_worker(*t)


def print_version(ctx, _: Any, value: Any) -> None:
    """

    :param ctx:
    :param _:
    :param value:
    :return:
    """
    if not value or ctx.resilient_parsing:
        return
    echo(__version__)
    ctx.exit()


@group()
@option(
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Version",
)
def main_group() -> None:
    """
    All commands.
    """
    pass


@option(
    "--distance-metric",
    "-m",
    type=Choice(["sorensen", "levenstein"]),
    default="sorensen",
    help="The distance metric the tool should use.",
)
@option(
    "--input-directory",
    "-i",
    type=click_Path(exists=True, file_okay=False),
    prompt=True,
    help="The directory with the crashes.",
)
@option(
    "--output-directory",
    "-o",
    type=click_Path(writable=True, file_okay=False),
    help="The directory in which the script stores the result.",
    prompt=True,
)
@option("--epsilon", "-e", type=float, default=None, help="The epsilon.")
@option(
    "--fuzzer",
    "-f",
    type=Choice(FUZZERS),
    multiple=True,
    help="All the fuzzers you want to test.",
    default=(),
)
@option(
    "--target-program",
    "-t",
    type=Choice(TARGETS),
    multiple=True,
    help="All programms you want to test",
    default=(),
)
@main_group.command()
def find_crash_clusters(
    distance_metric: _METRIC_TYPES,
    input_directory: str,
    output_directory: str,
    epsilon: Optional[float],
    fuzzer: Sequence[_FUZZER_TYPES],
    target_program: Sequence[_TARGET_TYPES],
) -> None:
    """

    :return:
    """
    if epsilon is None:
        epsilon = DEFAULT_EPSILONS.get(distance_metric)
        if epsilon is None:
            _LOGGER.critical(f"{distance_metric} is not a known metric.")
            return
    fuzzers: Sequence[_FUZZER_TYPES] = FUZZERS if len(fuzzer) == 0 else fuzzer
    targets: Sequence[_TARGET_TYPES] = (
        TARGETS if len(target_program) == 0 else target_program
    )
    input_path = pathlib_Path(input_directory)
    output_path = pathlib_Path(output_directory)
    _LOGGER.info("hi")
    worker_inputs = []

    for target in targets:
        for fuzzer1, fuzzer2 in itertools.combinations(fuzzers, 2):
            for seed in SEEDS:
                worker_inputs.append(
                    (
                        input_path,
                        target,
                        fuzzer1,
                        fuzzer2,
                        seed,
                        {
                            "name": distance_metric,
                            "function": distance_metrics[distance_metric],
                        },
                        epsilon,
                        N_FRAMES,
                        output_path,
                        True,
                    )
                )
    with multiprocessing.Pool() as pool:
        fuzzer_crashes = list(pool.map(_starter, worker_inputs))

    df = pd.DataFrame(fuzzer_crashes)
    output_file = output_path.joinpath("fuzzer_crashes.csv")
    df.to_csv(output_file, sep=";")


if __name__ == "__main__":
    main_group()
