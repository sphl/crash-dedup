"""
Main.
"""
import itertools
import multiprocessing
import os
import shutil
from dataclasses import dataclass
from functools import partial
from logging import INFO, basicConfig, getLogger
from os import path
from pathlib import Path as pathlib_Path
from re import compile as re_compile
from sys import exc_info, stdout
from typing import (
    AbstractSet,
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
OUTPUT_CSV_FILE_NAME = "fuzzer_crashes.csv"

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

# Dictionary with functions to the respective similarity metrics
DISTANCE_METRICS = {
    # "cosine"      : Cosine(2).distance,
    # "jaro-winkler": JaroWinkler().distance,
    "sorensen": SorensenDice(2).distance,
    "levenstein": NormalizedLevenshtein().distance,
}

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


def _get_file_content(file: pathlib_Path, n_frames: Optional[int]) -> str:
    if n_frames is None:
        file_content = file.read_text()
    else:
        with file.open() as f_read:
            file_content = " ".join(f_read.readlines()[:n_frames])
    return file_content


def read_crashes(
    fuzzer: _FUZZER_TYPES,
    crash_dir: pathlib_Path,
    max_no_of_crashes: int,
    n_frames: int = None,
) -> List[Crash]:
    """
     Read all (stack-)traces in 'crash_dir'.
    :param fuzzer:
    :param crash_dir:
    :param max_no_of_crashes:
    :param n_frames:
    :return:
    """
    get_file_content = partial(_get_file_content, n_frames=n_frames)
    crashes: List[Crash] = [
        {
            "fuzzer": fuzzer,
            "file_path": crash_dir,
            "file_content": get_file_content(file),
            "cluster_id": -1,  # ... will be set later
        }
        for file in find_files(crash_dir, file_exts=["trace"], recursive=True)
    ]
    result_list = [d for d in crashes if len(d["file_content"]) > 0]
    if max_no_of_crashes == -1:
        return result_list
    else:
        return result_list[:max_no_of_crashes]


def not_in(s: str, black_list: List[str]) -> bool:
    """

    :param s:
    :param black_list:
    :return:
    """
    for v in black_list:
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
) -> List[pathlib_Path]:
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

    extension_matcher = create_matcher_for_file_extensions(file_exts)
    not_in_matcher = partial(not_in, black_list=exclude_files)
    if recursive:
        source_files = [
            path.join(root, file)
            for root, _, files in os.walk(source_dir)
            if root not in exclude_dirs
            for file in [f for f in files if extension_matcher(f)]
        ]
    else:
        source_files = [f for f in source_dir.iterdir() if extension_matcher(f.name)]
    return [pathlib_Path(f) for f in source_files if not_in_matcher(f)]


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

    _LOGGER.info("Start DBSCAN")
    model = DBSCAN(metric=_metric, min_samples=1, eps=epsilon, algorithm="brute")
    model.fit(np.arange(len(crashes)).reshape(-1, 1))
    _LOGGER.info("End DBSCAN")
    return model.labels_


def to_string(c: Iterable, sep: str = ",") -> str:
    """

    :param c:
    :param sep:
    :return:
    """
    return sep.join([str(v) for v in c])


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


@dataclass()
class Record(object):
    """
    Record.
    """

    target: _TARGET_TYPES
    fuzzer1: _FUZZER_TYPES
    fuzzer2: _FUZZER_TYPES
    seed: str
    metric: _METRIC_TYPES
    epsilon: float
    n_frames: Optional[int]
    cluster_ids1: AbstractSet[int]
    cluster_ids2: AbstractSet[int]
    shared_cluster_ids: AbstractSet[int]

    def to_dict(self) -> Dict[str, Any]:
        """

        :return:
        """
        return {
            "Target": self.target,
            "Fuzzer 1": self.fuzzer1,
            "Fuzzer 2": self.fuzzer2,
            "Seed": self.seed,
            "Metric": self.metric,
            "Epsilon (DBSCAN)": self.epsilon,
            "#Frames (Stacktraces)": "all" if self.n_frames is None else self.n_frames,
            "#Bugs (Fuzzer 1)": len(self.cluster_ids1),
            "#Bugs (Fuzzer 2)": len(self.cluster_ids2),
            "Cluster IDs (Fuzzer 1)": to_string(self.cluster_ids1),
            "Cluster IDs (Fuzzer 2)": to_string(self.cluster_ids1),
            "#Unique Bugs (Fuzzer 1)": len(self.cluster_ids1 - self.shared_cluster_ids),
            "#Unique Bugs (Fuzzer 2)": len(self.cluster_ids2 - self.shared_cluster_ids),
            "#Shared Bugs (Fuzzer 1 & 2)": len(self.shared_cluster_ids),
        }


def crash_analysis_worker(
    crash_root: pathlib_Path,
    target: _TARGET_TYPES,
    fuzzer1: _FUZZER_TYPES,
    fuzzer2: _FUZZER_TYPES,
    seed: str,
    metric: Dict,
    epsilon: float,
    n_frames: int,
    output_dir: pathlib_Path,
    draw_venn: bool,
    max_no_of_crashes: int,
) -> Record:
    """
    Worker routine which (1) reads and clusters the crash-stacktraces of both
    fuzzers, (2) draws a Venn diagram (if 'draw_venn' is set to true) and (3)
    finally returns some key figures of the crash analysis.
    """
    crashes1 = read_crashes(
        fuzzer1,
        get_crash_dir(crash_root, fuzzer1, target, seed),
        max_no_of_crashes,
        n_frames,
    )
    crashes2 = read_crashes(
        fuzzer2,
        get_crash_dir(crash_root, fuzzer2, target, seed),
        max_no_of_crashes,
        n_frames,
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
    return Record(
        target,
        fuzzer1,
        fuzzer2,
        seed,
        metric["name"],
        epsilon,
        n_frames,
        cluster_ids1,
        cluster_ids2,
        cluster_ids1 & cluster_ids2,
    )


def _starter(t: Tuple) -> Record:
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
@option(
    "--max-no-of-crashes-per-fuzzer",
    "-M",
    type=int,
    help="You can limit the amount of crashes.",
    default=-1,
)
@option(
    "--overwrite",
    "-O",
    is_flag=True,
    help="If this flag is passed, the script will clean the output directory.",
    default=False,
)
@main_group.command()
def find_crash_clusters(
    distance_metric: _METRIC_TYPES,
    input_directory: str,
    output_directory: str,
    epsilon: Optional[float],
    fuzzer: Sequence[_FUZZER_TYPES],
    target_program: Sequence[_TARGET_TYPES],
    max_no_of_crashes_per_fuzzer: int,
    overwrite: bool,
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

    if output_path.is_dir():
        if overwrite:
            _LOGGER.warning(f"Clean {output_path} and create again.")
            shutil.rmtree(output_path)
            output_path.mkdir()
        else:
            _LOGGER.info(f"{output_path} already exists. Adding stuff.")
    else:
        _LOGGER.info(f"Create {output_path}.")
        output_path.mkdir()

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
                            "function": DISTANCE_METRICS[distance_metric],
                        },
                        epsilon,
                        N_FRAMES,
                        output_path,
                        True,
                        max_no_of_crashes_per_fuzzer,
                    )
                )
    with multiprocessing.Pool() as pool:
        fuzzer_crashes: List[Record] = list(pool.map(_starter, worker_inputs))

    df = pd.DataFrame([c.to_dict() for c in fuzzer_crashes])
    output_file = output_path.joinpath(OUTPUT_CSV_FILE_NAME)
    df.to_csv(output_file, sep=";")


if __name__ == "__main__":
    main_group()
