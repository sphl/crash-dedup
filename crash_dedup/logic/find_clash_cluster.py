"""
Find clash in cluster!
"""
from itertools import combinations
from logging import getLogger
from multiprocessing import Pool
from os import path
from pathlib import Path
from sys import exc_info
from typing import Callable, Dict, List, Sequence, Set, Tuple

import numpy as np
import pandas as pd

from crash_dedup.classes.crash import Crash
from crash_dedup.classes.helper_types import FUZZER_TYPES, METRIC_TYPES, TARGET_TYPES
from crash_dedup.classes.record import Record
from crash_dedup.constants import (
    DISTANCE_METRICS,
    N_FRAMES,
    OUTPUT_CSV_FILE_NAME,
    SEEDS,
)
from crash_dedup.logic.draw_venn_diagram import draw_venn_diagram
from crash_dedup.logic.read_crashes import get_crash_dir, read_crashes
from sklearn.cluster import DBSCAN

_LOGGER = getLogger(__name__)


def find_clash_cluster_internal(
    distance_metric: METRIC_TYPES,
    epsilon: float,
    fuzzers: Sequence[FUZZER_TYPES],
    input_path: Path,
    max_no_of_crashes_per_fuzzer: int,
    output_path: Path,
    targets: Sequence[TARGET_TYPES],
) -> None:
    """

    :param distance_metric:
    :param epsilon:
    :param fuzzers:
    :param input_path:
    :param max_no_of_crashes_per_fuzzer:
    :param output_path:
    :param targets:
    :return:
    """
    worker_inputs = []
    for target in targets:
        for fuzzer1, fuzzer2 in combinations(fuzzers, 2):
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
    with Pool() as pool:
        fuzzer_crashes: List[Record] = list(pool.map(_starter, worker_inputs))
    df = pd.DataFrame([c.to_dict() for c in fuzzer_crashes])
    output_file = output_path.joinpath(OUTPUT_CSV_FILE_NAME)
    df.to_csv(output_file, sep=";")


def _filter_cluster_ids(fuzzer: FUZZER_TYPES, crashes: List[Crash]) -> Set[int]:
    """

    :param fuzzer:
    :param crashes:
    :return:
    """
    return set(crash["cluster_id"] for crash in crashes if crash["fuzzer"] == fuzzer)


def _get_diff_crash_cov(
    fuzzer1: FUZZER_TYPES,
    crashes1: List[Crash],
    fuzzer2: FUZZER_TYPES,
    crashes2: List[Crash],
    epsilon: float,
    distance_metric: Callable[[str, str], float],
) -> Dict:
    """
    Return unique crash (resp. cluster) IDs in 'crashes1' and 'crashes2'.
    """

    all_crashes = crashes1 + crashes2

    assert len(all_crashes) > 0

    clusters = _get_crash_clusters(
        [crash["file_content"] for crash in all_crashes], epsilon, distance_metric
    )

    assert len(all_crashes) == len(clusters)

    for i in range(len(all_crashes)):
        all_crashes[i]["cluster_id"] = clusters[i]

    return {
        fuzzer1: _filter_cluster_ids(fuzzer1, all_crashes),
        fuzzer2: _filter_cluster_ids(fuzzer2, all_crashes),
    }


def _get_crash_clusters(
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


def _crash_analysis_worker(
    crash_root: Path,
    target: TARGET_TYPES,
    fuzzer1: FUZZER_TYPES,
    fuzzer2: FUZZER_TYPES,
    seed: str,
    metric: Dict,
    epsilon: float,
    n_frames: int,
    output_dir: Path,
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
            cluster_dict = _get_diff_crash_cov(
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
    return _crash_analysis_worker(*t)
