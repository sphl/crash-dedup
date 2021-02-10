"""
Record.
"""
from dataclasses import dataclass
from typing import AbstractSet, Any, Dict, Iterable, Optional

from crash_dedup.classes.helper_types import FUZZER_TYPES, METRIC_TYPES, TARGET_TYPES


def to_string(c: Iterable, sep: str = ",") -> str:
    """

    :param c:
    :param sep:
    :return:
    """
    return sep.join([str(v) for v in c])


@dataclass()
class Record(object):
    """
    Record.
    """

    target: TARGET_TYPES
    fuzzer1: FUZZER_TYPES
    fuzzer2: FUZZER_TYPES
    seed: str
    metric: METRIC_TYPES
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
