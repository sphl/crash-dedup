"""
Draw!
"""
from typing import Set

from matplotlib import pyplot as plt

from matplotlib_venn import venn2


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
