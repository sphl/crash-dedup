"""
Main.
"""
from logging import INFO, basicConfig, getLogger
from pathlib import Path as pathlib_Path
from shutil import rmtree
from sys import stdout
from typing import Any, Optional, Sequence

from click import Choice
from click import Path as click_Path
from click import echo, group, option

from crash_dedup import __version__
from crash_dedup.classes.helper_types import FUZZER_TYPES, METRIC_TYPES, TARGET_TYPES
from crash_dedup.constants import DEFAULT_EPSILONS, FUZZERS, TARGETS
from crash_dedup.logic.find_clash_cluster import find_clash_cluster_internal

basicConfig(
    format="%(levelname)s: %(asctime)s: %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=INFO,
    stream=stdout,
)

_LOGGER = getLogger(__name__)


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
    distance_metric: METRIC_TYPES,
    input_directory: str,
    output_directory: str,
    epsilon: Optional[float],
    fuzzer: Sequence[FUZZER_TYPES],
    target_program: Sequence[TARGET_TYPES],
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
    fuzzers: Sequence[FUZZER_TYPES] = FUZZERS if len(fuzzer) == 0 else fuzzer
    targets: Sequence[TARGET_TYPES] = (
        TARGETS if len(target_program) == 0 else target_program
    )
    input_path = pathlib_Path(input_directory)
    output_path = pathlib_Path(output_directory)

    if output_path.is_dir():
        if overwrite:
            _LOGGER.warning(f"Clean {output_path} and create again.")
            rmtree(output_path)
            output_path.mkdir()
        else:
            _LOGGER.info(f"{output_path} already exists. Adding stuff.")
    else:
        _LOGGER.info(f"Create {output_path}.")
        output_path.mkdir()

    find_clash_cluster_internal(
        distance_metric,
        epsilon,
        fuzzers,
        input_path,
        max_no_of_crashes_per_fuzzer,
        output_path,
        targets,
    )


if __name__ == "__main__":
    main_group()
