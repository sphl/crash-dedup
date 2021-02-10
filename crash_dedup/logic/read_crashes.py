"""
Read crashes.
"""
from functools import partial
from os import path, walk
from pathlib import Path
from re import compile as re_compile
from typing import Callable, List, Optional, Pattern

from crash_dedup.classes.crash import Crash
from crash_dedup.classes.helper_types import FUZZER_TYPES


def read_crashes(
    fuzzer: FUZZER_TYPES,
    crash_dir: Path,
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
        for file in _find_files(crash_dir, file_exts=["trace"], recursive=True)
    ]
    result_list = [d for d in crashes if len(d["file_content"]) > 0]
    if max_no_of_crashes == -1:
        return result_list
    else:
        return result_list[:max_no_of_crashes]


def get_crash_dir(
    crash_root: Path, fuzzer: FUZZER_TYPES, target: str, seed: str
) -> Path:
    """

    :param crash_root:
    :param fuzzer:
    :param target:
    :param seed:
    :return:
    """
    return Path(
        path.join(
            crash_root,
            fuzzer,
            target,
            "stacktraces" if seed == "-" else path.join("stacktraces", f"seed_{seed}"),
        )
    )


def _not_in(s: str, black_list: List[str]) -> bool:
    """

    :param s:
    :param black_list:
    :return:
    """
    for v in black_list:
        if s.endswith(v):
            return False
    return True


def _create_matcher_for_file_extensions(
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


def _find_files(
    source_dir: Path,
    file_exts: Optional[List[str]] = None,
    exclude_dirs: Optional[List[str]] = None,
    exclude_files: Optional[List[str]] = None,
    recursive: bool = False,
) -> List[Path]:
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

    extension_matcher = _create_matcher_for_file_extensions(file_exts)
    not_in_matcher = partial(_not_in, black_list=exclude_files)
    if recursive:
        source_files = [
            path.join(root, file)
            for root, _, files in walk(source_dir)
            if root not in exclude_dirs
            for file in [f for f in files if extension_matcher(f)]
        ]
    else:
        source_files = [f for f in source_dir.iterdir() if extension_matcher(f.name)]
    return [Path(f) for f in source_files if not_in_matcher(f)]


def _get_file_content(file: Path, n_frames: Optional[int]) -> str:
    if n_frames is None:
        file_content = file.read_text()
    else:
        with file.open() as f_read:
            file_content = " ".join(f_read.readlines()[:n_frames])
    return file_content
