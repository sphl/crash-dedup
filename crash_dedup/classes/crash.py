"""
Crash.
"""
from typing import TypedDict

from crash_dedup.classes.helper_types import FUZZER_TYPES


class Crash(TypedDict):
    """
    Crash.
    """

    fuzzer: FUZZER_TYPES
    file_path: str
    file_content: str
    cluster_id: int
