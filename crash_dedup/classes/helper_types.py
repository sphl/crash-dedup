"""
Typings.
"""
from typing import Literal

FUZZER_TYPES = Literal[
    "afl",
    "aflfast",
    "aflpp",
    "aflsmart",
    "fairfuzz",
    "honggfuzz",
    "mopt_afl",
    "mopt_aflpp",
]
METRIC_TYPES = Literal["sorensen", "levenstein"]
TARGET_TYPES = Literal[
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
