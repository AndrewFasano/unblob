"""File extraction related functions."""
# ruff: noqa

import errno
import os
from pathlib import Path
from typing import Union

from structlog import get_logger

from .file_utils import carve, is_safe_path
from .models import Chunk, File, PaddingChunk, TaskResult, UnknownChunk, ValidChunk

logger = get_logger()

FILE_PERMISSION_MASK = 0
DIR_PERMISSION_MASK = 0

# re-exported, or unused symbols
__all__ = [
    "is_safe_path",
    "fix_symlink",
    "is_recursive_link",
]


def carve_chunk_to_file(carve_path: Path, file: File, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    logger.debug("Carving chunk", path=carve_path)
    carve(carve_path, file, chunk.start_offset, chunk.size)


def fix_permission(path: Path):
    if not path.exists():
        return

    if path.is_symlink():
        return

    mode = path.stat().st_mode

    if path.is_file():
        mode |= FILE_PERMISSION_MASK
    elif path.is_dir():
        mode |= DIR_PERMISSION_MASK

    path.chmod(mode)


def is_recursive_link(path: Path) -> bool:
    try:
        path.resolve()
    except RuntimeError:
        return True
    return False


def fix_symlink(path: Path, outdir: Path, task_result: TaskResult) -> Path:
    # This is a temporary function for existing unit tests in tests/test_extractor.py
    fix_extracted_directory(outdir, task_result)
    return path


def fix_extracted_directory(outdir: Path, task_result: TaskResult):
    def _fix_extracted_directory(directory: Path):
        if not directory.exists():
            return

        base_dir = os.path.abspath(outdir)
        for root, dirs, files in os.walk(base_dir, topdown=True):
            fix_permission(Path(root))
            for name in dirs + files:
                try:
                    full_path = os.path.join(root, name)
                    if os.path.islink(full_path):
                        # Unlike upstream unblob, we allow symlinks to do anything they want. We run in docker so this
                        # isn't as dangerous as it would be otherwise, but it's still probably
                        # a questionable decision.
                        pass
                except OSError as e:
                    if e.errno == errno.ENAMETOOLONG:
                        continue
                    raise e from None

    fix_permission(outdir)
    _fix_extracted_directory(outdir)


def carve_unknown_chunk(
    extract_dir: Path, file: File, chunk: Union[UnknownChunk, PaddingChunk]
) -> Path:
    extension = "unknown"
    if isinstance(chunk, PaddingChunk):
        extension = "padding"

    filename = f"{chunk.start_offset}-{chunk.end_offset}.{extension}"
    carve_path = extract_dir / filename
    logger.info("Extracting unknown chunk", path=carve_path, chunk=chunk)
    carve_chunk_to_file(carve_path, file, chunk)
    return carve_path


def carve_valid_chunk(extract_dir: Path, file: File, chunk: ValidChunk) -> Path:
    filename = f"{chunk.start_offset}-{chunk.end_offset}.{chunk.handler.NAME}"
    carve_path = extract_dir / filename
    logger.info("Extracting valid chunk", path=carve_path, chunk=chunk)
    carve_chunk_to_file(carve_path, file, chunk)
    return carve_path
