"""File extraction related functions."""
import errno
import os
from pathlib import Path
from typing import Union
from subprocess import check_output

from structlog import get_logger

from .file_utils import carve, is_safe_path
from .models import Chunk, File, PaddingChunk, TaskResult, UnknownChunk, ValidChunk
from .report import MaliciousSymlinkRemoved

logger = get_logger()

FILE_PERMISSION_MASK = 0 #0o600
DIR_PERMISSION_MASK = 0 #0o700


def carve_chunk_to_file(carve_path: Path, file: File, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    logger.debug("Carving chunk", path=carve_path)
    carve(carve_path, file, chunk.start_offset, chunk.size)

def fix_extracted_directory(outdir: Path, task_result: TaskResult):
    '''
    Given an extracted directly, we want to make sure there are
    no symlinks that point to absolute paths outside of our extraction.

    We use the symlinks(8) utility to replace all absolute symlinks
    with relative symlinks recursively within the directory and
    ensure all symlinks are within the directory.
    '''

    if not outdir.exists():
        return

    try:
        check_output(["symlinks", "-cr", str(outdir)])
    except Exception as e:
        logger.error(f"Failed to run symlinks on {outdir}: {e}")
        # We should not continue if symlinks fails as our directory
        # may have now contain symlinks that point outside outdir
        raise e



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
