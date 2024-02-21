"""File extraction related functions."""
from pathlib import Path
from typing import Union

from structlog import get_logger

from .file_utils import carve
from .models import Chunk, File, PaddingChunk, UnknownChunk, ValidChunk

logger = get_logger()

def carve_chunk_to_file(carve_path: Path, file: File, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    logger.debug("Carving chunk", path=carve_path)
    carve(carve_path, file, chunk.start_offset, chunk.size)


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
