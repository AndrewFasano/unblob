import io
from operator import attrgetter, itemgetter
from pathlib import Path
from typing import Iterator, List

from structlog import get_logger

from .extractor import carve_chunk_to_file, extract_with_command, make_extract_dir
from .file_utils import LimitedStartReader
from .finder import search_chunks
from .handlers import _ALL_MODULES_BY_PRIORITY
from .iter_utils import pairwise
from .logging import noformat
from .models import UnknownChunk, ValidChunk

logger = get_logger()


def search_chunks_by_priority(  # noqa: C901
    path: Path, file: io.BufferedReader, file_size: int
) -> List[ValidChunk]:
    all_chunks = []

    for priority_level, handlers in enumerate(_ALL_MODULES_BY_PRIORITY, start=1):
        logger.info("Starting priority level", priority_level=noformat(priority_level))
        yara_results = search_chunks(handlers, path)

        if yara_results:
            logger.info("Found YARA results", count=noformat(len(yara_results)))

        for result in yara_results:
            handler = result.handler
            match = result.match
            sorted_matches = sorted(match.strings, key=itemgetter(0))
            for offset, identifier, string_data in sorted_matches:
                real_offset = offset + handler.YARA_MATCH_OFFSET

                if any(chunk.contains_offset(real_offset) for chunk in all_chunks):
                    continue

                logger.info(
                    "Calculating chunk for YARA match",
                    start_offset=offset,
                    real_offset=real_offset,
                    identifier=identifier,
                )
                limited_reader = LimitedStartReader(file, real_offset)

                try:
                    chunk = handler.calculate_chunk(limited_reader, real_offset)
                except Exception as exc:
                    logger.error(
                        "Unhandled Exception during chunk calculation", exc_info=exc
                    )
                    continue

                # We found some random bytes this handler couldn't parse
                if chunk is None:
                    continue

                if chunk.end_offset > file_size or chunk.start_offset < 0:
                    logger.error("Chunk overflows file", chunk=chunk)
                    continue

                chunk.handler = handler
                logger.info("Found valid chunk", chunk=chunk, handler=handler.NAME)
                all_chunks.append(chunk)

    return all_chunks


def remove_inner_chunks(chunks: List[ValidChunk]) -> List[ValidChunk]:
    """Remove all chunks from the list which are within another bigger chunks."""
    if not chunks:
        return []

    chunks_by_size = sorted(chunks, key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks_by_size[0]]
    for chunk in chunks_by_size[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)

    outer_count = len(outer_chunks)
    removed_count = len(chunks) - outer_count
    logger.info(
        "Removed inner chunks",
        outer_chunk_count=outer_count,
        removed_inner_chunk_count=removed_count,
    )
    return outer_chunks


def calculate_unknown_chunks(
    chunks: List[ValidChunk], file_size: int
) -> List[UnknownChunk]:
    """Calculate the empty gaps between chunks."""
    if not chunks or file_size == 0:
        return []

    sorted_by_offset = sorted(chunks, key=attrgetter("start_offset"))

    unknown_chunks = []

    first = sorted_by_offset[0]
    if first.start_offset != 0:
        unknown_chunk = UnknownChunk(0, first.start_offset)
        unknown_chunks.append(unknown_chunk)

    for chunk, next_chunk in pairwise(sorted_by_offset):
        diff = next_chunk.start_offset - chunk.end_offset
        if diff != 0:
            unknown_chunk = UnknownChunk(
                start_offset=chunk.end_offset,
                end_offset=next_chunk.start_offset,
            )
            unknown_chunks.append(unknown_chunk)

    last = sorted_by_offset[-1]
    if last.end_offset < file_size:
        unknown_chunk = UnknownChunk(
            start_offset=last.end_offset,
            end_offset=file_size,
        )
        unknown_chunks.append(unknown_chunk)

    return unknown_chunks


def extract_with_priority(
    root: Path, path: Path, extract_root: Path, file_size: int
) -> Iterator[Path]:

    with path.open("rb") as file:
        all_chunks = search_chunks_by_priority(path, file, file_size)
        outer_chunks = remove_inner_chunks(all_chunks)
        unknown_chunks = calculate_unknown_chunks(outer_chunks, file_size)
        if unknown_chunks:
            logger.warning("Found unknown Chunks", chunks=unknown_chunks)

        for chunk in outer_chunks:
            extract_dir = make_extract_dir(root, path, extract_root)
            filename = f"{chunk.start_offset}-{chunk.end_offset}.{chunk.handler.NAME}"
            carved_path = carve_chunk_to_file(extract_dir, filename, file, chunk)
            extracted = extract_with_command(extract_dir, carved_path, chunk.handler)
            yield extracted
