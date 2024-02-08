"""File extraction related functions."""
import errno
import os
from pathlib import Path
from typing import Union

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
    """Check if the symlink creates a loop."""
    try:
        path.resolve(strict=True)
    except RecursionError:
        return True
    return False

def safe_resolve(path: Path, root_dir: Path) -> Path:
    try:
        return path.resolve()
    except RuntimeError as e:
        logger.error(f"Symlink loop detected for {path}: {e}")
        # Return the path as is or handle it according to your needs
        return path

def is_potential_loop(target: Path, root_dir: Path) -> bool:
    resolved_target = target.resolve()
    return resolved_target.is_symlink() and resolved_target.resolve() == target

def fix_symlink(path: Path, root_dir: Path, task_result : TaskResult) -> Path:
    '''
    Make a symlink relative to root_dir.
    '''
    assert(path.is_symlink())

    target = path.readlink()

    if Path(target).is_absolute():
        # Convert absolute target to be relative to root_dir
        absolute_target = root_dir / str(target).lstrip('/')
    else:
        # Resolve relative target against symlink's directory
        absolute_target = safe_resolve(path.parent / target, root_dir)
        logger.debug(f"Target {target} is relative, resolved to {absolute_target}")

    # Check if the absolute target exists within root_dir. Also check that it's not a dangling symlink
    if not absolute_target.exists() and not os.path.lexists(absolute_target):
        logger.warning(f"Symlink {path} -> {absolute_target} but target does not exist. Creating a placeholder and linking to it.")

        # We may need to create 1 or more directories before we can touch absolute_target
        # track the directories we need to create
        dirs_to_create = []
        parent = absolute_target.parent
        while parent and not parent.exists():
            dirs_to_create.append(parent)
            parent = parent.parent
        if len(dirs_to_create):
            # Just create all the directories we need at once
            absolute_target.parent.mkdir(parents=True, exist_ok=True)
        # Create the placeholder file
        absolute_target.touch()

        # Calculate new target relative to the symlink's directory
        new_target = os.path.relpath(absolute_target, start=path.parent)
        # Replace the symlink with the new target
        path.unlink()

        if is_potential_loop(path, new_target):
            logger.error(f"Potential symlink loop detected for {path} -> {new_target}. Skipping modification.")
            return path

        path.symlink_to(new_target)
        logger.info(f"Symlink at {path} now points to {new_target}.")

        # Remove the placeholder to intentionally leave a dangling symlink.
        # Also remove directories we created for it
        absolute_target.unlink()
        for d in dirs_to_create:
            os.rmdir(d)

        logger.info(f"Removed placeholder {absolute_target}, leaving a dangling symlink at {path}->{absolute_target}.")
        # Assert that the symlink is now dangling
        assert(os.path.islink(path) and not os.path.exists(os.readlink(path)))

    else:
        # If the target exists, simply adjust the symlink as necessary
        new_target = os.path.relpath(absolute_target, start=path.parent)
        path.unlink()

        if is_potential_loop(path, new_target):
            logger.error(f"Potential symlink loop detected v2 for {path} -> {new_target}. Skipping modification.")
            return path

        path.symlink_to(new_target)
        logger.debug(f"Symlink at {path} updated to point to {new_target}.")

    return path

def fix_extracted_directory(outdir: Path, task_result: TaskResult):
    def _fix_extracted_directory(directory: Path):
        if not directory.exists():
            return
        for path in (directory / p for p in os.listdir(directory)):
            try:
                fix_permission(path)
                if path.is_symlink():
                    fix_symlink(path, outdir, task_result)
                    continue
                if path.is_dir():
                    _fix_extracted_directory(path)
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
