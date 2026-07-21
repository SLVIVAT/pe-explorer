from pathlib import Path


def read_binary_file(file_path: str) -> bytes:
    """
    Reads a file in binary mode.

    Args:
        file_path: Path to the file.

    Returns:
        File contents as bytes.
    """
    return Path(file_path).read_bytes()


def format_size(size: int) -> str:
    """
    Converts file size into a human-readable format.
    """

    units = ["B", "KB", "MB", "GB"]

    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{size} B"


def format_hex(value: int, digits: int = 8) -> str:
    """
    Formats integer as hexadecimal.
    """

    return f"0x{value:0{digits}X}"


def file_exists(file_path: str) -> bool:
    """
    Checks whether a file exists.
    """

    return Path(file_path).exists()


def get_file_name(file_path: str) -> str:
    """
    Returns file name only.
    """

    return Path(file_path).name


def get_extension(file_path: str) -> str:
    """
    Returns file extension.
    """

    return Path(file_path).suffix.lower()