"""Exceptions shared by PE parsing modules."""


class PEFormatError(Exception):
    """Raised when a file is not a structurally valid PE image."""
