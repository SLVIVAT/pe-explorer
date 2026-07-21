"""Small reusable background-task primitive for responsive Qt workflows."""

from __future__ import annotations

from collections.abc import Callable
import traceback
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


ProgressCallback = Callable[[str], None]
TaskFunction = Callable[[ProgressCallback], object]


class TaskSignals(QObject):
    """Queued signals emitted by :class:`BackgroundTask`."""

    progress = Signal(int, str)
    succeeded = Signal(int, object)
    failed = Signal(int, str, str)
    finished = Signal(int)


class BackgroundTask(QRunnable):
    """Run a function in ``QThreadPool`` with generation-safe signals."""

    def __init__(self, generation: int, function: TaskFunction) -> None:
        super().__init__()
        self.generation = generation
        self.function = function
        self.signals = TaskSignals()
        self.setAutoDelete(True)

    @Slot()
    def run(self) -> None:
        try:
            result = self.function(self._report_progress)
        except Exception as error:  # pragma: no cover - branch asserted by GUI test
            self.signals.failed.emit(
                self.generation,
                str(error),
                traceback.format_exc(),
            )
        else:
            self.signals.succeeded.emit(self.generation, result)
        finally:
            self.signals.finished.emit(self.generation)

    def _report_progress(self, message: str) -> None:
        self.signals.progress.emit(self.generation, message)


def task_from_callable(
    generation: int,
    function: Callable[[], Any],
) -> BackgroundTask:
    """Adapt a zero-argument callable to a background task."""

    return BackgroundTask(generation, lambda progress: function())


__all__ = [
    "BackgroundTask",
    "ProgressCallback",
    "TaskSignals",
    "task_from_callable",
]
