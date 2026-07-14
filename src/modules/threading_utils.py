"""
Generic background-thread helper for PyQt5.

Any blocking core function (network scan, APK analysis, report generation)
can be run through run_in_thread() to keep the UI responsive. Reused by
every module rather than each one hand-rolling its own QThread plumbing.
"""

from typing import Any, Callable, Tuple

from PyQt5.QtCore import QObject, QThread, pyqtSignal


class ScanWorker(QObject):
    """Runs a blocking callable on a background thread and reports via signals."""

    progress = pyqtSignal(str)
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, task: Callable[..., Any], *args, **kwargs):
        super().__init__()
        self._task = task
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:
        try:
            kwargs = dict(self._kwargs)
            # Only inject progress_callback if the target task accepts it and
            # the caller hasn't already supplied one.
            kwargs.setdefault("progress_callback", self.progress.emit)
            result = self._task(*self._args, **kwargs)
            self.finished.emit(result)
        except Exception as exc:  # noqa: BLE001 - never let a worker crash the app
            self.failed.emit(str(exc))


def run_in_thread(task: Callable[..., Any], *args, **kwargs) -> Tuple[QThread, ScanWorker]:
    """
    Wire up a QThread + ScanWorker pair for `task`.

    The caller MUST keep strong references to both returned objects
    (e.g. as instance attributes) until `finished`/`failed` fires, or
    Python's garbage collector may destroy them mid-run.
    """
    thread = QThread()
    worker = ScanWorker(task, *args, **kwargs)
    worker.moveToThread(thread)

    thread.started.connect(worker.run)
    worker.finished.connect(thread.quit)
    worker.failed.connect(thread.quit)
    thread.finished.connect(thread.deleteLater)

    return thread, worker
