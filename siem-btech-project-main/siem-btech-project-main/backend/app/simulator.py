from __future__ import annotations

import threading
import time

from .logging_config import get_logger

logger = get_logger("siem.simulator")


class SimulatorManager:
    def __init__(self, tick_callback, interval_seconds: int = 5) -> None:
        self._tick_callback = tick_callback
        self._interval_seconds = interval_seconds
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def _run(self) -> None:
        logger.info("Simulator thread started | interval_seconds=%s", self._interval_seconds)
        while not self._stop_event.wait(self._interval_seconds):
            try:
                self._tick_callback()
            except Exception:
                logger.exception("Simulator tick failed")
        logger.info("Simulator thread stopped")

    def start(self) -> dict[str, int | bool]:
        with self._lock:
            if self.is_running():
                return {"running": True, "interval_seconds": self._interval_seconds}

            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True, name="siem-simulator")
            self._thread.start()
            return {"running": True, "interval_seconds": self._interval_seconds}

    def stop(self) -> dict[str, int | bool]:
        with self._lock:
            self._stop_event.set()
            thread = self._thread
            self._thread = None

        if thread and thread.is_alive():
            thread.join(timeout=1)

        return {"running": False, "interval_seconds": self._interval_seconds}

    def status(self) -> dict[str, int | bool]:
        return {"running": self.is_running(), "interval_seconds": self._interval_seconds}

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
