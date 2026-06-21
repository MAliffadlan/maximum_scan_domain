"""
Simple spinner & progress indicator for terminal.
"""

import itertools
import sys
import threading
import time


class Spinner:
    """Simple animated spinner with elapsed time.

    Usage:
        with Spinner("Scanning..."):
            do_work()
    """

    def __init__(self, message: str = "Loading", quiet: bool = False):
        self.message = message
        self.quiet = quiet
        self._running = False
        self._thread: threading.Thread | None = None
        self._start_time = 0.0
        self._frames = itertools.cycle(["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"])

    def _spin(self):
        while self._running:
            elapsed = time.time() - self._start_time
            frame = next(self._frames)
            msg = f"\r{frame} {self.message} ({elapsed:.0f}s)"
            sys.stdout.write(msg)
            sys.stdout.flush()
            time.sleep(0.1)

        # Clear the line
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

    def __enter__(self):
        if not self.quiet:
            self._start_time = time.time()
            self._running = True
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(0.2)

    def set_message(self, msg: str):
        """Update the spinner message."""
        self.message = msg
