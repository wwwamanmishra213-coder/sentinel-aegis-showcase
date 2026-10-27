"""
SentinelAegis-X - Filesystem Sentinel Monitor
Watches high-risk ingress points (Downloads, Temp, Startup) and passes new binaries
directly to the MalwareAnalyzer for real-time static/heuristic inspection.
"""

import os
import time
import logging
from typing import List, Callable, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("FSSentinel")


class MalwareDropHandler(FileSystemEventHandler):
    def __init__(self, callback: Callable[[str], None], watched_extensions: List[str]):
        super().__init__()
        self.callback = callback
        self.watched_extensions = set(ext.lower() for ext in watched_extensions)
        self._processed = {}

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def _handle(self, file_path: str):
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.watched_extensions:
            now = time.time()
            # Debounce rapid writes
            if file_path in self._processed and (now - self._processed[file_path] < 3):
                return
            self._processed[file_path] = now
            # Small delay to ensure file write is complete
            time.sleep(0.5)
            try:
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    self.callback(file_path)
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")


class FileSystemSentinel:
    def __init__(self, watch_paths: List[str], extensions: List[str], on_file_detected: Callable[[str], None]):
        self.watch_paths = [os.path.expanduser(p) for p in watch_paths]
        self.extensions = extensions
        self.on_file_detected = on_file_detected
        self.observer = Observer()

    def start(self):
        handler = MalwareDropHandler(self.on_file_detected, self.extensions)
        started_any = False
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(handler, path, recursive=False)
                logger.info(f"FileSystem Sentinel watching: {path}")
                started_any = True
        if started_any:
            self.observer.start()

    def stop(self):
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
