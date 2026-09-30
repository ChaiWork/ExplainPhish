"""Small helper functions shared by all modules."""
import json
import logging
import time
from pathlib import Path

import numpy as np


def ensure_dir(path):
    """Create a folder (and parents) if it does not exist, then return it."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_logger(name, log_file=None):
    """Logger that prints to the console and (optionally) to a log file."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S")
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)
    if log_file:
        ensure_dir(Path(log_file).parent)
        file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


class _JsonEncoder(json.JSONEncoder):
    """Lets json.dump handle numpy numbers, arrays, Paths and sets."""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return None if np.isnan(obj) else float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, (Path, set)):
            return str(obj) if isinstance(obj, Path) else sorted(obj)
        return super().default(obj)


def save_json(obj, path):
    ensure_dir(Path(path).parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, cls=_JsonEncoder)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class Timer:
    """Usage: with Timer() as t: ...; then t.seconds."""
    def __enter__(self):
        self._start = time.perf_counter()
        self.seconds = 0.0
        return self

    def __exit__(self, *exc):
        self.seconds = round(time.perf_counter() - self._start, 3)
        return False
