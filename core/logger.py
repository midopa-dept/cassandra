"""Cassandra Bot — 로깅."""
import logging
import sys
from datetime import datetime


def setup_logger(name: str = "cassandra", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s", datefmt="%H:%M:%S")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger


def get_logger(name: str = "cassandra") -> logging.Logger:
    return logging.getLogger(name)
