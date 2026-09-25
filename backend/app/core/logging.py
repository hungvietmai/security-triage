"""Logging for the API and worker processes.

Uvicorn and Celery configure their own loggers; this gives `app.*` loggers a
timestamped stderr handler so failures such as readiness probes are readable.
"""

import logging.config

from app.core.config import get_settings


def configure_logging() -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {"format": "%(asctime)s %(levelname)-7s %(name)s: %(message)s"}
            },
            "handlers": {
                "stderr": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stderr",
                }
            },
            "loggers": {
                "app": {
                    "handlers": ["stderr"],
                    "level": get_settings().log_level,
                    "propagate": False,
                }
            },
        }
    )
