import logging
import logging.handlers

from tanner.config import TannerConfig


class LevelFilter(logging.Filter):
    """Filters (lets through) all messages with level < LEVEL"""

    def __init__(self, level):
        self.level = level

    def filter(self, record):
        # "<" instead of "<=": since logger.setLevel is inclusive, this should be exclusive
        return record.levelno < self.level


class Logger:
    @staticmethod
    def create_logger(debug_filename, err_filename, logger_name):
        if TannerConfig.get("CLEANLOG", "enabled") == "True":
            with open(err_filename, "w"):
                pass

        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s:%(name)s:%(funcName)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

        # ERROR log to 'tanner.err'
        error_log_handler = logging.handlers.RotatingFileHandler(err_filename, encoding="utf-8")
        error_log_handler.setLevel(logging.ERROR)
        error_log_handler.setFormatter(formatter)
        logger.addHandler(error_log_handler)

        # DEBUG log to 'tanner.log'
        debug_log_handler = logging.handlers.RotatingFileHandler(debug_filename, encoding="utf-8")
        debug_log_handler.setLevel(logging.DEBUG)
        debug_log_handler.setFormatter(formatter)
        max_level_filter = LevelFilter(logging.ERROR)
        debug_log_handler.addFilter(max_level_filter)
        logger.addHandler(debug_log_handler)

        return logger
