import logging
import logging.handlers


class Logger:
    @staticmethod
    def create_logger(filename, logger_name):
        log_filename = filename
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.RotatingFileHandler(log_filename)

        formatter = logging.Formatter(fmt='%(asctime)s %(levelname)s:%(name)s:%(funcName)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M')
        handler.setFormatter(formatter)

        logger.addHandler(handler)

        return logger
