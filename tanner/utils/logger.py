import logging
import logging.handlers


class Logger:
    @staticmethod
    def create_logger(error_log_filename, event_log_filename, logger_name):

        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)
        error_log_handler = logging.handlers.RotatingFileHandler(error_log_filename, encoding='utf-8')
        error_log_handler.setLevel(logging.ERROR)
        event_log_handler = logging.handlers.RotatingFileHandler(event_log_filename, encoding='utf-8')
        event_log_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(fmt='%(asctime)s %(levelname)s:%(name)s:%(funcName)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M')
        event_log_handler.setFormatter(formatter)
        error_log_handler.setFormatter(formatter)

        logger.addHandler(error_log_handler)
        logger.addHandler(event_log_handler)

        return logger
