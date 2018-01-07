import logging
import sys
ALLOWED_LOGGING_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']


class StdErrFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno in (logging.ERROR, logging.WARNING, logging.CRITICAL)

class StdOutFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno in (logging.DEBUG, logging.INFO)

def setup_console_logger(loglevel):

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    format_string = '%(levelname)s - %(asctime)s - %(message)s'
    logger = logging.getLogger('console')
    logger.setLevel(numeric_level)

    formatter = logging.Formatter(fmt=format_string)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stdout_handler.addFilter(StdOutFilter())
    logger.addHandler(stdout_handler)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    stderr_handler.addFilter(StdErrFilter())
    logger.addHandler(stdout_handler)

    return logger
