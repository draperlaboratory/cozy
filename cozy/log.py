import logging

logger = logging.getLogger('cozy-log')
def disable():
    """
    Disable cozy logging
    """
    logger.setLevel(logging.NOTSET)

def set_level(level):
    """
    Set the level of logging
    """
    logger.setLevel(level)

def info(*args, **kwargs):
    """
    Log at the info level
    """
    logger.info(*args, **kwargs)

def warning(*args, **kwargs):
    """
    Log at the warning level
    """
    logger.warning(*args, **kwargs)

def error(*args, **kwargs):
    """
    Log at the error level
    """
    logger.error(*args, **kwargs)

def debug(*args, **kwargs):
    """
    Log at the debug level
    """
    logger.debug(*args, **kwargs)

def critical(*args, **kwargs):
    """
    Log at the critical level
    """
    logger.critical(*args, **kwargs)

set_level(logging.DEBUG)