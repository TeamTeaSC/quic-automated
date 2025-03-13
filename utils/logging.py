from enum import Enum

class Logging(Enum):
    """
    This class is an enum type for console logging levels.
    """
    CRIT = 0   # critical errors
    ALERT = 1  # alerts
    WARN = 2   # warnings
    NORM = 3   # normal messages
    INFO = 4   # informational messages
    DEBUG = 5  # debugging messages

    @staticmethod
    def higher_prio(level_1, level_2) -> bool:
        return (level_1.value <= level_2.value)

console_log_level = Logging.NORM

def log(log_level: Logging, *args):
    if Logging.higher_prio(log_level, console_log_level):
        print(f'{log_level.name}: ', end='')
        print(*args)

def get_log_level() -> Logging:
    return console_log_level

def set_log_level(log_level: Logging):
    global console_log_level
    console_log_level = log_level
