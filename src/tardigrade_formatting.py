import argparse
import logging
from sys import stderr


class TardigradeColorFormatter(logging.Formatter):
    color_mappings = {
        'black': "\033[1;30m",
        'dark_blue': "\033[0;34m",
        'dark_green': "\033[0;32m",
        'dark_aqua': "\033[0;36m",
        'dark_red': "\033[0;31m",
        'dark_purple': "\033[0;35m",
        'gold': "\033[1;33m",
        'gray': "\033[1;37m",
        'dark_gray': "\033[0;90m",
        'blue': "\033[1;94m",
        'green': "\033[1;92m",
        'aqua': "\033[1;96m",
        'red': "\033[1;91m",
        'purple': "\033[0;35m",
        'pink': "\033[38;5;206m",
        'orange': "\033[38;5;208m",
        'light_purple': "\033[1;95m",
        'yellow': "\033[1;93m",
        'white': "\033[1;97m",
        'reset': "\033[0m",
    }
    other_mappings = {
        'banner': '(꒰֎꒱)',
        'title': 'Tardigrade'
    }

    def __init__(self, log_formats: argparse.Namespace = None, extra_mappings: dict[str, str] = None,
                 color_enabled=True):
        super(TardigradeColorFormatter).__init__()
        self.other_mappings.update(extra_mappings)
        self.logFormats = log_formats
        self.color = color_enabled
        self.FORMATS = self.define_format()
        super().__init__()

    def color_pre_formatter(self, s):
        result = []
        for part in s.split('%('):
            if ')' in part:
                key, value = part.split(')', 1)
                if value[0] == 's':
                    if key in self.color_mappings and self.color:
                        result.append(self.color_mappings[key] + value[1:])
                    elif key in self.other_mappings:
                        result.append(self.other_mappings[key] + value[1:])
                    else:
                        result.append("%(" + key + ")" + value)
                else:
                    result.append("%(" + part)
            else:
                result.append(part)
        return ''.join(result)

    def define_format(self):
        prefix = "%(purple)s%(asctime)s%(reset)s"
        suffix = "[%(levelname)s]%(reset)s {%(funcName)s} (%(lineno)s) - %(message)s"
        if not self.color:
            return {
                logging.DEBUG: self.logFormats.NOCOLOR,
                logging.INFO: self.logFormats.NOCOLOR,
                logging.WARNING: self.logFormats.NOCOLOR,
                logging.ERROR: self.logFormats.NOCOLOR,
                logging.CRITICAL: self.logFormats.NOCOLOR
            }

        if self.logFormats is not None:
            if self.logFormats.DEFAULT is None:
                self.logFormats.DEFAULT = prefix + suffix
            return {
                logging.DEBUG: self.logFormats.DEBUG or self.logFormats.DEFAULT,
                logging.INFO: self.logFormats.INFO or self.logFormats.DEFAULT,
                logging.WARNING: self.logFormats.WARNING or self.logFormats.DEFAULT,
                logging.ERROR: self.logFormats.ERROR or self.logFormats.DEFAULT,
                logging.CRITICAL: self.logFormats.CRITICAL or self.logFormats.DEFAULT
            }
        else:
            return {
                logging.DEBUG: prefix + " %(dark_green)s" + suffix,
                logging.INFO: prefix + " %(blue)s" + suffix,
                logging.WARNING: prefix + " %(orange)s" + suffix,
                logging.ERROR: prefix + " %(red)s" + suffix,
                logging.CRITICAL: prefix + " %(dark_red)s" + suffix,
            }

    def format(self, record):
        """

        :type record: logging.Record
        """
        try:
            parsing_string = self.FORMATS.get(record.levelno)
            parsing_string = self.color_pre_formatter(parsing_string)
            formatter = logging.Formatter(parsing_string)
            return formatter.format(record)
        except TypeError as e:
            stderr.write(str(e))
            stderr.flush()
