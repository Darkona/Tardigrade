"""<Small footprint SimpleHTTPServer implementation with nice logging and POST requests processing,
 meant for development work and simple testing>
Author: <Javier Darkona> <Javier.Darkona@Gmail.com>
Created: <14/06/2023>
"""
import argparse
import logging
import os
import string
from functools import partial
from http.server import HTTPServer
from logging.handlers import RotatingFileHandler

import importlib_metadata
import yaml

from tardigrade.configuration import TardigradeConfiguration
from tardigrade.constants import TARDIGRADE_ASCII, FULL_COLOR
from tardigrade.formatting import TardigradeColorFormatter
from tardigrade.handling import TardigradeRequestHandler
from tardigrade.commandthread import TardigradeCommandReturningThread

AUTHOR = "Javier.Darkona@Gmail.com"

metadata = importlib_metadata.metadata("tardigrade")
__VERSION__ = metadata.json["version"]

log = logging.Logger
ENC = 'utf-8'
command_thread: TardigradeCommandReturningThread
configuration: TardigradeConfiguration


def get_args(c: TardigradeConfiguration):
    checker = argparse.ArgumentParser(add_help=False)

    checker.add_argument("--extra", "-e", action="append", dest="extra", choices=["file", "web"],
                         help="extra logger outputs")
    checker.add_argument("--secure", "-s", action="store_true", help="[WEB LOGGER]")
    extra_args = checker.parse_known_args()[0]
    extra_args.extra = set(extra_args.extra) if extra_args.extra else []

    parser = argparse.ArgumentParser(prog="Tardigrade", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Server Configuration Arguments
    server_group = parser.add_argument_group("Server Configuration")

    server_group.add_argument("--port", "-p", type=int, default=c.port, dest="port",
                              help="the server port where Tardigrade will run")

    server_group.add_argument("--directory", "-d", type=str, default=c.directory, dest="directory",
                              help="directory to execute commands from")

    server_group.add_argument("--timeout", "-t", type=int, default=c.timeout, dest="timeout",
                              help="directory to serve files or execute commands from")

    server_group.add_argument("--output", "-O", type=str, default=c.output, dest="output",
                              help="Directory where to write files to")
    server_group.add_argument("--input", "-I", type=str, default=c.input, dest="input",
                              help="Directory to serve files from")
    # Log Configuration
    log_group = parser.add_argument_group(title="Logging Configuration")

    log_group.add_argument("--logserver", "-L", action="store_true", default=c.log_server, dest="log_server",
                           help="Disables all own logging, will listen for POST logging from another Tardigrade and log its messages with this Tardigrade configuration")

    log_group.add_argument("--loglevel", "-l",
                           metavar="{q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}", type=str,
                           default=c.loglevel, dest="loglevel",
                           choices=["quiet", "debug", "info", "warn", "error", "critical", "q", "d", "i", "w", "e",
                                    "c"], help="logging level")

    log_group.add_argument("--options", "-o", nargs='*', default=c.options, dest="options",
                           choices=["no-color", "no-request", "no-response", "no-header", "no-body", "no-console",
                                    "no-banner"],
                           help="remove certain attributes from logging.")

    log_group.add_argument("--extra", "-e", action="append", dest="extra", default=c.extra, choices=["file", "web"],
                           help="extra logger outputs")
    # Extra Logger Configuration
    extra_group = parser.add_argument_group(title="Extra Logger Options")

    extra_group.add_argument("--filename", "-f", type=str, default=c.filename,
                             help="only has an effect if file logger is enabled; filename for the log file")
    extra_group.add_argument("--maxbytes", "-x", type=int, default=c.max_bytes, dest="max_bytes",
                             help="only has an effect if file logger is enabled;max size of each file in bytes, if 0, file grows indefinitely")
    extra_group.add_argument("--count", "-c", metavar="FILECOUNT", type=int, default=c.count,
                             help="only has an effect if file logger is enabled; max amount of files to keep before rolling over, if 0, file grows indefinitely")

    extra_group.add_argument("--webhost", required="web" in extra_args.extra, default=c.web_host, dest="web_host",
                             help="required if web logger is enabled; host for the listening log server, can include port like host:port")
    extra_group.add_argument("--weburl", required="web" in extra_args.extra, default=c.web_url, dest="web_url",
                             help="required if web logger is enabled; url for the listening log server")
    extra_group.add_argument("--method", "-m", choices=["GET", "POST"], default=c.method,
                             help="only has an effect if web logger is enabled")
    extra_group.add_argument("--credentials", "-C", nargs=2, metavar=("userid", "password"),
                             required="secure" in extra_args.extra, default=c.credentials,
                             help="only has an effect if web logger is enabled; enables basic authentication with Authorization header")

    # Other Arguments
    parser.add_argument("--version", action="version", help="show Tardigrade version", version=__VERSION__)
    parser.epilog = ""

    return parser.parse_args()


def initialize_logger(c: TardigradeConfiguration):
    # Get log level from single letter
    letter_to_word_map = {"I": "INFO", "D": "DEBUG", "W": "WARN", "E": "ERROR", "C": "CRITICAL", "Q": "QUIET"}
    log_level = c.loglevel.upper()
    log_level = letter_to_word_map[log_level] if log_level in letter_to_word_map else log_level

    string.Template("")

    if log_level != "QUIET":

        logger = logging.getLogger("root")
        logger.setLevel(logging.DEBUG if c.log_server else getattr(logging, log_level))

        # Configure handlers
        handlers = []
        if c.file_log:
            handlers.append(logging.handlers.RotatingFileHandler(c.filename, encoding=ENC, maxBytes=c.max_bytes,
                                                                 backupCount=c.count))
            c.file_enable = True

        if c.web_log:
            handlers.append(logging.handlers.HTTPHandler(c.web_host, c.web_url, method=c.method, secure=c.secure,
                                                         credentials=tuple(c.credentials)))
            c.web_enable = True

        # Set same formatter for all the file handlers
        for h in handlers:
            h.setFormatter(
                TardigradeColorFormatter(log_formats=c.log_formats, extra_mappings=c.colors, color_enabled=False))

        if c.console:
            con = logging.StreamHandler()
            # Select color or plain formatter for console logger
            con.setFormatter(
                TardigradeColorFormatter(log_formats=c.log_formats, extra_mappings=c.colors, color_enabled=c.color))
            handlers.append(con)

        for h in handlers:
            logger.addHandler(h)
        return logger


def print_initialization(httpd):
    global log

    if configuration.console:
        if configuration.banner:
            if configuration.color:
                print(f'\033[38;5;206m{TARDIGRADE_ASCII}\033[0m')
            else:
                print(TARDIGRADE_ASCII)

        print(
            f"Tardigrade Server version {__VERSION__} is running. Listening at: {httpd.server_name}:{str(configuration.port)}")
        print(f"Writing files to {configuration.output}, reading files from {configuration.input}")
        print((
                  FULL_COLOR if configuration.color else "Monochromatic (boring) ") + "logging enabled. Level: " +
              logging.getLevelName(log.getEffectiveLevel()))

        if configuration.configFile:
            print("Configuration file loaded")

        if configuration.file_log:
            print(f"Logging in file: {configuration.filename}")

        if configuration.web_log:
            print(f"Logging in web at: {configuration.web_host}/{configuration.web_url}")


def run():
    global configuration
    global log
    global command_thread
    global ENC

    log = initialize_logger(configuration)

    server_address = ('localhost', int(configuration.port))
    handler = partial(TardigradeRequestHandler,
                      configuration=globals().get("configuration"),
                      logger=globals().get("log"),
                      thread=globals().get("command_thread"))
    httpd = HTTPServer(server_address, handler)
    httpd.timeout = configuration.timeout if configuration.timeout > 0 or configuration.log_server else None

    print_initialization(httpd)

    try:
        if not configuration.log_server:
            log.info("Tardigrade started")
        else:
            print("Tardigrade started as Log Server")
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not configuration.log_server:
            log.info('Tardigrade stopped...\n')
        else:
            print("Tardigrade stopped as Log Server")
    httpd.server_close()


if __name__ == '__main__':
    configuration = TardigradeConfiguration(ver=__VERSION__)

    try:
        with open("config/config.yaml") as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            configuration.update(**config)
            configuration.configFile = True
    except FileNotFoundError:
        pass
    finally:
        configuration.update(**get_args(configuration).__dict__)
    try:
        for s in [configuration.output, configuration.input]:
            p = os.path.join(os.getcwd(), s)
            if not os.path.exists(p):
                os.makedirs(p)
    except OSError:
        pass
    run()
