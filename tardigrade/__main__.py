"""<Small footprint SimpleHTTPServer implementation with nice logging and POST requests processing,
 meant for development work and simple testing>
Author: <Javier Darkona> <Javier.Darkona@Gmail.com>
Created: <14/06/2023>
"""
import argparse
import inspect
import logging
import os
import shutil
import string
import sys
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


def run():
    global configuration
    global log
    global command_thread
    global ENC

    configuration = TardigradeConfiguration(ver=__VERSION__)

    load_config()

    create_folders()

    log = initialize_logger()

    httpd = config_server()

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


def config_server():
    global configuration
    server_address = ('localhost', int(configuration.port))
    handler = partial(TardigradeRequestHandler,
                      configuration=globals().get("configuration"),
                      logger=globals().get("log"),
                      thread=globals().get("command_thread"))
    httpd = HTTPServer(server_address, handler)
    httpd.timeout = configuration.timeout if configuration.timeout > 0 or configuration.log_server else None
    return httpd


def load_config():
    global configuration
    try:
        config_path = os.path.normpath(os.getcwd() + "/config/config.yaml")
        with open(config_path) as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            configuration.update(**config)
            configuration.config_file = True
    except FileNotFoundError:
        pass
    finally:
        configuration.update(**get_args().__dict__)


def create_folders():
    global configuration
    try:
        new_output = os.path.normpath(os.getcwd() + "/" + configuration.output)
        if not os.path.exists(new_output):
            os.makedirs(new_output)

        new_input = os.path.normpath(os.getcwd() + "/" + configuration.input)
        if not os.path.exists(new_input):
            os.makedirs(new_input)
            for f in ["index.html", "commas.csv", "tardigrades.txt", "tardigrade.jpeg", "response.json"]:
                shutil.copy2(os.path.normpath(inspect.getfile(inspect.currentframe()) + "/../../input/" + f), new_input)

        new_config = os.path.normpath(os.getcwd() + "/config")
        if not os.path.exists(new_config):
            os.makedirs(new_config)
            shutil.copy2(os.path.normpath(inspect.getfile(inspect.currentframe()) + "/../../config/config.yaml"), new_config)

    except Exception as e:
        print(str(e))


def get_args():
    global configuration

    checker = argparse.ArgumentParser(add_help=False)

    checker.add_argument("--extra", "-e", action="append", dest="extra", choices=["file", "web"],
                         help="extra logger outputs")
    checker.add_argument("--secure", "-s", action="store_true", help="[WEB LOGGER]")
    extra_args = checker.parse_known_args()[0]
    extra_args.extra = set(extra_args.extra) if extra_args.extra else []

    parser = argparse.ArgumentParser(prog="Tardigrade", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Server Configuration Arguments
    server_group = parser.add_argument_group("Server Configuration")

    server_group.add_argument("--port", "-p", type=int, default=configuration.port, dest="port",
                              help="the server port where Tardigrade will run")

    server_group.add_argument("--directory", "-d", type=str, default=configuration.directory, dest="directory",
                              help="directory to execute commands from")

    server_group.add_argument("--timeout", "-t", type=int, default=configuration.timeout, dest="timeout",
                              help="directory to serve files or execute commands from")

    server_group.add_argument("--output", "-O", type=str, default=configuration.output, dest="output",
                              help="Directory where to write files to")
    server_group.add_argument("--input", "-I", type=str, default=configuration.input, dest="input",
                              help="Directory to serve files from")
    # Log Configuration
    log_group = parser.add_argument_group(title="Logging Configuration")

    log_group.add_argument("--logserver", "-L", action="store_true", default=configuration.log_server,
                           dest="log_server",
                           help="Disables all own logging, will listen for POST logging from another Tardigrade and log its messages with this Tardigrade configuration")

    log_group.add_argument("--loglevel", "-l",
                           metavar="{q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}", type=str,
                           default=configuration.loglevel, dest="loglevel",
                           choices=["quiet", "debug", "info", "warn", "error", "critical", "q", "d", "i", "w", "e",
                                    "c"], help="logging level")

    log_group.add_argument("--options", "-o", nargs='*', default=configuration.options, dest="options",
                           choices=["no-color", "no-request", "no-response", "no-header", "no-body", "no-console",
                                    "no-banner"],
                           help="remove certain attributes from logging.")

    log_group.add_argument("--extra", "-e", action="append", dest="extra", default=configuration.extra,
                           choices=["file", "web"],
                           help="extra logger outputs")
    # Extra Logger Configuration
    extra_group = parser.add_argument_group(title="Extra Logger Options")

    extra_group.add_argument("--filename", "-f", type=str, default=configuration.filename,
                             help="only has an effect if file logger is enabled; filename for the log file")
    extra_group.add_argument("--maxbytes", "-x", type=int, default=configuration.max_bytes, dest="max_bytes",
                             help="only has an effect if file logger is enabled;max size of each file in bytes, if 0, file grows indefinitely")
    extra_group.add_argument("--count", "-c", metavar="FILECOUNT", type=int, default=configuration.count,
                             help="only has an effect if file logger is enabled; max amount of files to keep before rolling over, if 0, file grows indefinitely")

    extra_group.add_argument("--webhost", required="web" in extra_args.extra, default=configuration.web_host,
                             dest="web_host",
                             help="required if web logger is enabled; host for the listening log server, can include port like host:port")
    extra_group.add_argument("--weburl", required="web" in extra_args.extra, default=configuration.web_url,
                             dest="web_url",
                             help="required if web logger is enabled; url for the listening log server")
    extra_group.add_argument("--method", "-m", choices=["GET", "POST"], default=configuration.method,
                             help="only has an effect if web logger is enabled")
    extra_group.add_argument("--credentials", "-C", nargs=2, metavar=("userid", "password"),
                             required="secure" in extra_args.extra, default=configuration.credentials,
                             help="only has an effect if web logger is enabled; enables basic authentication with Authorization header")

    # Other Arguments
    parser.add_argument("--version", action="version", help="show Tardigrade version", version=__VERSION__)
    parser.epilog = ""

    return parser.parse_args()


def initialize_logger():
    global configuration

    # Get log level from single letter
    letter_to_word_map = {"I": "INFO", "D": "DEBUG", "W": "WARN", "E": "ERROR", "C": "CRITICAL", "Q": "QUIET"}
    log_level = configuration.loglevel.upper()
    log_level = letter_to_word_map[log_level] if log_level in letter_to_word_map else log_level

    string.Template("")

    if log_level != "QUIET":

        logger = logging.getLogger("root")
        logger.setLevel(logging.DEBUG if configuration.log_server else getattr(logging, log_level))

        # Configure handlers
        handlers = []
        if configuration.file_log:
            handlers.append(logging.handlers.RotatingFileHandler(configuration.filename, encoding=ENC,
                                                                 maxBytes=configuration.max_bytes,
                                                                 backupCount=configuration.count))
            configuration.file_enable = True

        if configuration.web_log:
            handlers.append(
                logging.handlers.HTTPHandler(configuration.web_host, configuration.web_url, method=configuration.method,
                                             secure=configuration.secure,
                                             credentials=tuple(configuration.credentials)))
            configuration.web_enable = True

        # Set same formatter for all the file handlers
        for h in handlers:
            h.setFormatter(
                TardigradeColorFormatter(log_formats=configuration.log_formats, extra_mappings=configuration.colors,
                                         color_enabled=False))

        if configuration.console:
            con = logging.StreamHandler()
            # Select color or plain formatter for console logger
            con.setFormatter(
                TardigradeColorFormatter(log_formats=configuration.log_formats, extra_mappings=configuration.colors,
                                         color_enabled=configuration.color))
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
        # noinspection PyArgumentList
        print((FULL_COLOR if configuration.color else "Monochromatic (boring) ") + "logging enabled. Level: " +
              logging.getLevelName(log.getEffectiveLevel()))

        if configuration.config_file:
            print("Configuration file loaded")
        else:
            print("Configuration file not found, running internal defaults.")

        if configuration.file_log:
            print(f"Logging in file: {configuration.filename}")

        if configuration.web_log:
            print(f"Logging in web at: {configuration.web_host}/{configuration.web_url}")


if __name__ == '__main__':
    run()
