"""<Small footprint SimpleHTTPServer implementation with nice logging and POST requests processing,
 meant for development work and simple testing>
Author: <Javier Darkona> <Javier.Darkona@Gmail.com>
Created: <14/06/2023>
"""
import argparse
import ast
import email.utils
import html
import io
import logging
import os
import signal
import socketserver
import string
import subprocess
import threading
import time
import urllib.parse
from datetime import datetime
from datetime import timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler
from typing import Any

import importlib_metadata
import psutil
import simplejson
import yaml

# Tardigrade ASCII art from> https://twitter.com/tardigradopedia/status/1289077195793674246 - modified by me
AUTHOR = "Javier.Darkona@Gmail.com"

TARDIGRADE_ASCII = " (꒰֎꒱) \n උ( ___ )づ\n උ( ___ )づ \n  උ( ___ )づ\n උ( ___ )づ"'\n'
FULL_COLOR = "\033[1;91mF\033[38;5;208mu\033[1;93ml\033[1;92ml \033[1;96mc\033[0;34mo\033[0;35ml\033[1;95mo\033[38;5;206mr\033[0m "

metadata = importlib_metadata.metadata("tardigrade")
__VERSION__ = metadata.json["version"]


class HEADERS:
    CONNECTION = 'Connection'
    CLOSE = 'Close'
    CONTENT_TYPE = 'Content-Type'
    CONTENT_LENGTH = 'Content-Length'
    SERVER = 'Server'
    DATE = 'Date'
    LOCATION = 'Location'
    IF_MODIFIED_SINCE = 'If-Modified-Since'
    IF_NONE_MATCH = 'If-None-Match'
    ACCEPT = 'Accept'
    AUTHORIZATION = 'Authorization'
    LAST_MODIFIED = 'Last-Modified'


APPLICATION_JSON = 'application/json'
TEXT_HTML = 'text/html'
TEXT_PLAIN = 'text/plain'


class TardigradeConfiguration(argparse.Namespace):
    # Configuration with all defaults, overriden by configuration file or running arguments
    configFile = False
    extra: list = []
    port = 8000
    directory = '/'
    input = '/input'
    output = '/output'
    timeout = 10
    logserver = False
    loglevel = 'info'
    options: list = []
    filename = '/output/logs/tardigrade.log'
    maxBytes = 0
    count = 0
    webhost = None
    weburl = None
    method = 'POST'
    secure = False
    credentials: tuple = ('', '')
    colors: dict = {}
    mimeTypes: argparse.Namespace()
    logFormats: argparse.Namespace()
    header, body, request, response, console, color, banner = True, True, True, True, True, True, True
    file_log = False
    web_log = False
    __mmtyp = {
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.bmp': 'image/bmp',
        '.svg': 'image/svg+xml',
        '.pdf': 'application/pdf',
        '.csv': 'text/csv',
        '.txt': 'text/plain',
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.json': 'application/json',
        '.xml': 'application/xml',
        '.zip': 'application/zip',
        '.tar': 'application/x-tar',
        '.rar': 'application/x-rar-compressed',
        '.7z': 'application/x-7z-compressed',
        '.rtf': 'application/x-sh',
        '.ttf': 'font/ttf',
        '.xhtml': 'application/xhtml+xml',
    }
    __fmts = {
        "NOCOLOR": "%(title)s %(banner)s - [%(levelname)s] %(asctime)s {%(funcName)s:%(lineno)d} - %(message)s",
        "DEFAULT": '%(pink)s%(title)s %(banner)s%(reset)s - %(dark_blue)s[%(levelname)s] %(purple)s%(asctime)s%('
                   'reset)s {%(funcName)s} (%(lineno)s) - %(message)s',
        "DEBUG": "%(pink)s%(title)s %(banner)s%(reset)s - %(dark_green)s[%(levelname)s] %(purple)s%(asctime)s %("
                 "dark_gray)s{%(funcName)s:%(lineno)s}%(blue)s %(message)s%(reset)s",
        "INFO": '%(pink)s%(title)s %(banner)s%(reset)s - %(aqua)s[%(levelname)s] %(purple)s%(asctime)s %(dark_gray)s{'
                '%(funcName)s:%(lineno)s}%(reset)s %(message)s%(reset)s',
        "WARNING": "%(pink)s%(title)s %(banner)s%(reset)s - %(orange)s[%(levelname)s] %(purple)s%(asctime)s %("
                   "dark_gray)s{%(funcName)s:%(lineno)s}%(yellow)s %(message)s%(reset)s",
        "ERROR": "%(pink)s%(title)s %(banner)s%(reset)s - %(red)s[%(levelname)s] %(purple)s%(asctime)s %(dark_gray)s{"
                 "%(funcName)s:%(lineno)s}%(red)s %(message)s%(reset)s",
        "CRITICAL": "%(pink)s%(title)s %(banner)s%(reset)s - %(dark_red)s[%(levelname)s] %(purple)s%(asctime)s %("
                    "dark_gray)s{%(funcName)s:%(lineno)s}%(red)s %(message)s%(reset)s",
    }

    def update(self, **kwargs):
        for name in kwargs:
            if isinstance(getattr(self, name), dict):
                getattr(self, name).update(**kwargs[name])
            if isinstance(getattr(self, name), argparse.Namespace):
                getattr(self, name).__dict__.update(kwargs[name])
            else:
                setattr(self, name, kwargs[name])
        # if self.options is None: self.options = []

        self.header = "no-header" not in self.options and not self.logserver
        self.body = "no-body" not in self.options and not self.logserver
        self.request = "no-request" not in self.options and not self.logserver
        self.response = "no-response" not in self.options and not self.logserver
        self.console = "no-console" not in self.options
        self.color = "no-color" not in self.options
        self.banner = "no-banner" not in self.options
        self.file_log = "file" in self.extra
        self.web_log = "web" in self.extra

    def __init__(self):
        self.logFormats = argparse.Namespace(**self.__fmts)
        self.mimeTypes = argparse.Namespace(**self.__mmtyp)
        super().__init__()


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

    def __init__(self, logFormats: argparse.Namespace = None, extra_mappings: dict[str, str] = None, color_enabled=True):
        super(TardigradeColorFormatter).__init__()
        self.other_mappings.update(extra_mappings)
        self.logFormats = logFormats
        self.color = color_enabled
        self.FORMATS = self.define_format()
        super().__init__()

    def colorPreFormatter(self, s):
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

    def default(self, a: str, b: str):
        return a or b

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
        try:
            parsingString = self.FORMATS.get(record.levelno)
            parsingString = self.colorPreFormatter(parsingString)
            formatter = logging.Formatter(parsingString)
            return formatter.format(record)
        except TypeError as e:
            logging.error(str(e))


class TardigradeCommandReturningThread(threading.Thread):

    def __init__(self, cwd: (str, []) = (), timeout: float = None):
        super().__init__()
        self.process = None
        self.stdout = None
        self.stderr = None
        self.process_name = None
        self.timeout = timeout
        self.cwd = cwd

    def run(self):
        self.process = subprocess.Popen(self.cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=None, shell=True, encoding='utf-8', text=True, bufsize=4096)
        logging.debug("Thread started with process: ")
        self.process_name = self.process.args[0]
        if self.timeout <= 0: self.process.wait()

    def go_nuclear(self):
        # If CTRL_C doesn't work, kill them with fire. This will cause self-termination
        for _ in psutil.Process(self.process.pid).children(recursive=True): _.send_signal(signal.CTRL_BREAK_EVENT)
        self.stdout, self.stderr = self.process.stdout.read(), self.process.stderr.read()

    def anakin_order_66(self):
        # Kill all children
        try:
            for _ in psutil.Process(self.process.pid).children(recursive=True): _.kill()
        except psutil.NoSuchProcess:
            logging.warning("What is dead cannot die")

    def join(self, timeout: float | None = ...) -> None:
        logging.debug("finalizing thread")
        if self.timeout > 0:
            try:
                self.stdout, self.stderr = self.process.communicate(timeout=self.timeout, input=None)
            except subprocess.TimeoutExpired as e:
                logging.debug("Process timed out." + str(e))
                self.anakin_order_66()
        else:
            self.anakin_order_66()

        try:
            self.stdout, self.stderr = self.process.communicate(input=None)
        except Exception as e:
            logging.error(str(e))

        super().join()

    def result(self):
        return self.stdout, self.stderr


log = logging.Logger
ENC = 'utf-8'
th: TardigradeCommandReturningThread = None
cfg: TardigradeConfiguration = TardigradeConfiguration()


class TardigradeRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, request: bytes, client_address: tuple[str, int], server: socketserver.BaseServer, cfg: TardigradeConfiguration):
        self._headers_buffer = []
        self.server_version = "TardigradeHTTP/" + __VERSION__
        self.extensions_map.update(cfg.mimeTypes.__dict__.items())
        self.cfg = config
        super().__init__(request, client_address, server)

    def prepare_error(self, code: HTTPStatus, message: str = None, explain: str = None):
        try:
            shortMsg, longMsg = self.responses[code]
        except KeyError:
            shortMsg, longMsg = '???', '???'
        if message is None:
            message = shortMsg
        if explain is None:
            explain = longMsg
        self.send_response(code, message)
        self.send_header(HEADERS.CONNECTION, HEADERS.CLOSE)
        body = None
        if (code >= 200 and
                code not in (HTTPStatus.NO_CONTENT,
                             HTTPStatus.RESET_CONTENT,
                             HTTPStatus.NOT_MODIFIED)):
            content = (self.error_message_format % {
                'code': code,
                'message': html.escape(message, quote=False),
                'explain': html.escape(explain, quote=False)
            })
            body = content.encode(ENC, 'replace')
            self.send_header(HEADERS.CONTENT_TYPE, self.error_content_type)
            self.send_header(HEADERS.CONTENT_LENGTH, str(len(body)))
            self.end_headers()
        if self.command != 'HEAD' and body:
            self.wfile.write(body)
        return body

    def prepare_log_request(self, body):
        message = '\n--- REQUEST: ' + self.requestline
        if cfg.header: message += "\nHEADER:\n" + str(self.headers)
        if cfg.body and body: message += "BODY:\n" + body
        return message

    def prepare_log_response(self, code: HTTPStatus = None, msg: str = None, body=None):
        if isinstance(code, HTTPStatus): code = code.value
        try:
            shortMsg, longMsg = self.responses[code]
        except KeyError:
            shortMsg, longMsg = '???', '???'
        if msg is None: msg = shortMsg
        output = '\n --- RESPONSE: HTTP Status - ' + str(code) + "-" + msg
        if cfg.header: output += "\nHEADER:\n" + ''.join(item.decode() for item in self._headers_buffer)
        if cfg.body: output += "\nBODY: \n" + body if body else ''
        return output

    def do_LogServe(self, content_type):
        if content_type != "application/x-www-form-urlencoded":
            raise TypeError("Incorrect content type. Should be: application/x-www-form-urlencoded")
        request_data = self.rfile.read(int(self.headers[HEADERS.CONTENT_LENGTH]))
        # Gotta parse this thing like 3 times -____-
        parsed = urllib.parse.unquote(request_data.decode('utf-8'))
        broken_request = urllib.parse.parse_qs(parsed)
        log_request = {key: value[0] for key, value in broken_request.items()}
        # And clean it up
        log_request['args'] = ast.literal_eval(log_request['args'])
        for key, value in log_request.items():
            if isinstance(value, str):
                if value.isdigit():
                    log_request[key] = int(value)
                elif value.replace('.', '', 1).isdigit():
                    log_request[key] = float(value)
                else:
                    pass
            if value == 'None':
                log_request[key] = ''
        log.callHandlers(logging.makeLogRecord(log_request))
        self.send_response(HTTPStatus.OK)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len("OK")))
        if cfg.response: log.info(self.prepare_log_response(HTTPStatus.OK))
        self.end_headers()

    def do_GET(self):
        if cfg.logserver:
            return self.do_LogServe(self.headers.get(HEADERS.CONTENT_TYPE))
        if cfg.request: log.info(self.prepare_log_request(None))
        try:
            file = self.do_Common(default_filenames=("index.html", "index.htm"))
            try:
                if file:
                    if cfg.response: log.info(self.prepare_log_response(code=HTTPStatus.OK, body=file[1]))
                    self.end_headers()
                    self.copyfile(file[0], self.wfile)
            except Exception as e:
                raise e
            finally:
                file[0].close()
        except Exception as e:
            msg = "Problem while serving GET request: " + str(e)
            log.warning(msg)
            body = self.prepare_error(code=HTTPStatus.INTERNAL_SERVER_ERROR, explain=msg)
            if cfg.response: log.info(self.prepare_log_response(body))
            self.end_headers()

    def do_HEAD(self):
        if cfg.request: log.info(self.prepare_log_request(None))
        try:
            file = self.do_Common(default_filenames=("index.html", "index.htm"))
            try:
                if file:
                    if cfg.response: log.info(self.prepare_log_response(body=file[1], code=HTTPStatus.OK))
                    self.end_headers()
            except Exception as e:
                raise e
            finally:
                file[0].close()
        except Exception as e:
            msg = "Problem while serving HEAD request: " + str(e)
            log.warning(msg)
            body = self.prepare_error(HTTPStatus.INTERNAL_SERVER_ERROR, explain=msg)
            if cfg.response: log.info(self.prepare_log_response(body))
            self.end_headers()

    def do_POST(self):
        if cfg.logserver:
            return self.do_LogServe(self.headers.get(HEADERS.CONTENT_TYPE))
        else:
            log.debug("Received POST request")
            response_body, status, explain = None, None, None
            action = ''
            try:

                if HEADERS.CONTENT_TYPE not in self.headers:
                    raise TypeError("No Content-Type HEADER")

                content_type = self.headers.get(HEADERS.CONTENT_TYPE)

                log.debug('Normal server active')

                request_data = self.rfile.read(int(self.headers[HEADERS.CONTENT_LENGTH]))

                part = self.path.split('/')[1]
                if part in ["command", "mock", "log", "stop", "write"]:

                    try:
                        request_body = simplejson.dumps(simplejson.loads(request_data), sort_keys=True, indent=4 * ' ')
                    except simplejson.JSONDecodeError:
                        raise TypeError("Badly formatted JSON")

                    if cfg.request: log.info(self.prepare_log_request(request_body))

                    match part:

                        case "command":
                            log.debug("Calling command endpoint")
                            if content_type != APPLICATION_JSON:
                                raise TypeError("Incorrect content type. Should be: application/json")

                            data = simplejson.loads(request_data)

                            if "cmd" in data and "args" in data:

                                cmd_response = self.run_command(command=data["cmd"], arg_list=data["args"])
                            elif "single_line" in data and data["single_line"] != '':
                                cmd_response = self.run_command(command=data["single_line"])
                            else:
                                raise TypeError("Either no 'single_line' or no 'cmd' and 'args' pair")

                            response_body = simplejson.dumps(cmd_response[1], indent=4 * ' ')
                            status = cmd_response[0]
                            log.debug("Command endpoint exiting.")

                        case "mock":
                            log.debug("Calling mock endpoint")
                            action = 'mock'
                            self.path = self.path.replace("/mock", "", 1)

                            file = self.do_Common(default_filenames=["response.json"])

                            try:
                                if file:
                                    if cfg.response: log.info(self.prepare_log_response(code=HTTPStatus.OK, body=file[1]))
                                    # response_body = file[1]
                                    status = HTTPStatus.OK
                                    self.end_headers()
                                    self.copyfile(file[0], self.wfile)
                                    return
                            finally:
                                file[0].close()

                        case "log":
                            log.debug("Calling mock endpoint")
                            status = HTTPStatus.OK

                        case "stop":
                            log.debug("Calling mock endpoint")
                            response_body, status = self.stop_command()

                        case "write":
                            log.debug("Calling write endpoint")
                            if content_type != APPLICATION_JSON:
                                raise TypeError("Incorrect content type. Should be: application/json")

                            data = simplejson.loads(request_data)

                            if "filename" in data and "content" in data:

                                operation = "w"
                                operation_verb = "written"

                                if 'mode' in data:
                                    match data["mode"]:
                                        case "append" | "a":
                                            operation = "a"
                                            operation_verb = "appended"
                                        case "create" | "c":
                                            operation = "x"
                                            operation_verb = "created"
                                        case "overwrite" | "w":
                                            pass
                                        case None:
                                            raise TypeError("Incorrect mode specified")

                                if 'type' in data:
                                    match data["type"]:
                                        case "text" | "t":
                                            operation += "t"
                                        case "binary" | "b":
                                            operation += "b"
                                        case None:
                                            raise TypeError("Incorrect type specified")

                                path = self.translate_path(cfg.output + "/" + data["filename"])

                                file = open(path, operation, encoding=ENC)
                                file.write(data["content"])
                                file.flush()
                                fs = os.fstat(file.fileno())
                                file.close()

                                response_body = simplejson.dumps({
                                    'message': f'File {data["filename"]} {operation_verb}',
                                    'filesize': fs[6]
                                })

                                status = HTTPStatus.OK
                                log.debug("Command endpoint exiting.")
                            else:
                                raise TypeError("No filename or content")
                        case None:
                            log.debug("Calling non-existent endpoint")
                            status = HTTPStatus.NOT_FOUND
                else:
                    status = HTTPStatus.NOT_FOUND

            except Exception as e:

                self.flush_headers()
                msg = "Problem while serving POST request: " + str(e)
                log.warning(msg)
                status = HTTPStatus.INTERNAL_SERVER_ERROR
                if isinstance(e, TypeError):
                    status = HTTPStatus.BAD_REQUEST
                if isinstance(e, FileNotFoundError):
                    status = HTTPStatus.NOT_FOUND
                explain = msg

            finally:

                if action != 'mock':
                    self.send_response(status)
                    self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)
                    self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)
                    self.send_header(HEADERS.CONTENT_TYPE, APPLICATION_JSON)
                    self.end_headers()
                    if response_body:
                        self.wfile.write(response_body.encode(ENC))
                if cfg.response: log.info(self.prepare_log_response(code=HTTPStatus.OK, body=response_body, msg=explain))

    def do_DELETE(self):

        if cfg.request:
            log.info(self.prepare_log_request(None))

        response_body, status = self.stop_command()
        self.send_response(status)

        self.send_header(HEADERS.CONTENT_TYPE, APPLICATION_JSON)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)

        if cfg.response:
            log.info(self.prepare_log_response(status, body=response_body if response_body else ''))

        self.end_headers()
        self.wfile.write(response_body.encode('utf-8'))

    def stop_command(self):

        response_body = None

        if th is not None and th.is_alive():
            log.debug("Process exists, sending stop signal.")
            th.join()

            if th.is_alive():
                log.error("Process not stopping, I'm killing myself and all my children processes now.")
                th.go_nuclear()
                status = HTTPStatus.INTERNAL_SERVER_ERROR
                if th.is_alive():
                    log.critical("Something is very wrong.")
                    response_body = simplejson.dumps({"error": "Process still running"}, indent=4 * ' ')
                    status = HTTPStatus.INTERNAL_SERVER_ERROR
            else:
                status = HTTPStatus.OK
                log.debug("Process stopped, sending response")
                stdout, stderr = th.result()
                response_body = simplejson.dumps({"error": stderr, "output": stdout}, indent=4 * ' ')
        else:
            status = HTTPStatus.NOT_FOUND
            response_body = simplejson.dumps({"message": "No process running"}, indent=4 * ' ')
        return response_body, status

    def do_Common(self, default_filenames):

        # path = urllib.parse.unquote(self.path)
        self.path = cfg.input + "/" + self.path
        path = self.translate_path(self.path)
        log.debug(f"PATH: {path}")

        if os.path.isdir(path):
            log.debug("PATH points to directory instead of file, looking for index files")
            parts = urllib.parse.urlsplit(self.path)

            if not parts.path.endswith('/'):
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/', parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.send_header(HEADERS.SERVER, self.version_string())
                self.send_header(HEADERS.DATE, self.date_time_string())
                self.send_header(HEADERS.LOCATION, new_url)
                self.send_header(HEADERS.CONTENT_LENGTH, "0")
                self.prepare_log_response(HTTPStatus.MOVED_PERMANENTLY)

                if cfg.response: log.info(self.prepare_log_response())

            for index in default_filenames:
                if os.path.isfile(os.path.join(path, index)):
                    path = os.path.join(path, index)
                    break
            else:
                log.debug("No index found, serving directory list")
                return [self.list_directory(path), "List for: " + path]

        ctype = self.guess_type(path)

        if path.endswith("/"):
            msg = "File " + path + " not found"
            log.warning(msg)
            body = self.prepare_error(HTTPStatus.NOT_FOUND, explain=msg)
            if cfg.response: log.info(self.prepare_log_response(body))
            return None

        try:
            file = open(path, 'rb')
        except OSError as e:
            msg = "OS error: " + str(e)
            log.warning(msg)
            body = self.prepare_error(HTTPStatus.NOT_FOUND, explain=msg)
            if cfg.response: log.info(self.prepare_log_response(body))
            return None

        log.debug("File '" + path + "' found")

        try:
            fs = os.fstat(file.fileno())
            if HEADERS.IF_MODIFIED_SINCE in self.headers and HEADERS.IF_NONE_MATCH not in self.headers:

                log.debug("If-Modified-Since header found in request, attempting to parse.")

                try:
                    ims = email.utils.parsedate_to_datetime(self.headers[HEADERS.IF_MODIFIED_SINCE])
                except (TypeError, IndexError, OverflowError, ValueError):
                    log.debug("Error at parsing date from headers")

                else:
                    if ims.tzinfo is None:
                        ims = ims.replace(tzinfo=timezone.utc)

                    if ims.tzinfo is timezone.utc:
                        log.debug("Comparing file timestamp to If-Modified-Since")
                        last_modif = datetime.fromtimestamp(fs.st_mtime, timezone.utc)
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            log.warning("Modified not matching, sending NOT_MODIFIED")
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            file.close()
                            return None

            self.send_response(HTTPStatus.OK)
            self.send_header(HEADERS.CONTENT_TYPE, ctype)
            self.send_header(HEADERS.CONTENT_LENGTH, str(fs[6]))
            self.send_header(HEADERS.LAST_MODIFIED, self.date_time_string(int(fs.st_mtime)))
            return [file, path]

        except Exception as e:
            file.close()
            raise e

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header(HEADERS.SERVER, self.version_string())
        self.send_header(HEADERS.DATE, self.date_time_string())

    def list_directory(self, path):
        try:
            itemList = os.listdir(path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None
        itemList.sort(key=lambda a: a.lower())
        r = []
        try:
            displayPath = urllib.parse.unquote(self.path, errors='surrogatepass')
        except UnicodeDecodeError:
            displayPath = urllib.parse.unquote(self.path)
        displayPath = html.escape(displayPath, quote=False)
        title = f'Directory listing for {displayPath}'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{ENC}">')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name in itemList:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            r.append('<li><a href="%s">%s</a></li>'
                     % (urllib.parse.quote(linkname, errors='surrogatepass'),
                        html.escape(displayname, quote=False)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(ENC, 'surrogateescape')
        file = io.BytesIO()
        file.write(encoded)
        file.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header(HEADERS.CONTENT_TYPE, TEXT_HTML + ";charset=%s" % ENC)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len(encoded)))
        return file

    def send_header(self, keyword, value):
        """Send a MIME header to the headers buffer."""
        if self.request_version != 'HTTP/0.9':
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            val = ("%s: %s\r\n" % (keyword, value))
            if not any(header.decode('latin-1', 'strict').startswith(val.split(":")[0]) for header in
                       self._headers_buffer):
                self._headers_buffer.append(val.encode('latin-1', 'strict'))

        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = True
            elif value.lower() == 'keep-alive':
                self.close_connection = False

    def run_command(self, command: str = '', arg_list: (str, []) = ()) -> [HTTPStatus, dict[str, str]]:
        cwd = [command]
        global th
        if arg_list: cwd.extend(arg_list)
        log.debug("Received command: " + " ".join(cwd) + "\nexecuting...\n")
        if th is None or not th.is_alive():
            th = TardigradeCommandReturningThread(cwd=cwd, timeout=cfg.timeout)
            try:
                log.debug("Created thread, starting")
                th.start()
                if cfg.timeout <= 0:
                    return [HTTPStatus.OK, {"error": None, "output": "Process " + cwd[0] + " has been started and is now running."}]
                time.sleep(0.1)
                th.join()
                log.debug("Thread finished, obtaining results")
                stdout, stderr = th.result()
                return [HTTPStatus.OK, {"error": stderr, "output": stdout}]
            except subprocess.TimeoutExpired:
                stdout, stderr = th.result()
                return [HTTPStatus.REQUEST_TIMEOUT, {"error": stderr, "output": stdout}]
            finally:
                if cfg.timeout > 0: th = None
        else:
            return [HTTPStatus.LOCKED, {'error': 'Another process already running: ' + th.process_name}]

    # Overrides to bury ugly, useless logs
    def log_request(self, code: int | str = ..., size: int | str = ...) -> None:
        pass

    def log_error(self, format: str, *args: Any) -> None:
        pass


def initialize_logger(c: TardigradeConfiguration):
    # Get log level from single letter
    letter_to_word_map = {"I": "INFO", "D": "DEBUG", "W": "WARN", "E": "ERROR", "C": "CRITICAL", "Q": "QUIET"}
    log_level = c.loglevel.upper()
    log_level = letter_to_word_map[log_level] if log_level in letter_to_word_map else log_level

    string.Template("")

    if log_level != "QUIET":

        logger = logging.getLogger("root")
        logger.setLevel(logging.DEBUG if c.logserver else getattr(logging, log_level))

        # Configure handlers
        handlers = []
        if c.file_log:
            handlers.append(logging.handlers.RotatingFileHandler(c.filename, encoding=ENC, maxBytes=c.maxBytes, backupCount=c.count))
            c.file_enable = True

        if c.web_log:
            handlers.append(logging.handlers.HTTPHandler(c.webhost, c.weburl, method=c.method, secure=c.secure, credentials=tuple(c.credentials)))
            c.web_enable = True

        # Set same formatter for all the file handlers
        for h in handlers:
            h.setFormatter(TardigradeColorFormatter(logFormats=c.logFormats, extra_mappings=c.colors, color_enabled=False))

        if c.console:
            con = logging.StreamHandler()
            # Select color or plain formatter for console logger
            con.setFormatter(TardigradeColorFormatter(logFormats=c.logFormats, extra_mappings=c.colors, color_enabled=c.color))
            handlers.append(con)

        for h in handlers:
            logger.addHandler(h)
        return logger, c


def print_initialization(httpd):
    if cfg.console:
        if cfg.banner:
            if cfg.color:
                print(f'\033[38;5;206m{TARDIGRADE_ASCII}\033[0m')
            else:
                print(TARDIGRADE_ASCII)

        print(f"Tardigrade Server version {__VERSION__} is running. Listening at: {httpd.server_name}:{str(cfg.port)}")
        print(f"Writting files to {cfg.output}, reading files from {cfg.input}")
        print((FULL_COLOR if cfg.color else "Monochromatic (boring) ") + "logging enabled. Level: " + logging.getLevelName(log.getEffectiveLevel()))
        if cfg.configFile:
            print("Configuration file loaded")
        if cfg.file_log: print(f"Logging in file: {cfg.filename}")
        if cfg.web_log: print(f"Logging in web at: {cfg.webhost}/{cfg.weburl}")


def run():
    global cfg
    global log
    # Initialize http server
    server_address = ('localhost', int(cfg.port))
    # handler = partial(TardigradeRequestHandler, cfg=cfg) Partial to pass cfg to nadler, but nah, i dont feel like typing self a hundred times
    httpd = HTTPServer(server_address, TardigradeRequestHandler)
    httpd.timeout = cfg.timeout if cfg.timeout > 0 or cfg.logserver else None
    log, cfg = initialize_logger(cfg)

    print_initialization(httpd)

    try:
        if not cfg.logserver:
            log.info("Tardigrade started")
        else:
            print("Tardigrade started as Log Server")
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not cfg.logserver:
            log.info('Tardigrade stopped...\n')
        else:
            print("Tardigrade stopped as Log Server")
    httpd.server_close()


def get_args(c: TardigradeConfiguration):
    checker = argparse.ArgumentParser(add_help=False)

    checker.add_argument("--extra", "-e", action="append", dest="extra", choices=["file", "web"], help="extra logger outputs")
    checker.add_argument("--secure", "-s", action="store_true", help="[WEB LOGGER]")
    extra_args = checker.parse_known_args()[0]
    extra_args.extra = set(extra_args.extra) if extra_args.extra else []

    parser = argparse.ArgumentParser(prog="Tardigrade", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Server Configuration Arguments
    server_group = parser.add_argument_group("Server Configuration")

    server_group.add_argument("--port", "-p", type=int, default=c.port, dest="port", help="the server port where Tardigrade will run")

    server_group.add_argument("--directory", "-d", type=str, default=c.directory, dest="directory", help="directory to execute commands from")

    server_group.add_argument("--timeout", "-t", type=int, default=c.timeout, dest="timeout", help="directory to serve files or execute commands from")

    server_group.add_argument("--output", "-O", type=str, default=c.output, dest="output", help="Directory where to write files to")
    server_group.add_argument("--input", "-I", type=str, default=c.input, dest="input", help="Directory to serve files from")
    # Log Configuration
    log_group = parser.add_argument_group(title="Logging Configuration")

    log_group.add_argument("--logserver", "-L", action="store_true", default=c.logserver, dest="logserver",
                           help="Disables all own logging, will listen for POST logging from another Tardigrade and log its messages with this Tardigrade configuration")

    log_group.add_argument("--loglevel", "-l", metavar="{q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}", type=str, default=c.loglevel, dest="loglevel",
                           choices=["quiet", "debug", "info", "warn", "error", "critical", "q", "d", "i", "w", "e", "c"], help="logging level")

    log_group.add_argument("--options", "-o", nargs='*', default=c.options, dest="options", choices=["no-color", "no-request", "no-response", "no-header", "no-body", "no-console", "no-banner"],
                           help="remove certain attributes from logging.")

    log_group.add_argument("--extra", "-e", action="append", dest="extra", default=c.extra, choices=["file", "web"], help="extra logger outputs")
    # Extra Logger Configuration
    extra_group = parser.add_argument_group(title="Extra Logger Options")

    extra_group.add_argument("--filename", "-f", type=str, default=c.filename, help="only has an effect if file logger is enabled; filename for the log file")
    extra_group.add_argument("--maxbytes", "-x", type=int, default=c.maxBytes, dest="maxBytes",
                             help="only has an effect if file logger is enabled;max size of each file in bytes, if 0, file grows indefinitely")
    extra_group.add_argument("--count", "-c", metavar="FILECOUNT", type=int, default=c.count,
                             help="only has an effect if file logger is enabled; max amount of files to keep before rolling over, if 0, file grows indefinitely")

    extra_group.add_argument("--webhost", required="web" in extra_args.extra, default=c.webhost, dest="webhost",
                             help="required if web logger is enabled; host for the listening log server, can include port like host:port")
    extra_group.add_argument("--weburl", required="web" in extra_args.extra, default=c.weburl, dest="weburl", help="required if web logger is enabled; url for the listening log server")
    extra_group.add_argument("--method", "-m", choices=["GET", "POST"], default=c.method, help="only has an effect if web logger is enabled")
    extra_group.add_argument("--credentials", "-C", nargs=2, metavar=("userid", "password"), required="secure" in extra_args.extra, default=c.credentials,
                             help="only has an effect if web logger is enabled; enables basic authentication with Authorization header")

    # Other Arguments
    parser.add_argument("--version", action="version", help="show Tardigrade version", version=__VERSION__)
    parser.epilog = ""

    return parser.parse_args()


if __name__ == '__main__':
    cfg = TardigradeConfiguration()

    try:
        with open("config/config.yaml") as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            cfg.update(**config)
            cfg.configFile = True
    except FileNotFoundError:
        pass
    finally:
        cfg.update(**get_args(cfg).__dict__)
    try:
        for s in [cfg.output, cfg.input]:
            p = os.path.join(os.getcwd(), s)
            if not os.path.exists(p): os.makedirs(p)
    except OSError:
        pass
    run()
