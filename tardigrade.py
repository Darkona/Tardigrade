"""<Small footprint SimpleHTTPServer implementation with nice logging and POST requests processing,
 meant for development work and simple testing>
Author: <Javier Darkona> <Javier.Darkona@Gmail.com>
Created: <14/06/2023>
"""
import argparse
import ast
import email.utils
import http.server

import html
import io
import logging
import os
import socketserver
import string
import subprocess
import time
import urllib.parse
from datetime import datetime
from datetime import timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler
from typing import Any
import yaml

import simplejson

from tardigrade_colors import ColorFormatter, Colors, HEADERS, MimeTypes
from tardigrade_commands import CommandThread

# Tardigrade ASCII art from> https://twitter.com/tardigradopedia/status/1289077195793674246 - modified by me
AUTHOR = "Javier.Darkona@Gmail.com"

TARDIGRADE_ASCII = " (꒰֎꒱) \n උ( ___ )づ\n උ( ___ )づ \n  උ( ___ )づ\n උ( ___ )づ"'\n'
VERSION = "Tardigrade-1.0"

cfg: argparse.Namespace

# Console

log = None
ENC = 'utf-8'
th: CommandThread

class TardigradeRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, request: bytes, client_address: tuple[str, int], server: socketserver.BaseServer):
        self._headers_buffer = []
        self.server_version = "TardigradeHTTP/" + VERSION
        self.extensions_map.update(cfg.mimetypes)


        super().__init__(request, client_address, server, directory=_directory_serve)

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
        if cfg.header  : message += "\nHEADER:\n" + str(self.headers)
        if cfg.body   and body: message += "BODY:\n" + body
        return message

    def prepare_log_response(self, code: HTTPStatus = None, msg: str = None, body=None):
        if isinstance(code, HTTPStatus): code = code.value
        try:
            shortMsg, longMsg = self.responses[code]
        except KeyError:
            shortMsg, longMsg = '???', '???'
        if msg is None: msg = shortMsg
        output = '\n --- RESPONSE: HTTP Status - ' + str(code) + "-" + msg
        if cfg.header  : output += "\nHEADER:\n" + ''.join(item.decode() for item in self._headers_buffer)
        if cfg.body  : output += "\nBODY: \n" + body if body else ''
        return output

    def do_GET(self):
        if cfg.request: log.info(self.prepare_log_request(None))
        try:
            f = self.do_Common(default_filenames=("index.html", "index.htm"))
            try:
                if f:
                    if cfg.response: log.info(self.prepare_log_response(code=HTTPStatus.OK, body=f[1]))
                    self.end_headers()
                    self.copyfile(f[0], self.wfile)
            except Exception as e:
                raise e
            finally:
                f[0].close()
        except Exception as e:
            msg = "Problem while serving GET request: " + str(e)
            log.warning(msg)
            body = self.prepare_error(code=HTTPStatus.INTERNAL_SERVER_ERROR, explain=msg)
            if cfg.response: log.info(self.prepare_log_response(body))
            self.end_headers()

    def do_HEAD(self):
        if cfg.request: log.info(self.prepare_log_request(None))
        try:
            f = self.do_Common(default_filenames=("index.html", "index.htm"))
            try:
                if f:
                    if cfg.response: log.info(self.prepare_log_response(body=f[1], code=HTTPStatus.OK))
                    self.end_headers()
            except Exception as e:
                raise e
            finally:
                f[0].close()
        except Exception as e:
            msg = "Problem while serving HEAD request: " + str(e)
            log.warning(msg)
            body = self.prepare_error(HTTPStatus.INTERNAL_SERVER_ERROR, explain=msg)
            if cfg.response: log.info(self.prepare_log_response(body))
            self.end_headers()

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

    def do_POST(self):

        log.debug("Received POST request")
        response_body, status, explain = None, None, None

        try:

            if HEADERS.CONTENT_TYPE not in self.headers:
                raise TypeError("No Content-Type HEADER")

            content_type = self.headers.get(HEADERS.CONTENT_TYPE)

            if cfg.logserver:

                log.debug('Log server active')
                return self.do_LogServe(content_type)

            else:

                log.debug('Normal server active')

                request_data = self.rfile.read(int(self.headers[HEADERS.CONTENT_LENGTH]))

                part = self.path.split('/')[1]
                if part in ["command", "mock", "log", "stop"]:

                    try:
                        request_body = simplejson.dumps(simplejson.loads(request_data), sort_keys=True, indent=4 * ' ')
                    except simplejson.JSONDecodeError:
                        raise TypeError("Badly formatted JSON")

                    if cfg.request: log.info(self.prepare_log_request(request_body))

                    match part:

                        case "command":
                            log.debug("Calling command endpoint")
                            if content_type != MimeTypes.APPLICATION_JSON:
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

                            self.path = self.path.replace("/mock", "", 1)
                            f = self.do_Common(default_filenames=["response.json"])

                            try:
                                if f:
                                    response_body = f[1]
                                    status = HTTPStatus.OK
                                    self.end_headers()
                                    self.copyfile(f[0], self.wfile)
                            finally:
                                f[0].close()

                        case "log":
                            log.debug("Calling mock endpoint")
                            status = HTTPStatus.OK

                        case "stop":
                            log.debug("Calling mock endpoint")
                            response_body, status = self.stop_command()

                        case None:
                            log.debug("Calling non-existent endpoint")
                            status = HTTPStatus.NOT_FOUND
                else:
                    status = HTTPStatus.NOT_FOUND
        except Exception as e:
            self.flush_headers()
            msg = "Problem while serving POST request: " + str(e)
            log.warning(msg)
            status = HTTPStatus.BAD_REQUEST if isinstance(e, TypeError) else HTTPStatus.INTERNAL_SERVER_ERROR
            explain = msg

        finally:

            self.send_response(status)
            self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)
            self.send_header(HEADERS.CONTENT_TYPE, MimeTypes.APPLICATION_JSON)
            if cfg.response: log.info(self.prepare_log_response(code=HTTPStatus.OK, body=response_body, msg=explain))
            self.end_headers()
            if response_body:
                self.wfile.write(response_body.encode(ENC))

    def do_DELETE(self):
        if cfg.request: log.info(self.prepare_log_request(None))
        response_body, status = self.stop_command()
        self.send_response(status)

        self.send_header(HEADERS.CONTENT_TYPE, MimeTypes.APPLICATION_JSON)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)
        if cfg.response: log.info(
            self.prepare_log_response(status, body=response_body.decode(ENC) if response_body else ''))
        self.end_headers()
        self.wfile.write(response_body)

    def stop_command(self):
        response_body = None
        if th is not None and th.is_alive():
            log.debug("Process exists, sending stop signal.")
            th.join()
            status = HTTPStatus.OK

            if th.is_alive():
                log.error("Process not stopping, I'm killing myself and all my children processes now.")
                th.go_nuclear()
                if th.is_alive():
                    log.critical("Something is very wrong.")
                    response_body = "Process still running".encode('utf-8')
                    status = HTTPStatus.INTERNAL_SERVER_ERROR
            else:
                log.debug("Process stopped, sending response")
                stdout, stderr = th.result()
                response_body = simplejson.dumps({"error": stderr, "output": stdout}, indent=4 * ' ').encode('utf-8')

        else:
            status = HTTPStatus.NOT_FOUND
            response_body = "No process running".encode('utf-8')
        return response_body, status

    def do_Common(self, default_filenames):

        # path = urllib.parse.unquote(self.path)
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
                self.end_headers()

            for index in default_filenames:
                if os.path.isfile(os.path.join(path, index)):
                    path = index
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
            f = open(path, 'rb')
        except OSError as e:
            msg = "OS error: " + str(e)
            log.warning(msg)
            body = self.prepare_error(HTTPStatus.NOT_FOUND, explain=msg)
            if cfg.response: log.info(self.prepare_log_response(body))
            return None

        log.debug("File '" + path + "' found")

        try:
            fs = os.fstat(f.fileno())
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
                            f.close()
                            return None

            self.send_response(HTTPStatus.OK)
            self.send_header(HEADERS.CONTENT_TYPE, ctype)
            self.send_header(HEADERS.CONTENT_LENGTH, str(fs[6]))
            self.send_header(HEADERS.LAST_MODIFIED, self.date_time_string(int(fs.st_mtime)))
            return [f, path]

        except Exception as e:
            f.close()
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
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header(HEADERS.CONTENT_TYPE, MimeTypes.TEXT_HTML + ";charset=%s" % ENC)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len(encoded)))
        return f

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
            th = CommandThread(cwd=cwd, timeout=cfg.timeout)
            try:
                log.debug("Created thread, starting")
                th.start()
                if cfg.timeout <= 0:
                    return [HTTPStatus.OK, {"error": None, "output": "Process " + cwd[0] + " is running."}]
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
            return [HTTPStatus.LOCKED, {'error': 'Another process already running'}]

    # Overrides to bury ugly, useless logs
    def log_request(self, code: int | str = ..., size: int | str = ...) -> None:
        pass

    def log_error(self, format: str, *args: Any) -> None:
        pass


def initialize_logger(cfg: argparse.Namespace):
    # Get log level from single letter
    letter_to_word_map = {"I": "INFO", "D": "DEBUG", "W": "WARN", "E": "ERROR", "C": "CRITICAL", "Q": "QUIET"}
    log_level = cfg.loglevel.upper()
    log_level = letter_to_word_map[log_level] if log_level in letter_to_word_map else log_level
    console_fmt = 'Line:%(lineno)d : [%(funcName)s] %(message)s'
    file_fmt = "%(aqua)s%(title)s %(pink)s%(banner)s%(reset)s - %(purple)s%(asctime)s %(reset)s[%(levelname)s] %(funcName)s Line:%(lineno)d : %(message)s"

    string.Template("")

    if log_level != "QUIET":

        logger = logging.getLogger("root")
        logger.setLevel(logging.DEBUG if cfg.logserver else getattr(logging, log_level))

        # Configure handlers
        handlers = []
        if "file" in cfg.extra:
            handlers.append(logging.handlers.RotatingFileHandler(cfg.filename, encoding='utf-8',
                                                                 maxBytes=cfg.maxbytes, backupCount=cfg.count))
            cfg.file_enable = True

        if "web" in cfg.extra:
            handlers.append(logging.handlers.HTTPHandler(cfg.host, cfg.url, method=cfg.method,
                                                         secure=cfg.secure, credentials=cfg.credentials))
            cfg.web_enable = True
        # Set same formatter for all the file handlers
        for h in handlers:
            h.setFormatter(ColorFormatter(console_fmt))
            # h.setFormatter(logging.Formatter(file_fmt))

        if cfg.console:
            con = logging.StreamHandler()
            # Select color or plain formatter for console logger
            con.setFormatter(
                ColorFormatter(console_fmt) if cfg.color else logging.Formatter(file_fmt))
            handlers.append(con)

        for h in handlers:
            logger.addHandler(h)
        return logger, cfg


def run(server_class=HTTPServer, handler_class=TardigradeRequestHandler, cfg=None):
    # Initialize http server
    server_address = ('localhost', int(cfg.port))
    httpd = server_class(server_address, handler_class)
    httpd.timeout = cfg.timeout
    if cfg.console:
        if cfg.banner:
            if cfg.color:
                print(f'{Colors.pink}{TARDIGRADE_ASCII}{Colors.reset}')
            else:
                print(TARDIGRADE_ASCII)

        print('Tardigrade Server is running. Listening at: ' + httpd.server_name + ":" + str(cfg.port))
        print('GET requests serving files from: ' + (cfg.directory if cfg.directory != '' else 'same folder.'))
        print(("Full color " if cfg.color else "Monochromatic (boring) ") + "logging enabled. Level: " +
              logging.getLevelName(log.getEffectiveLevel()))
        if hasattr(cfg, "file_enabled"): print("Logging in file: " + cfg["filename"])
        if hasattr(cfg, "file_web"): print("Logging in web at: " + cfg["host"] + "/" + cfg["url"])
    try:
        log.info("Tardigrade started")
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info('Tardigrade stopped...\n')
    httpd.server_close()


def manageDefault(default: Any = None, changed: Any = None) -> Any:
    if changed is None or changed == default: return default
    return changed


def get_args(cfg):

    checker = argparse.ArgumentParser(add_help=False)

    checker.add_argument("--extra", "-e", action="append", dest="extra",
                         choices=["file", "web"], help="extra logger outputs")
    checker.add_argument("--secure", "-s", action="store_true", help="[WEB LOGGER]")
    extra_args = checker.parse_known_args()[0]
    extra_args.extra = set(extra_args.extra) if extra_args.extra else []

    parser = argparse.ArgumentParser(prog="Tardigrade", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Server Configuration Arguments
    server_group = parser.add_argument_group("Server Configuration")

    server_group.add_argument("--port", "-p", type=int, default=manageDefault(8000, cfg.port), dest="port",
                              help="the server port where Tardigrade will run")

    server_group.add_argument("--directory", "-d", type=str,
                              default=manageDefault('/', cfg.directory), dest="directory",
                              help="directory to serve files or execute commands from")

    server_group.add_argument("--timeout", "-t", type=int,
                              default=manageDefault(5, cfg.timeout), dest="timeout",
                              help="directory to serve files or execute commands from")

    server_group.add_argument("--output", "-j", type=str,
                              default=manageDefault("output.txt", cfg.output), dest="output",
                              help="[FILE LOGGER]")
    # Log Configuration
    log_group = parser.add_argument_group(title="Logging Configuration")
    log_group.add_argument("--logserver", action="store_true",
                           default=manageDefault(False, cfg.logserver), dest="logserver",
                           help="Disables all own logging, will listen for POST logging from another Tardigrade and "
                                "log its messages with this Tardigrade configuration")
    log_group.add_argument("--loglevel", "-l",
                           metavar="{q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}", type=str,
                           default=manageDefault('info', cfg.loglevel), dest="loglevel",
                           choices=["quiet", "debug", "info", "warn", "error", "critical", "server",
                                    "q", "d", "i", "w", "e", "c", "s"], help="logging level")

    log_group.add_argument("--options", "-o", nargs='*', default=manageDefault(None, cfg.options), dest="options",
                           choices=["no-color", "no-request", "no-response", "no-header", "no-body", "no-console",
                                    "no-banner"],
                           help="remove certain attributes from logging.")

    log_group.add_argument("--extra", "-e", action="append", dest="extra", default=manageDefault(None, cfg.extra),
                           choices=["file", "web"], help="extra logger outputs")
    # Extra Logger Configuration
    extra_group = parser.add_argument_group(title="Extra Logger Options")

    extra_group.add_argument("--filename", "-f", type=str, default=manageDefault("tardigrade.log", cfg.filename),
                             help="[FILE LOGGER]")
    extra_group.add_argument("--maxbytes", "-x", type=int, default=manageDefault(0, cfg.maxbytes),
                             help="[FILE LOGGER] max size of each file in bytes, if 0, file grows indefinitely")
    extra_group.add_argument("--count", "-c", metavar="filecount", type=int, default=manageDefault(0, cfg.maxbytes),
                             help="[FILE LOGGER] max amount of files to keep before rolling over, "
                                  "if 0, file grows indefinitely")
    extra_group.add_argument("--host", required="web" in extra_args.extra, default=manageDefault(None, cfg.host),
                             help="[WEB LOGGER]")
    extra_group.add_argument("--url", required="web" in extra_args.extra, default=manageDefault(None, cfg.url),
                             help="[WEB LOGGER]")
    extra_group.add_argument("--method", "-m", choices=["GET", "POST"], default=manageDefault("GET", cfg.method),
                             help="[WEB LOGGER]")
    extra_group.add_argument("--secure", "-s", action="store_true", help="[WEB LOGGER]",
                             default=manageDefault(False, cfg.secure))
    extra_group.add_argument("--credentials", nargs=2, metavar=("userid", "password"), help="[WEB LOGGER]",
                             required="secure" in extra_args.extra,
                             default=manageDefault(None, (cfg.credentials["username"],
                                                          cfg.credentials["password"])))

    # Other Arguments
    parser.add_argument("--version", action="version", help="show Tardigrade version", version=VERSION)
    parser.epilog = ""

    return parser.parse_args()


def load_configuration():
    with open("config/constants.yaml", "r") as yaml_file:
        data = yaml.load(yaml_file, Loader=yaml.FullLoader)
    return data


if __name__ == '__main__':

    c = argparse.Namespace()
    c.__dict__.update(load_configuration())
    c.__dict__.update(get_args(c).__dict__.items())
    cfg = c
    cfg.options = set(cfg.options) if cfg.options else []
    cfg.extra = set(cfg.extra) if cfg.extra else []

    # Set global options
    cfg.header = "no-header" not in cfg.options and not cfg.logserver
    cfg.body = "no-body" not in cfg.options and not cfg.logserver
    cfg.request = "no-request" not in cfg.options and not cfg.logserver
    cfg.response = "no-response" not in cfg.options and not cfg.logserver
    cfg.console = "no-console" not in cfg.options
    cfg.color = "no-color" not in cfg.options
    cfg.banner = "no-banner" not in cfg.options
    _directory_serve = os.path.join(os.getcwd() + cfg.directory)

    log, cfg = initialize_logger(cfg)

    run(cfg=cfg)
