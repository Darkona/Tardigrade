import argparse
import ast
import email.utils
import html
import io
import logging
import os
import socketserver
import subprocess
import sys
import urllib.parse
from datetime import datetime
from datetime import timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler
from typing import Any

import simplejson

# Tardigrade ASCII art from> https://twitter.com/tardigradopedia/status/1289077195793674246 - modified by me
TARDIGRADE_ASCII = " (꒰֎꒱) \n උ( ___ )づ\n උ( ___ )づ \n  උ( ___ )づ\n උ( ___ )づ"'\n'
VERSION = "Tardigrade 1.0 - Javier Darkona (2023)"

# Globals so I can pass stuff from one class to another, because python is weird and I don't fully understand it

# Server
_file = None
_directory_serve = ''

# Logging
_request = False
_response = False
_header = True
_body = True

# Console
_color = True
_console = True
log = None


class TardigradeRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, request: bytes, client_address: tuple[str, int], server: socketserver.BaseServer):
        self._headers_buffer = []
        super().__init__(request, client_address, server, directory=_directory_serve)

    def log_request(self, code='-', size='-', body: str = None) -> None:
        if isinstance(code, HTTPStatus):
            code = code.value
        if _request:
            message = '\n------- REQUEST: ' + self.requestline
            if _header: message += "\nHEADER:\n" + str(self.headers)
            if _body and body: message += "BODY: \n" + body
            log.info(message)

    def log_error(self, f: str, *args: Any) -> None:
        f = "%d %s"
        log.error("Error: " + f % args)

    def do_GET(self):
        self.log_request()
        f = self.do_Common(default_filenames=("index.html", "index.htm"))
        if f:
            try:
                if _response:
                    message = '\n------- RESPONSE -------'
                    if _header: message += "\nHEADER:\n" + ''.join(item.decode() for item in self._headers_buffer)
                    if _body: message += "\nBODY: \n" + f[1]
                    log.info(message)
                self.end_headers()
                self.copyfile(f[0], self.wfile)

            finally:
                f[0].close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.do_Common()

        if f:
            if _response: log.info("\nRESPONSE HEADER:\n" + str(self.headers))
            f.close()

    def do_LogServe(self, content_type):
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(HTTPStatus.BAD_REQUEST, "Incorrect content type. Should be " + content_type)
            return
        try:
            request_data = self.rfile.read(int(self.headers['Content-Length']))
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
            self.send_response(HTTPStatus.OK, "OK")
            self.send_header("Content-Length", str(len("OK")))
            self.end_headers()
        except Exception as e:
            self.send_error(HTTPStatus.BAD_REQUEST, str(e))

    def do_Log(self):
        request_data = self.rfile.read(int(self.headers['Content-Length']))
        self.log_request(code=HTTPStatus.OK, body=simplejson.dumps(simplejson.loads(request_data),
                                                               sort_keys=True, indent=4 * ' '))
        self.send_response(HTTPStatus.ACCEPTED, "Accepted")
        self.end_headers()

    def do_POST(self):

        if "Content-Type" not in self.headers:
            self.send_error(HTTPStatus.BAD_REQUEST, "No Content-Type HEADER")
        content_type = self.headers.get("Content-Type")

        if _logserver:
            self.do_LogServe(content_type)
            return

        else:

            match self.path:
                case "/command":
                    if content_type != "application/json":
                        self.send_error(HTTPStatus.BAD_REQUEST, "Incorrect content type. Should be " + content_type)
                        return
                    self.do_command()
                    return
                case None:
                    self.do_Log()
                    return
                case "/log":
                    self.do_Log()
                    return
                case "/mock":
                    self.path ='/'
                    request_data = self.rfile.read(int(self.headers['Content-Length']))
                    self.log_request(code=HTTPStatus.OK, body=simplejson.dumps(simplejson.loads(request_data),
                                                                               sort_keys=True, indent=4 * ' '))
                    f = self.do_Common(default_filenames=["response.json"])
                    try:
                        if _response:
                            message = '\n------- RESPONSE -------'
                            if _header: message += "\nHEADER:\n" + ''.join(item.decode() for item in self._headers_buffer)
                            if _body: message += "\nBODY: \n" + f[1]
                            log.info(message)
                        self.end_headers()
                        self.copyfile(f[0], self.wfile)
                    finally:
                        f[0].close()

    def do_Common(self, default_filenames):
        path = self.translate_path(self.path)
        f = None
        log.debug(f"PATH: {path}")
        if os.path.isdir(path):
            log.debug("PATH points to directory instead of file, looking for index files")
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith('/'):
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/', parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.send_header('Server', self.version_string())
                self.send_header('Date', self.date_time_string())
                self.send_header("Location", new_url)
                self.send_header("Content-Length", "0")
                if _response and _header: log.info("\nHEADERS:\n" + self.headers_as_string())
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
            log.warning("File " + path + " not found")
            self.send_error(HTTPStatus.NOT_FOUND, "file not found")
            return None
        try:
            f = open(path, 'rb')
        except OSError:
            log.warning("File " + path + " not found")
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        log.debug("File '" + path + "' found")
        try:
            fs = os.fstat(f.fileno())
            # Use browser cache if possible
            if "If-Modified-Since" in self.headers and "If-None-Match" not in self.headers:
                # compare If-Modified-Since and time of last file modification
                log.debug("If-Modified-Since header found in request, attempting to parse.")
                try:
                    ims = email.utils.parsedate_to_datetime(self.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    log.debug("Error at parsing date from headers")
                    pass
                else:
                    if ims.tzinfo is None:
                        # obsolete format with no timezone, cf.
                        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                        ims = ims.replace(tzinfo=timezone.utc)
                    if ims.tzinfo is timezone.utc:
                        log.debug("Comparing file timestamp to If-Modified-Since")
                        # compare to UTC datetime of last modification
                        last_modif = datetime.fromtimestamp(fs.st_mtime, timezone.utc)
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            log.warning("Modified not matching, sending NOT_MODIFIED")
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return None
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Content-Type", ctype)
            self.send_header("Last-Modified", self.date_time_string(int(fs.st_mtime)))
            return [f, path]
        except Exception as e:
            log.warning("Error while fetching file: " + str(e))
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            f.close()
            raise

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    def headers_as_string(self):
        output = ''
        for h in self._headers_buffer:
            output += h.decode('utf-8')
        return output

    def do_command(self):
        request_data = self.rfile.read(int(self.headers['Content-Length']))
        self.log_request(code=HTTPStatus.OK,
                         body=simplejson.dumps(simplejson.loads(request_data), sort_keys=True, indent=4 * ' '))
        jsonData = simplejson.loads(request_data)

        if "type" not in jsonData:
            self.send_error(HTTPStatus.BAD_REQUEST, "No type")
            return

        match jsonData["type"]:

            case "command":
                if "command" not in jsonData:
                    self.send_error(HTTPStatus.BAD_REQUEST, "No command")
                    return

                log.debug("Received command order.")
                commandJson = jsonData["command"]

                if "single_line" in commandJson:
                    command_data = commandJson["single_line"]
                elif "cmd" in commandJson and "args" in commandJson:
                    command_data = "cmd" + " " + "args"
                else:
                    self.send_error(HTTPStatus.BAD_REQUEST, "Either no 'single_line' or no 'cmd' and 'args' pair")
                    return

                response = run_command(command=command_data)
                body = simplejson.dumps(response, indent=4 * ' ').encode('utf-8')

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/json")
                if _response:
                    message = "\n------- RESPONSE ------"
                    if _header: message += "\nHEADERS:\n" + self.headers_as_string()
                    if _body: message += f"\nBODY:\n{body.decode('utf-8')}\n"
                    log.info(message)
                self.end_headers()
                self.wfile.write(body)
            case "log":
                log.debug("Received log order.")
            case None:
                log.debug("Received unknown type")

    def list_directory(self, path):
        try:
            list = os.listdir(path)
        except OSError:
            self.send_error(
                HTTPStatus.NOT_FOUND,
                "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(self.path)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = f'Directory listing for {displaypath}'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{enc}">')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name in list:
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
                    % (urllib.parse.quote(linkname,
                                          errors='surrogatepass'),
                       html.escape(displayname, quote=False)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        return f


def run_command(command: str) -> dict[str, str]:
    try:
        log.debug(f"Received command: {command}\nexecuting...\n")
        process_output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
        log.debug(f"Process output: \n{process_output}")
        return {'output': process_output}
    except Exception as e:
        log.warning("Exception occurred: " + str(e))
    return {"error": "something bad happened"}


class Colors:
    pink = "\033[38;5;206m"
    grey = "\033[1;30m"
    green = "\033[0;32m"
    yellow = "\033[1;33m"
    red = "\033[31;1;m"
    purple = "\033[0;35m"
    blue = "\033[10;34;5m"
    light_blue = "\033[1;36m"
    reset = "\033[0m"
    blink_red = "\033[31;1;4m"


class ColorFormatter(logging.Formatter):

    def __init__(self, f):
        super(ColorFormatter, self).__init__()
        self.fstring = f
        self.FORMATS = self.define_format()
        super().__init__()

    def define_format(self):
        format_prefix = f"{Colors.light_blue}%(module)s - {Colors.purple}%(asctime)s{Colors.reset}"
        format_prefix.encode('utf-8')
        level = f" [%(levelname)s] "
        return {
            logging.DEBUG: format_prefix + Colors.green + level + Colors.reset + self.fstring,
            logging.INFO: format_prefix + Colors.blue + level + ' ' + Colors.reset + self.fstring,
            logging.WARNING: format_prefix + Colors.yellow + level + Colors.reset + self.fstring,
            logging.ERROR: format_prefix + Colors.red + level + self.fstring + Colors.reset,
            logging.CRITICAL: format_prefix + Colors.blink_red + level + self.fstring + Colors.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def get_args():
    checker = argparse.ArgumentParser(add_help=False)
    checker.add_argument("--extra", "-e", action="append", dest="extra", choices=["file", "web"],
                         help="extra logger outputs")
    extra_args = checker.parse_known_args()[0]
    extra_args.extra = set(extra_args.extra) if extra_args.extra else []

    parser = argparse.ArgumentParser("tardigrade.py", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Server Configuration Arguments
    server_group = parser.add_argument_group("Server Configuration")

    server_group.add_argument("--port", type=int, default=8000, dest="port",
                              help="the server port where Tardigrade will run")

    server_group.add_argument("--directory", type=str, default='/', dest="directory",
                              help="directory to serve files or execute commands from")

    # Log Configuration
    log_group = parser.add_argument_group(title="Logging Configuration")
    log_group.add_argument("--logserver", action="store_true", help="Disables all own logging, will listen for POST "
                                                                    "logging from another Tardigrade and log its "
                                                                    "messages with this Tardigrade configuration")
    log_group.add_argument("--loglevel", "-l",
                           metavar="{q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}",
                           type=str, help="logging level", default="info", dest="loglevel",
                           choices=["quiet", "debug", "info", "warn", "error", "critical", "server",
                                    "q", "d", "i", "w", "e", "c", "s"])

    log_group.add_argument("--options", "-o", nargs='*', dest="options",
                           choices=["no-color", "no-request", "no-response", "no-header", "no-body", "no-console"],
                           help="remove certain attributes from logging.")
    log_group.add_argument("--extra", "-e", action="append", dest="extra", choices=["file", "web"],
                           help="extra logger outputs")
    # Extra Logger Configuration
    extra_group = parser.add_argument_group(title="Extra Logger Options")

    extra_group.add_argument("--filename", "-f", type=str, default="tardigrade_log.log", help="[FILE LOGGER]")
    extra_group.add_argument("--maxbytes", "-x", type=int, default=0, help="[FILE LOGGER] max size of each file in "
                                                                           "bytes, if 0, file grows indefinitely")
    extra_group.add_argument("--count", "-c", metavar="filecount", type=int, default=0,
                             help="[FILE LOGGER] max amount of files to keep before rolling over, "
                                  "if 0, file grows indefinitely")
    extra_group.add_argument("--host", required="web" in extra_args.extra, help="[WEB LOGGER]")
    extra_group.add_argument("--url", required="web" in extra_args.extra, help="[WEB LOGGER]")
    extra_group.add_argument("--method", "-m", choices=["GET", "POST"], default="GET", help="[WEB LOGGER]")
    extra_group.add_argument("--secure", "-s", action="store_true", help="[WEB LOGGER]")
    extra_group.add_argument("--credentials", nargs=2, metavar=("userid", "password"), help="[WEB LOGGER]")

    # Other Arguments
    parser.add_argument("--version", action="version", help="show Tardigrade version", version=VERSION)
    parser.epilog = ""

    return parser.parse_args()


def initialize_logger(config):
    # Get log level from single letter
    letter_to_word_map = {"I": "INFO", "D": "DEBUG", "W": "WARN", "E": "ERROR", "C": "CRITICAL", "Q": "QUIET"}
    log_level = config.loglevel.upper()
    log_level = letter_to_word_map[log_level] if log_level in letter_to_word_map else log_level
    console_fmt = 'Line:%(lineno)d : [%(funcName)s] %(message)s'
    file_fmt = "Tardigrade ( ꒰֎꒱ ) - %(asctime)s  [%(levelname)s] Line:%(lineno)d : [%(funcName)s] %(message)s"
    if log_level != "QUIET":

        logger = logging.getLogger("root")
        logger.setLevel(logging.DEBUG if _logserver else getattr(logging, log_level))

        # Configure handlers
        handlers = []
        if "file" in config.extra:
            handlers.append(logging.handlers.RotatingFileHandler(config.filename, encoding='utf-8',
                                                                 maxBytes=config.maxbytes, backupCount=config.count))
        if "web" in config.extra:
            handlers.append(logging.handlers.HTTPHandler(config.host, config.url, method=config.method,
                                                         secure=config.secure, credentials=config.credentials))
        # Set same formatter for all the file handlers
        for h in handlers:
            h.setFormatter(ColorFormatter(console_fmt))
            # h.setFormatter(logging.Formatter(file_fmt))

        if _console:
            con = logging.StreamHandler()
            # Select color or plain formatter for console logger
            con.setFormatter(ColorFormatter(console_fmt) if _color else logging.Formatter(file_fmt))
            handlers.append(con)

        for h in handlers:
            logger.addHandler(h)

        if "fileLog" in config: print("Logging in file: " + config["filename"])
        if "rotatingLog" in config: print("Logging in rotating file: " + config["filename"])
        if "webLog" in config: print("Logging in web at: " + config["host"] + "/" + config["url"])
        return logger


def run(server_class=HTTPServer, handler_class=TardigradeRequestHandler, config=None):
    # Initialize http server
    server_address = ('localhost', int(config.port))
    httpd = server_class(server_address, handler_class)

    if "no-console" not in c.options:
        print(f'{Colors.pink}' + TARDIGRADE_ASCII + f'{Colors.reset}')
        print(f'Tardigrade Server is running. Listening at: ' + httpd.server_name + ":" + str(c.port))

    if "no-console" not in c.options:
        print('GET requests serving files from: ' + (config.directory if config.directory != '' else 'same folder.'))
        print(("Full color " if _color else "No color ") + "logging enabled. Level: " +
              logging.getLevelName(log.getEffectiveLevel()))
    try:
        log.info("Tardigrade started")
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    log.info('Tardigrade stopped...\n')


if __name__ == '__main__':
    c = get_args()
    c.options = set(c.options) if c.options else []
    c.extra = set(c.extra) if c.extra else []
    # Set global options
    _header = "no-header" not in c.options and not c.logserver
    _body = "no-body" not in c.options and not c.logserver
    _request = "no-request" not in c.options and not c.logserver
    _response = "no-response" not in c.options and not c.logserver
    _color = "no-color" not in c.options
    _console = "no-console" not in c.options
    _logserver = c.logserver
    _directory_serve = os.path.join(os.getcwd() + c.directory)
    log = initialize_logger(c)

    run(config=c)
