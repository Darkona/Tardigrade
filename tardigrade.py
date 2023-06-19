import argparse
import ast
import email.utils
import html
import io
import logging
import os
import socketserver
import subprocess
import time
import urllib.parse
from datetime import datetime
from datetime import timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler

import simplejson

from commandthread import CommandThread
from legs import ColorFormatter, Colors, HEADERS, MimeTypes

# Tardigrade ASCII art from> https://twitter.com/tardigradopedia/status/1289077195793674246 - modified by me
AUTHOR = "Javier.Darkona@Gmail.com"

TARDIGRADE_ASCII = " (꒰֎꒱) \n උ( ___ )づ\n උ( ___ )づ \n  උ( ___ )づ\n උ( ___ )づ"'\n'
VERSION = "Tardigrade-1.0"

# Globals so I can pass stuff from one class to another, because python is weird and I don't fully understand it

# Server
_directory_serve = ''
_timeout = 0
# Logging
_request = False
_response = False
_header = True
_body = True

# Console

log = None
ENC = 'utf-8'
th: CommandThread = None


class TardigradeRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, request: bytes, client_address: tuple[str, int], server: socketserver.BaseServer):
        self._headers_buffer = []
        self.server_version = "TardigradeHTTP/" + VERSION
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
        message = '\n------- REQUEST: ' + self.requestline
        if _header: message += "\nHEADER:\n" + str(self.headers)
        if _body and body: message += "BODY:\n" + body
        return message

    def prepare_log_response(self, code: HTTPStatus = None, msg: str = None, body=None):
        if isinstance(code, HTTPStatus): code = code.value
        try:
            shortMsg, longMsg = self.responses[code]
        except KeyError:
            shortMsg, longMsg = '???', '???'
        if msg is None: msg = shortMsg
        output = '\n------- RESPONSE: HTTP Status - ' + str(code) + "-" + msg
        if _header: output += "\nHEADER:\n" + ''.join(item.decode() for item in self._headers_buffer)
        if _body: output += "\nBODY: \n" + body if body else ''
        return output

    def do_GET(self):
        if _request: log.info(self.prepare_log_request(None))
        try:
            f = self.do_Common(default_filenames=("index.html", "index.htm"))
            try:
                if f:
                    if _response: log.info(self.prepare_log_response(code=HTTPStatus.OK, body=f[1]))
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
            if _response: log.info(self.prepare_log_response(body))
            self.end_headers()

    def do_HEAD(self):
        if _request: log.info(self.prepare_log_request(None))
        try:
            f = self.do_Common(default_filenames=("index.html", "index.htm"))
            try:
                if f:
                    if _response: log.info(self.prepare_log_response(body=f[1], code=HTTPStatus.OK))
                    self.end_headers()
            except Exception as e:
                raise e
            finally:
                f[0].close()
        except Exception as e:
            msg = "Problem while serving HEAD request: " + str(e)
            log.warning(msg)
            body = self.prepare_error(HTTPStatus.INTERNAL_SERVER_ERROR, explain=msg)
            if _response: log.info(self.prepare_log_response(body))
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
        if _response: log.info(self.prepare_log_response(HTTPStatus.OK))

    def do_POST(self):

        log.debug("Received POST request")
        response_body, status, explain = None, None, None

        try:

            if HEADERS.CONTENT_TYPE not in self.headers:
                raise TypeError("No Content-Type HEADER")

            content_type = self.headers.get(HEADERS.CONTENT_TYPE)

            if _logserver:

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

                    if _request: log.info(self.prepare_log_request(request_body))

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
            if _response: log.info(self.prepare_log_response(code=HTTPStatus.OK, body=response_body, msg=explain))
            self.end_headers()
            if response_body:
                self.wfile.write(response_body.encode(ENC))

    def do_DELETE(self):
        if _request: log.info(self.prepare_log_request(None))
        response_body, status = self.stop_command()
        self.send_response(status)

        self.send_header(HEADERS.CONTENT_TYPE, MimeTypes.APPLICATION_JSON)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)
        if _response: log.info(
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

                if _response: log.info(self.prepare_log_response())
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
            if _response: log.info(self.prepare_log_response(body))
            return None

        try:
            f = open(path, 'rb')
        except OSError as e:
            msg = "OS error: " + str(e)
            log.warning(msg)
            body = self.prepare_error(HTTPStatus.NOT_FOUND, explain=msg)
            if _response: log.info(self.prepare_log_response(body))
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
            itemlist = os.listdir(path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None
        itemlist.sort(key=lambda a: a.lower())
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path, errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(self.path)
        displaypath = html.escape(displaypath, quote=False)
        title = f'Directory listing for {displaypath}'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{ENC}">')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name in itemlist:
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
            th = CommandThread(cwd=cwd, timeout=_timeout)
            try:
                log.debug("Created thread, starting")
                th.start()
                if _timeout <= 0:
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
                if _timeout > 0: th = None
        else:
            return [HTTPStatus.LOCKED, {'error': 'Another process already running'}]


def initialize_logger(c: argparse.Namespace):
    # Get log level from single letter
    letter_to_word_map = {"I": "INFO", "D": "DEBUG", "W": "WARN", "E": "ERROR", "C": "CRITICAL", "Q": "QUIET"}
    log_level = c.loglevel.upper()
    log_level = letter_to_word_map[log_level] if log_level in letter_to_word_map else log_level
    console_fmt = 'Line:%(lineno)d : [%(funcName)s] %(message)s'
    file_fmt = "Tardigrade " + (
        "" if "no-banner" in c.options else "( ꒰֎꒱ )") + \
               "- %(asctime)s  [%(levelname)s] Line:%(lineno)d : [%(funcName)s] %(message)s"
    if log_level != "QUIET":

        logger = logging.getLogger("root")
        logger.setLevel(logging.DEBUG if _logserver else getattr(logging, log_level))

        # Configure handlers
        handlers = []
        if "file" in c.extra:
            handlers.append(logging.handlers.RotatingFileHandler(c.filename, encoding='utf-8',
                                                                 maxBytes=c.maxbytes, backupCount=c.count))
            c.file_enable = True

        if "web" in c.extra:
            handlers.append(logging.handlers.HTTPHandler(c.host, c.url, method=c.method,
                                                         secure=c.secure, credentials=c.credentials))
            c.web_enable = True
        # Set same formatter for all the file handlers
        for h in handlers:
            h.setFormatter(ColorFormatter(console_fmt))
            # h.setFormatter(logging.Formatter(file_fmt))

        if "no-console" not in c.options:
            con = logging.StreamHandler()
            # Select color or plain formatter for console logger
            con.setFormatter(
                ColorFormatter(console_fmt) if "no-color" not in c.options else logging.Formatter(file_fmt))
            handlers.append(con)

        for h in handlers:
            logger.addHandler(h)
        return logger, c


def run(server_class=HTTPServer, handler_class=TardigradeRequestHandler, config=None):
    # Initialize http server
    server_address = ('localhost', int(config.port))
    console = "no-console" not in c.options
    color = "no-color" not in c.options
    banner = "no-banner" not in c.options

    httpd = server_class(server_address, handler_class)

    if console:
        if banner:
            if color: print(f'{Colors.pink}{TARDIGRADE_ASCII}{Colors.reset}')
            else: print(TARDIGRADE_ASCII)
        print('Tardigrade Server is running. Listening at: ' + httpd.server_name + ":" + str(c.port))
        print('GET requests serving files from: ' + (config.directory if config.directory != '' else 'same folder.'))
        print(("Full color " if color else "Monochromatic (boring) ") + "logging enabled. Level: " +
              logging.getLevelName(log.getEffectiveLevel()))
        if hasattr(config, "file_enabled"): print("Logging in file: " + config["filename"])
        if hasattr(config, "file_web"): print("Logging in web at: " + config["host"] + "/" + config["url"])
    try:
        log.info("Tardigrade started")
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info('Tardigrade stopped...\n')
        pass
    httpd.server_close()


def get_args():
    checker = argparse.ArgumentParser(add_help=False)
    checker.add_argument("--extra", "-e", action="append", dest="extra",
                         choices=["file", "web"], help="extra logger outputs")
    extra_args = checker.parse_known_args()[0]
    extra_args.extra = set(extra_args.extra) if extra_args.extra else []

    parser = argparse.ArgumentParser(prog="Tardigrade", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Server Configuration Arguments
    server_group = parser.add_argument_group("Server Configuration")

    server_group.add_argument("--port", "-p", type=int, default=8000, dest="port",
                              help="the server port where Tardigrade will run")

    server_group.add_argument("--directory", "-d", type=str, default='/', dest="directory",
                              help="directory to serve files or execute commands from")

    server_group.add_argument("--timeout", "-t", type=int, default=5, dest="timeout",
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
                           choices=["no-color", "no-request", "no-response", "no-header", "no-body", "no-console",
                                    "no-banner"],
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


if __name__ == '__main__':
    c = get_args()
    c.options = set(c.options) if c.options else []
    c.extra = set(c.extra) if c.extra else []
    # Set global options
    _header = "no-header" not in c.options and not c.logserver
    _body = "no-body" not in c.options and not c.logserver
    _request = "no-request" not in c.options and not c.logserver
    _response = "no-response" not in c.options and not c.logserver
    _logserver = c.logserver
    _directory_serve = os.path.join(os.getcwd() + c.directory)
    _timeout = c.timeout
    log, config = initialize_logger(c)

    run(config=config)
