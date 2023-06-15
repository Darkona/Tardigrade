import email.utils
import logging
from logging.handlers import RotatingFileHandler
import os
import socketserver
import subprocess
import argparse
import urllib.parse
from datetime import timezone
from datetime import datetime
from http import HTTPStatus

from http.server import SimpleHTTPRequestHandler, HTTPServer
from typing import Any

import simplejson

# Tardigrade ASCII art from> https://twitter.com/tardigradopedia/status/1289077195793674246 - modified by me
TARDIGRADE_ASCII = "  (꒰֎꒱) \n උ( ___ )づ\n උ( ___ )づ \n  උ( ___ )づ\n උ( ___ )づ"'\n'
VERSION = "Tardigrade 1.0 - Javier Darkona (2023)"


class Command(dict):
    cmd = ''
    args = ''

    def __init__(self, cmd: str = '', args: str = ''):
        super().__init__()
        self.cmd = cmd
        self.args = args if args else ''

    def for_json(self):
        return {'cmd': self.cmd}, {'args': self.args}


def run_command(coms: Command) -> dict[str, str]:
    try:
        g = coms.cmd + ((' ' + coms.args) if coms.args else '')
        print(f"Received command: {g}\nexecuting...\n")
        process_output = subprocess.check_output(g,
                                                 shell=True,
                                                 stderr=subprocess.STDOUT,
                                                 text=True,
                                                 timeout=5)
        print(f"Process output: \n{process_output}")
        return {'output': process_output}
    except:
        print("Exception occurred")
    return {"error": "something bad happened"}


def as_command(com):
    if 'single_line' in com:
        return Command(com['single_line'])
    else:
        return Command(com['cmd'], com['args'])


discriminate = 'all'

file = None

request = False
response = False

lheader = True
lbody = True


def get_level(arg):
    word = {"I": "INFO", "D": "DEBUG", "W": "WARN", "E": "ERROR", "C": "CRITICAL"}
    return word[arg] if arg in word else arg


def set_log_style(config):
    types = ['request', 'response']
    for t in types:
        if t in config: vars()[t] = config[t]


class TardigradeRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, request: bytes, client_address: tuple[str, int], server: socketserver.BaseServer):
        super().__init__(request, client_address, server, directory=config["directory"])
        logging.info(
            "Log style: " + logStyle + ". I'm' going to be talking a lot!" if verbose else ". I won't make a noise :x" if quiet else '')

    def response_headers(self, httpstatus: HTTPStatus, ctype, response):
        if verbose: logging.debug("Creating headers for response. Length of response: " + str(len(response)))

        self.send_response(httpstatus)
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Content-Type", ctype)
        if not hasattr(self, '_headers_buffer'): self._headers_buffer = []
        if not quiet: logging.info("\nHEADERS:\n" + '\n'.join(self.headers))

        # map(lambda i: str(i, 'utf-8'), self.headers)
        # log_verbose('info', "\nHEADERS: \n" + self.headers)

    def log_request(self, code='-', size='-') -> None:
        if isinstance(code, HTTPStatus):
            code = code.value
        logging.info("REQUEST: " + str(self.requestline) + " " + str(code) + " " + str(size))

    def log_error(self, f: str, *args: Any) -> None:
        f = "%d %s"
        logging.error("RESPONSE: " + f % args)

    def do_GET(self):
        self.log_request()
        self.log_headers()
        f = self.do_Common()
        if f:
            try:
                log_verbose("info", "RESPONSE: ")
                self.copyfile(f, self.wfile)
            finally:
                f.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.do_Common()
        if f:
            f.close()

    def do_POST(self):

        request_data = self.rfile.read(int(self.headers['Content-Length']))
        command_data: Command = simplejson.loads(request_data, object_hook=as_command)

        self.log_request(self.command)
        if not quiet and request:
            if lheader: logging.info("\nHEADERS:\n" + '\n'.join(self.headers))
            if lbody: logging.info(f"\nBODY:\n{simplejson.dumps(command_data, sort_keys=True, indent=4 * ' ')}\n")

        body = simplejson.dumps(response, indent=4 * ' ').encode('utf-8')
        # body = json.dumps(response).encode("utf-8")
        self.response_headers(HTTPStatus.OK, 'application/json', body)
        self.end_headers()
        if not quiet and response:
            if lheader: logging.info("\nHEADERS:\n" + '\n'.join(self.headers))
            if lbody: logging.info(f"BODY:\n{body.decode('utf-8')}\n")

        self.wfile.write(body)

    def do_Common(self):
        path = self.translate_path(self.path)
        filename = ''
        f = None
        logging.debug(f"PATH: {path}")
        if os.path.isdir(path):
            logging.debug("PATH valid!")
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith('/'):
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/',
                             parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.send_header("Location", new_url)
                self.send_header("Content-Length", "0")
                if lheader: logging.info("\nHEADERS:\n" + '\n'.join(self.headers))
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                filename = index
                index = os.path.join(path, index)
                if os.path.isfile(index):
                    path = index
                    break
            else:
                if verbose: logging.debug("No files found, serving list")
                return self.list_directory(path)
        ctype = self.guess_type(path)
        if path.endswith("/"):
            if not quiet: logging
            self.send_error(HTTPStatus.NOT_FOUND, "file not found")
            return None
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        log_verbose("debug", filename + " file found, serving...")
        try:
            fs = os.fstat(f.fileno())
            # Use browser cache if possible
            if "If-Modified-Since" in self.headers and "If-None-Match" not in self.headers:
                # compare If-Modified-Since and time of last file modification
                try:
                    ims = email.utils.parsedate_to_datetime(self.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    # ignore ill-formed values
                    pass
                else:
                    if ims.tzinfo is None:
                        # obsolete format with no timezone, cf.
                        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                        ims = ims.replace(tzinfo=timezone.utc)
                    if ims.tzinfo is timezone.utc:
                        # compare to UTC datetime of last modification
                        last_modif = datetime.fromtimestamp(
                            fs.st_mtime, timezone.utc)
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return None

            self.response_headers(HTTPStatus.OK, ctype, str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(int(fs.st_mtime)))
            self.end_headers()
            return f
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            f.close()
            raise

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())


def get_args():
    # RawTextHelpFormatter maintains whitespace for all sorts of help text, including argument descriptions.
    # However, multiple new lines are replaced with one.
    # If you wish to preserve multiple blank lines, add spaces between the newlines.
    parser = argparse.ArgumentParser("Tardigrade", "Simple http server for development",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # Server Configuration
    servergroup = parser.add_argument_group("Server options")
    servergroup.add_argument("-p", "--p", type=int, help="the server port where Tardigrade will run", default=8000)
    # servergroup.add_argument("-g", "--get", type=str, help="PATH for listening for GET requests", default='')
    # servergroup.add_argument("-t", "--post", type=str, help="Path for listening for POST requests", default='')
    servergroup.add_argument("-d", "--directory", type=str, help="directory to serve files or execute commands from")

    # Log Configuration

    loggroup = parser.add_argument_group(title="logging options", help="logging options")

    loggroup.add_argument("-l", "--level", type=str, help="Logging level", default="info",
                          choices=["quiet", "debug", "info", "warn", "error", "critical", "d", "i", "w", "e", "c"])

    loggroup.add_argument("-x", dest="remove", nargs='*',
                          choices=["nocolor", "norequest", "noresponse", "noheader", "nobody", "noconsole"
                                   "nc", "nrq", "nrs", "nh", "nb", "ncon"],
                          help="Remove certain attributes from logging.")

    logfile = parser.add_subparsers(title="File logging", help="Enable file logging")
    parserFile = logfile.add_parser("--file")
    parserFile.add_argument("-n", "--name", type=str, default="tardigrade_log.log")

    logRotating = parser.add_subparsers(title="Rolling File logging", help="Enable rolling file logging")
    parserRolling = logRotating.add_parser("--rolling")
    parserRolling.add_argument("-n", "--name", type=str, default="tardigrade_log.log")

    logWeb = parser.add_subparsers(title="HTTP Logging", help="Enable sending log to another server. "
                                                              "Maybe even another Tardigrade!")
    parserWeb = logWeb.add_parser("--web")
    parserWeb.add_argument("host", help="can be in the form host:port")
    parserWeb.add_argument("url", help="url where to send the requests")
    parserWeb.add_argument("--method", choices=["GET","POST"], default="GET")
    parserWeb.add_argument("--secure", action="store_true")
    parserWeb.add_argument("--secure", action="store_true")
    parserWeb.add_argument("--credentials", nargs=2, help="Requires two values, userid and password, "
                                                          "for HTTP Basic Header Authorization")


    # Other Arguments
    parser.add_argument("--version", action="version", help="show Tardigrade version", version=VERSION)
    parser.epilog = "By default, Tardigrade will run at localhost:8000; GET and POST requests will be listened " \
                    "for at the root PATH (no need to put '/') and logging will be moderate at INFO level"

    return vars(parser.parse_args())


def initialize_logger(file, level):
    # Initialize logger

    log_level = getattr(logging, get_level(level).upper())
    log_format = '%(levelname)s - %(funcName)s:  %(asctime)s - %(message)s'
    if file:
        logging.basicConfig(level=log_level, format=log_format, encoding='utf-8', handlers=[
            logging.handlers.RotatingFileHandler(),
            logging.StreamHandler()
        ])
    else:
        logging.basicConfig(level=log_level, format=log_format, encoding='utf-8')
    logging.info("Logging level is: " + str(log_level))


def run(server_class=HTTPServer, handler_class=TardigradeRequestHandler, config: dict[str, Any] = None):
    # Initialize http server
    port = int(config["port"])
    directory = config["directory"] if config["directory"] else ""

    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    if not config["quiet"]:
        initialize_logger(str(config["file"]), str(config["level"]))
        print(TARDIGRADE_ASCII)
        print('Tardigrade is running in port: ' + str(port))
        print('GET requests serving files from: .\\' + directory)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print('Stopping httpd...\n')


if __name__ == '__main__':
    c = get_args()
    lheader = c["discriminate"] == "all" or "header"
    lbody = c["discriminate"] == "all" or "body"
    run(config=c)
