import ast
import email
import html
import io
import logging
import os
import socketserver
import subprocess
import urllib
import time

from datetime import timezone, datetime
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from typing import Any
from email import utils

import simplejson

from tardigrade_configuration import TardigradeConfiguration
from tardigrade_constants import HEADERS, APPLICATION_JSON, TEXT_HTML
from tardigrade_threading import TardigradeCommandReturningThread


class TardigradeRequestHandler(SimpleHTTPRequestHandler):

    th: TardigradeCommandReturningThread
    cfg: TardigradeConfiguration
    ENCODING = 'UTF-8'
    log: logging.Logger

    def __init__(self, request: bytes, client_address: tuple[str, int],
                 server: socketserver.BaseServer,
                 configuration: TardigradeConfiguration,
                 logger: logging.Logger,
                 thread: TardigradeCommandReturningThread):
        self._headers_buffer = []
        self.server_version = "TardigradeHTTP/" + configuration.version
        self.cfg = configuration
        self.extensions_map.update(configuration.mime_types.__dict__.items())
        self.log = logger
        self.th = thread
        super().__init__(request, client_address, server)

    def prepare_error(self, code: int, message: str = None, explain: str = None):
        try:
            short_msg, long_msg = self.responses[code]
        except KeyError:
            short_msg, long_msg = '???', '???'

        if message is None:
            message = short_msg

        if explain is None:
            explain = long_msg

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
            body = content.encode(self.ENCODING, 'replace')
            self.send_header(HEADERS.CONTENT_TYPE, self.error_content_type)
            self.send_header(HEADERS.CONTENT_LENGTH, str(len(body)))
            self.end_headers()
        if self.command != 'HEAD' and body:
            self.wfile.write(body)
        return body

    def prepare_log_request(self, body):
        message = '\n--- REQUEST: ' + self.requestline

        if self.cfg.header:
            message += "\nHEADER:\n" + str(self.headers)

        if self.cfg.body and body:
            message += "BODY:\n" + body

        return message

    def prepare_log_response(self, code: int = None, msg: str = None, body=None):
        if isinstance(code, HTTPStatus):
            code = code.value
        try:
            short_msg, long_msg = self.responses[code]
        except KeyError:
            short_msg, long_msg = '???', '???'
        if msg is None:
            msg = short_msg
        output = '\n --- RESPONSE: HTTP Status - ' + str(code) + "-" + msg

        if self.cfg.header:
            output += "\nHEADER:\n" + ''.join(item.decode() for item in self._headers_buffer)

        if self.cfg.body:
            output += "\nBODY: \n" + body if body else ''
        return output

    def do_log_serve(self, content_type):
        if content_type != "application/x-www-form-urlencoded":
            raise TypeError("Incorrect content type. Should be: application/x-www-form-urlencoded")
        request_data = self.rfile.read(int(self.headers[HEADERS.CONTENT_LENGTH]))
        # Have to parse this thing like 3 times -____-
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
        self.log.callHandlers(logging.makeLogRecord(log_request))
        self.send_response(HTTPStatus.OK)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len("OK")))

        if self.cfg.response:
            self.log.info(self.prepare_log_response(HTTPStatus.OK))

        self.end_headers()

    def do_GET(self):
        if self.cfg.log_server:
            return self.do_log_serve(self.headers.get(HEADERS.CONTENT_TYPE))

        if self.cfg.request:
            self.log.info(msg=self.prepare_log_request(None))

        try:
            file = self.do_common(default_filenames=("index.html", "index.htm"))
            try:
                if file:
                    if self.cfg.response:
                        self.log.info(self.prepare_log_response(code=HTTPStatus.OK, body=file[1]))
                    self.end_headers()
                    self.copyfile(file[0], self.wfile)
            except Exception as e:
                raise e
            finally:
                file[0].close()
        except Exception as e:
            msg = "Problem while serving GET request: " + str(e)
            self.log.warning(msg)
            body = self.prepare_error(code=HTTPStatus.INTERNAL_SERVER_ERROR, explain=msg)
            if self.cfg.response:
                self.log.info(self.prepare_log_response(body))
            self.end_headers()

    def do_HEAD(self):
        if self.cfg.request:
            self.log.info(self.prepare_log_request(None))
        try:
            file = self.do_common(default_filenames=("index.html", "index.htm"))
            try:
                if file:
                    if self.cfg.response:
                        self.log.info(self.prepare_log_response(body=file[1], code=HTTPStatus.OK))
                    self.end_headers()
            except Exception as e:
                raise e
            finally:
                file[0].close()
        except Exception as e:
            msg = "Problem while serving HEAD request: " + str(e)
            self.log.warning(msg)
            body = self.prepare_error(HTTPStatus.INTERNAL_SERVER_ERROR, explain=msg)
            if self.cfg.response:
                self.log.info(self.prepare_log_response(body))
            self.end_headers()

    def do_POST(self):

        if self.cfg.log_server:
            return self.do_log_serve(self.headers.get(HEADERS.CONTENT_TYPE))

        else:
            self.log.debug("Received POST request")
            response_body, status, explain = None, None, None
            part = self.path.split('/')[1]
            try:

                if HEADERS.CONTENT_TYPE not in self.headers:
                    raise TypeError("No Content-Type HEADER")

                content_type = self.headers.get(HEADERS.CONTENT_TYPE)

                self.log.debug('Normal server active')

                request_data = self.rfile.read(int(self.headers[HEADERS.CONTENT_LENGTH]))

                if part not in ["command", "mock", "self.log", "stop", "write"]:
                    not_part = {"error": f"Path doesn't correspond to any use. Path used: {part}"}
                    status, response_body = HTTPStatus.NOT_FOUND, simplejson.dumps(not_part, indent=4 * ' ')

                try:
                    request_body = simplejson.dumps(simplejson.loads(request_data), sort_keys=True, indent=4 * ' ')
                except simplejson.JSONDecodeError:
                    raise TypeError("Badly formatted JSON")

                if self.cfg.request:
                    self.log.info(self.prepare_log_request(request_body))

                match part:

                    case "command":
                        response_body, status = self.do_command(content_type, request_data)

                    case "mock":
                        status = self.do_mock()

                    case "self.log":
                        self.log.debug("Calling mock endpoint")
                        status = HTTPStatus.OK

                    case "stop":
                        self.log.debug("Calling mock endpoint")
                        response_body, status = self.stop_command()

                    case "write":
                        response_body, status = self.do_write(content_type, request_data)

                    case None:
                        self.log.debug("Calling non-existent endpoint")
                        status = HTTPStatus.NOT_FOUND

            except Exception as e:

                self.flush_headers()
                msg = "Problem while serving POST request: " + str(e)
                self.log.warning(msg)
                status = HTTPStatus.INTERNAL_SERVER_ERROR
                if isinstance(e, TypeError):
                    status = HTTPStatus.BAD_REQUEST
                if isinstance(e, FileNotFoundError):
                    status = HTTPStatus.NOT_FOUND
                explain = msg

            finally:

                if part != 'mock':
                    self.send_response(status)
                    self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)
                    self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)
                    self.send_header(HEADERS.CONTENT_TYPE, APPLICATION_JSON)
                    self.end_headers()
                    if response_body:
                        self.wfile.write(response_body.encode(self.ENCODING))
                if self.cfg.response:
                    self.log.info(self.prepare_log_response(code=HTTPStatus.OK, body=response_body, msg=explain))

    def do_command(self, content_type, request_data):
        self.log.debug("Calling command endpoint")
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
        self.log.debug("Command endpoint exiting.")
        return response_body, status

    def do_mock(self):
        self.log.debug("Calling mock endpoint")
        self.path = self.path.replace("/mock", "", 1)
        file = self.do_common(default_filenames=["response.json"])
        try:
            if file:
                if self.cfg.response:
                    self.log.info(self.prepare_log_response(code=HTTPStatus.OK, body=file[1]))
                # response_body = file[1]
                status = HTTPStatus.OK
                self.end_headers()
                self.copyfile(file[0], self.wfile)
                return status
        finally:
            file[0].close()

    def do_write(self, content_type, request_data):
        self.log.debug("Calling write endpoint")
        if content_type != APPLICATION_JSON:
            raise TypeError("Incorrect content type. Should be: application/json")
        data = simplejson.loads(request_data)
        if "filename" not in data or "content" not in data:
            raise TypeError("No filename or content")
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
        path = self.translate_path(self.cfg.output + "/" + data["filename"])
        file = open(path, operation, encoding=self.ENCODING)
        file.write(data["content"])
        file.flush()
        fs = os.fstat(file.fileno())
        file.close()
        response_body = simplejson.dumps({
            'message': f'File {data["filename"]} {operation_verb}',
            'filesize': fs[6]
        })
        status = HTTPStatus.OK
        self.log.debug("Command endpoint exiting.")
        return response_body, status

    def do_DELETE(self):

        if self.cfg.request:
            self.log.info(self.prepare_log_request(None))

        response_body, status = self.stop_command()
        self.send_response(status)

        self.send_header(HEADERS.CONTENT_TYPE, APPLICATION_JSON)
        self.send_header(HEADERS.CONTENT_LENGTH, str(len(response_body)) if response_body else 0)

        if self.cfg.response:
            self.log.info(self.prepare_log_response(status, body=response_body if response_body else ''))

        self.end_headers()
        self.wfile.write(response_body.encode('utf-8'))

    def stop_command(self):

        response_body = None

        if self.th is not None and self.th.is_alive():
            self.log.debug("Process exists, sending stop signal.")
            self.th.join()

            if self.th.is_alive():
                self.log.error("Process not stopping, I'm killing myself and all my children processes now.")
                self.th.go_nuclear()
                status = HTTPStatus.INTERNAL_SERVER_ERROR
                if self.th.is_alive():
                    self.log.critical("Something is very wrong.")
                    response_body = simplejson.dumps({"error": "Process still running"}, indent=4 * ' ')
                    status = HTTPStatus.INTERNAL_SERVER_ERROR
            else:
                status = HTTPStatus.OK
                self.log.debug("Process stopped, sending response")
                stdout, stderr = self.th.result()
                response_body = simplejson.dumps({"error": stderr, "output": stdout}, indent=4 * ' ')
        else:
            status = HTTPStatus.NOT_FOUND
            response_body = simplejson.dumps({"message": "No process running"}, indent=4 * ' ')
        return response_body, status

    def do_common(self, default_filenames):

        # path = urllib.parse.unquote(self.path)
        self.path = self.cfg.input + "/" + self.path
        path = self.translate_path(self.path)
        self.log.debug(f"PATH: {path}")

        if os.path.isdir(path):
            self.log.debug("PATH points to directory instead of file, looking for index files")
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

                if self.cfg.response:
                    self.log.info(self.prepare_log_response())

            for index in default_filenames:
                if os.path.isfile(os.path.join(path, index)):
                    path = os.path.join(path, index)
                    break
            else:
                self.log.debug("No index found, serving directory list")
                return [self.list_directory(path), "List for: " + path]

        ctype = self.guess_type(path)

        if path.endswith("/"):
            msg = "File " + path + " not found"
            self.log.warning(msg)
            body = self.prepare_error(HTTPStatus.NOT_FOUND, explain=msg)
            if self.cfg.response:
                self.log.info(self.prepare_log_response(body))
            return None

        try:
            file = open(path, 'rb')
        except OSError as e:
            msg = "OS error: " + str(e)
            self.log.warning(msg)
            body = self.prepare_error(HTTPStatus.NOT_FOUND, explain=msg)
            if self.cfg.response:
                self.log.info(self.prepare_log_response(body))
            return None

        self.log.debug("File '" + path + "' found")

        try:
            fs = os.fstat(file.fileno())
            if HEADERS.IF_MODIFIED_SINCE in self.headers and HEADERS.IF_NONE_MATCH not in self.headers:

                self.log.debug("If-Modified-Since header found in request, attempting to parse.")

                try:
                    ims = email.utils.parsedate_to_datetime(self.headers[HEADERS.IF_MODIFIED_SINCE])
                except (TypeError, IndexError, OverflowError, ValueError):
                    self.log.debug("Error at parsing date from headers")

                else:
                    if ims.tzinfo is None:
                        ims = ims.replace(tzinfo=timezone.utc)

                    if ims.tzinfo is timezone.utc:
                        self.log.debug("Comparing file timestamp to If-Modified-Since")
                        last_modification = datetime.fromtimestamp(fs.st_mtime, timezone.utc)
                        last_modification = last_modification.replace(microsecond=0)

                        if last_modification <= ims:
                            self.log.warning("Modified not matching, sending NOT_MODIFIED")
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
            item_list = os.listdir(path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None
        item_list.sort(key=lambda a: a.lower())
        r = []
        try:
            display_path = urllib.parse.unquote(self.path, errors='surrogatepass')
        except UnicodeDecodeError:
            display_path = urllib.parse.unquote(self.path)
        display_path = html.escape(display_path, quote=False)
        title = f'Directory listing for {display_path}'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{self.ENCODING}">')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name in item_list:
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
        encoded = '\n'.join(r).encode(self.ENCODING, 'surrogateescape')
        file = io.BytesIO()
        file.write(encoded)
        file.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header(HEADERS.CONTENT_TYPE, TEXT_HTML + ";charset=%s" % self.ENCODING)
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

        if arg_list:
            cwd.extend(arg_list)

        self.log.debug("Received command: " + " ".join(cwd) + "\nexecuting...\n")
        if self.th is not None and self.th.is_alive():
            return [HTTPStatus.LOCKED, {'error': 'Another process already running: ' + self.th.process_name}]

        self.th = TardigradeCommandReturningThread(cwd=cwd, timeout=self.cfg.timeout, log=self.log)
        try:
            self.log.debug("Created thread, starting")
            self.th.start()
            if self.cfg.timeout <= 0:
                return [HTTPStatus.OK,
                        {"error": None, "output": "Process " + cwd[0] + " has been started and is now running."}]
            time.sleep(0.1)
            self.th.join()
            self.log.debug("Thread finished, obtaining results")
            stdout, stderr = self.th.result()
            return [HTTPStatus.OK, {"error": stderr, "output": stdout}]
        except subprocess.TimeoutExpired:
            stdout, stderr = self.th.result()
            return [HTTPStatus.REQUEST_TIMEOUT, {"error": stderr, "output": stdout}]
        finally:
            if self.cfg.timeout > 0:
                self.th = None

    # Overrides to bury ugly, useless logs
    def log_request(self, code: int | str = ..., size: int | str = ...) -> None:
        pass

    def log_error(self, format: str, *args: Any) -> None:
        pass
