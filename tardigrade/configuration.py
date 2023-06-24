import argparse


class TardigradeConfiguration(argparse.Namespace):
    # Configuration with all defaults, override by configuration file or running arguments
    version = ""
    configFile = False
    extra: list = []
    port = 8000
    directory = '/'
    input = '/input'
    output = '/output'
    timeout = 10
    log_server = False
    loglevel = 'info'
    options: list = []
    filename = '/output/logs/tardigrade.log'
    max_bytes = 0
    count = 0
    web_host = None
    web_url = None
    method = 'POST'
    secure = False
    credentials: tuple = ('', '')
    colors: dict = {}
    mime_types: argparse.Namespace()
    log_formats: argparse.Namespace()
    header, body, request, response, console, color, banner = True, True, True, True, True, True, True
    file_log = False
    web_log = False

    __mimetypes = {
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
    __default_formats = {
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

        self.header = "no-header" not in self.options and not self.log_server
        self.body = "no-body" not in self.options and not self.log_server
        self.request = "no-request" not in self.options and not self.log_server
        self.response = "no-response" not in self.options and not self.log_server
        self.console = "no-console" not in self.options
        self.color = "no-color" not in self.options
        self.banner = "no-banner" not in self.options
        self.file_log = "file" in self.extra
        self.web_log = "web" in self.extra

    def __init__(self, ver: str):
        self.log_formats = argparse.Namespace(**self.__default_formats)
        self.mime_types = argparse.Namespace(**self.__mimetypes)
        self.version = ver
        super().__init__()
