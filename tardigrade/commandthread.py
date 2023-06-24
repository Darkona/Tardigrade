import logging
import signal
import subprocess
import threading

import psutil


class TardigradeCommandReturningThread(threading.Thread):

    def __init__(self, cwd: (str, []) = (), timeout: float = None, log: logging.Logger = logging.Logger):
        super().__init__()
        self.process = None
        self.stdout = None
        self.stderr = None
        self.process_name = None
        self.timeout = timeout
        self.cwd = cwd
        self.log = log

    def run(self):
        self.process = subprocess.Popen(self.cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=None, shell=True, encoding='utf-8', text=True, bufsize=4096)
        self.log.debug("Thread started with process: ")
        self.process_name = self.process.args[0]
        if self.timeout <= 0:
            self.process.wait()

    def go_nuclear(self):
        # If CTRL_C doesn't work, kill them with fire. This will cause self-termination
        for _ in psutil.Process(self.process.pid).children(recursive=True):
            _.send_signal(signal.CTRL_BREAK_EVENT)
        self.stdout, self.stderr = self.process.stdout.read(), self.process.stderr.read()

    def anakin_order_66(self):
        # Kill all children
        try:
            for _ in psutil.Process(self.process.pid).children(recursive=True):
                _.kill()
        except psutil.NoSuchProcess:
            self.log.warning("What is dead cannot die")

    def join(self, timeout: float | None = ...) -> None:
        logging.debug("finalizing thread")
        if self.timeout > 0:
            try:
                self.stdout, self.stderr = self.process.communicate(timeout=self.timeout, input=None)
            except subprocess.TimeoutExpired as e:
                self.log.debug("Process timed out." + str(e))
                self.anakin_order_66()
        else:
            self.anakin_order_66()

        try:
            self.stdout, self.stderr = self.process.communicate(input=None)
        except Exception as e:
            self.log.error(str(e))

        super().join()

    def result(self):
        return self.stdout, self.stderr