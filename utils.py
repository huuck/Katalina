import logging
import zlib


class LogHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter('%(levelname)-7s | %(name)-8s | %(message)s'))

    def emit(self, record: logging.LogRecord):
        color = zlib.adler32(record.name.encode()) % 7 + 31
        if type(record.msg) is str:
            record.name = ("\x1b[%dm" % color) + record.name + "\x1b[0m"
            record.msg = ("\x1b[%dm" % color) + record.msg + "\x1b[0m"
        # else:  # When trying to log non-strings, skip coloring
            # print("Not coloring log msg of type: ", type(record.msg))
        super(LogHandler, self).emit(record)
