import logging
import zlib

import logging
import json
import sys

LOG_TYPE_STRING = 1
LOG_TYPE_INFO = 2

class JsonFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings after parsing the LogRecord.

    @param dict fmt_dict: Key: logging format attribute pairs. Defaults to {"message": "message"}.
    @param str time_format: time.strftime() format string. Default: "%Y-%m-%dT%H:%M:%S"
    @param str msec_format: Microsecond formatting. Appended at the end. Default: "%s.%03dZ"
    """

    def __init__(self, fmt_dict: dict = None, time_format: str = "%Y-%m-%dT%H:%M:%S", msec_format: str = "%s.%03dZ"):
        self.fmt_dict = fmt_dict if fmt_dict is not None else {"message": "message"}
        self.default_time_format = time_format
        self.default_msec_format = msec_format
        self.datefmt = None

    def usesTime(self) -> bool:
        """
        Overwritten to look for the attribute in the format dict values instead of the fmt string.
        """
        return "asctime" in self.fmt_dict.values()

    def formatMessage(self, record) -> dict:
        """
        Overwritten to return a dictionary of the relevant LogRecord attributes instead of a string.
        KeyError is raised if an unknown attribute is provided in the fmt_dict.
        """
        return {fmt_key: record.__dict__[fmt_val] for fmt_key, fmt_val in self.fmt_dict.items()}

    def format(self, record) -> str:
        """
        Mostly the same as the parent's class method, the difference being that a dict is manipulated and dumped as JSON
        instead of a string.
        """
        record.message = record.getMessage()

        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)

        message_dict = self.formatMessage(record)

        if record.exc_info:
            # Cache the traceback text to avoid converting it multiple times
            # (it's constant anyway)
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)

        if record.exc_text:
            message_dict["exc_info"] = record.exc_text

        if record.stack_info:
            message_dict["stack_info"] = self.formatStack(record.stack_info)

        t = record.__dict__.get("type")
        if t and t == LOG_TYPE_STRING:
            message_dict["type"] = "string"
            message_dict["fqfn"] = record.__dict__.get("fqfn")
        elif not t:
            message_dict["type"] = "info"
        return json.dumps(message_dict, default=str)

class LogHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__(sys.stdout)
        self.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))

    def emit(self, record: logging.LogRecord):
        color = zlib.adler32(record.name.encode()) % 7 + 31
        if isinstance(record.msg, str) and not isinstance(self.formatter, JsonFormatter):
            if record.__dict__.get("type", LOG_TYPE_INFO) == LOG_TYPE_STRING:
                record.msg = "String created: " + record.__dict__.get("fqfn") + " -> " + record.msg
            record.name = ("\x1b[%dm" % color) + record.name + "\x1b[0m"
            record.msg = ("\x1b[%dm" % color) + record.msg + "\x1b[0m"
        # else:  # When trying to log non-strings, skip coloring
            # print("Not coloring log msg of type: ", type(record.msg))
        super(LogHandler, self).emit(record)
