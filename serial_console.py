#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import os
import argparse
import threading
import serial
from serial.tools.list_ports import comports
import signal
import time

EXITING = threading.Event()
PROMPT_READY = threading.Event()
PROMPT = ':/ $'
PROMPT_ROOT = ':/ #'


def signal_handler(signal, frame):
    print >> sys.stderr, 'SIGINT'
    exit_app()


def exit_app():
    EXITING.set()


# setup_signal()
signal.signal(signal.SIGINT, signal_handler)
# Unfortunately, the Python docs on CTRL_C_EVENT don't really state that explicitly: When the docs say "the signal can only be used with os.kill", they mean it literally, as in "really, all you can do with this signal is use it as in os.kill(pid, signal.CTRL_C_EVENT), so don't try registering a handler for it".
# signal.signal(signal.CTRL_C_EVENT, signal_handler)


class Script(object):
    def __init__(self, cmds=[], path=None):
        self.path = path
        self.pos = 0
        self.commands = cmds

    def __iter__(self):
        self._load()
        self.pos = 0
        return self

    def _load(self):
        with open(self.path, 'rt') as f:
            self.commands = f.readlines()

    def load(self, path):
        self.path = path
        self._load()

    def next(self):
        old = self.pos
        if self.pos == len(self.commands):
            raise StopIteration
        self.pos += 1
        return self.commands[old]


def is_prompt_ready(log):
    log = log.strip()
    if len(log) == 0:
        return False
    if log.endswith(PROMPT) or log.endswith(PROMPT_ROOT):
        return True
    return False


def signal_prompt_ready():
    # print>>sys.stderr, 'console is ready'
    if not PROMPT_READY.is_set():
        PROMPT_READY.set()


class ConsoleLogger(object):
    # global EXITING
    global PROMPT_READY

    def __init__(self, sio, outfile):
        self.tag = 'console_logger'
        self.sio = sio
        self.outfile = outfile
        self.STOP = threading.Event()

    def _is_prompt_ready(self, log):
        log = log.strip()
        if len(log) == 0:
            return False
        if log.endswith(PROMPT) or log.endswith(PROMPT_ROOT):
            return True
        return False

    def _signal_prompt_ready(self):
        # print>>sys.stderr, 'console is ready'
        if not PROMPT_READY.is_set():
            PROMPT_READY.set()

    def _exiting(self):
        return self.STOP.is_set() or EXITING.is_set()

    def _exit(self):
        EXITING.set()

    def start(self):
        # start a thread for logging
        logger = threading.Thread(
            target=self._do_logging, name=self.tag)
        logger.daemon = True
        logger.start()

    def stop(self):
        self.STOP.set()

    def _do_logging(self):
        while not self._exiting():
            try:
                data = self.sio.read(self.sio.inWaiting() or 1)
                # print len(data), data,
                # 0
                if len(data) == 0:
                    continue
                else:
                    self.outfile.write(data)
                    # print >> outfile, data
                    print data,
                    if self._is_prompt_ready(data):
                        # print>>sys.stderr, 'console is ready'
                        self._signal_prompt_ready()
            except KeyboardInterrupt:
                self._exit()
            except IOError:
                self._exit()
        self._flush()

    def _flush(self):
        if self.sio.isOpen() and self.sio.inWaiting() > 0:
            data = self.sio.read(self.sio.inWaiting())
            self.outfile.write(data)
            print data,


def console_logger(sio, outfile):
    # log the kernel log to a file
    # and report it to main thread when the kernel console is actived
    # global EXITING
    while not EXITING.is_set():
        try:
            data = sio.read(sio.inWaiting() or 1)
            # print len(data), data,
            # 0
            if len(data) == 0:
                continue
            else:
                outfile.write(data)
                # print >> outfile, data
                print data,
                if is_prompt_ready(data):
                    # print>>sys.stderr, 'console is ready'
                    signal_prompt_ready()
        except KeyboardInterrupt:
            EXITING.set()
        except IOError:
            EXITING.set()

    if sio.isOpen() and sio.inWaiting() > 0:
        data = sio.read(sio.inWaiting())
        outfile.write(data)
        print data,


def load_cmdfile(cmdpath):
    return Script(path=cmdpath)


def handle_cmdfile(sio, scripts):
    # global EXITING

    # wait for the console to be ready
    print >> sys.stderr, "waiting for the console prompt"
    DUMMY_CMD = 'echo > /dev/null\n'.encode('utf-8')
    sio.write(DUMMY_CMD)
    PROMPT_READY.wait()

    try:
        for cmd in scripts:
            print >> sys.stderr, "cmd=", cmd

            # comment
            if cmd.startswith("#"):
                continue
            # sleep, we don't care about reponse of a comand,
            # so like sleep cmd, it should be handled at the client side
            if cmd.startswith('sleep'):
                time.sleep(int(cmd.split()[1]))
                continue

            # send command
            cmd += '\n'
            u8 = cmd.encode('utf-8')
            sio.write(u8)
            # and wait for the prompt
            PROMPT_READY.clear()
            # 60s
            PROMPT_READY.wait(60)
    except KeyboardInterrupt:
        print >> sys.stderr, "keyboard interrupt"
        EXITING.set()
    except IOError:
        print >> sys.stderr, "ioerror"
        EXITING.set()


def console(args, port, outfile):
    # read kernel log from the serial
    # and at the same time, write the log to the file
    # You can set timeout = None, then the read call will block
    # until the requested number of bytes are there.
    sio = serial.Serial(
        port=port, baudrate=921600, bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
        timeout=1)

    # start a thread for logging
    # logger = threading.Thread(
    #     target=console_logger, name='console_logger', args=(sio, outfile))
    # logger.daemon = True
    # logger.start()
    logger = ConsoleLogger(sio, outfile)
    logger.start()

    if args.cmdfile:
        script = load_cmdfile(args.cmdfile)
        handle_cmdfile(sio, script)

    global EXITING
    if args.loopcmd:
        while(not EXITING.is_set()):
            handle_cmdfile(sio, script)

    # exit console_logger
    if not EXITING.is_set():
        try:
            print>>sys.stderr, "press any key to stop"
            raw_input()
        except KeyboardInterrupt:
            pass
        finally:
            EXITING.set()

    # logger is a daemon thread, we don't need to join
    # logger.join()
    sio.close()
    return 0


THE_SERIAL_PORT = 'USB Serial Port'
def detect_port():
    ret = None
    for (port, desc, hwid) in sorted(comports()):
        sys.stderr.write('{:20} {}\n'.format(port, desc))
        # hope the last one is for what we want
        if desc.startswith(THE_SERIAL_PORT):
            ret = port
    return ret


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description='serial console')
    parser.add_argument(
        '-p', '--port', action='store', dest='port', default=None,
        help='port number, default use detected port')
    parser.add_argument(
        '-c', '--cmd', action='store', dest='cmd', default=None,
        help='adb shell commands')
    parser.add_argument(
        '-f', '--file', action='store', dest='cmdfile', default=None,
        help='load commeands from a file')
    parser.add_argument(
        '-l', '--loop', action='store_true', dest='loopcmd', default=False,
        help='loop commands')
    parser.add_argument(
        '-o', '--option', action='store', dest='options',
        default=None, help='options: timestamp')
    parser.add_argument(
        'log', nargs='?', default='-', help='log file, default to stdout')
    args = parser.parse_args(argv[1:])

    port = args.port
    if not port:
        port = detect_port()
    if not port:
        parser.print_help()
        return -1

    if args.log is '-':
        outfile = sys.stdout
        return console(args, port, outfile)
    else:
        with open(args.log, 'wt', 0) as outfile:
            return console(args, port, outfile)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
