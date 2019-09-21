#!/usr/bin/env python3
# Convenience shell for using sharkd, including history and tab completion.
#
# Copyright (c) 2019 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import argparse
import contextlib
import glob
import json
import logging
import os
import readline
import selectors
import signal
import subprocess
import sys

_logger = logging.getLogger(__name__)

# grep -Po 'tok_req, "\K\w+' sharkd_session.c
all_commands = """
load
status
analyse
info
check
complete
frames
tap
follow
iograph
intervals
frame
setcomment
setconf
dumpconf
download
bye
""".split()
all_commands += """
!pretty
!histfile
!debug
""".split()


class SharkdShell:
    def __init__(self, pretty, history_file):
        self.pretty = pretty
        self.history_file = history_file

    def ignore_sigint(self):
        # Avoid terminating the sharkd child when ^C in the shell.
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def sharkd_process(self):
        sharkd = 'sharkd'
        env = os.environ.copy()
        # Avoid loading user preferences which may trigger deprecation warnings.
        env['WIRESHARK_CONFIG_DIR'] = '/nonexistent'
        proc = subprocess.Popen([sharkd, '-'],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env=env,
                                preexec_fn=self.ignore_sigint)
        banner = proc.stderr.read1().decode('utf8')
        if banner.strip() != 'Hello in child.':
            _logger.warning('Unexpected banner: %r', banner)
        return proc

    def completer(self, text, state):
        if state == 0:
            origline = readline.get_line_buffer()
            line = origline.lstrip()
            skipped = len(origline) - len(line)
            startpos = readline.get_begidx() - skipped
            curpos = readline.get_endidx() - skipped
            # _logger.debug('Completing: head=%r cur=%r tail=%r',
            #              line[:startpos], line[startpos:curpos], line[curpos:])
            completions = []
            if startpos == 0:
                completions = all_commands
            elif line[:1] == '!':
                cmd = line[1:startpos].strip()
                if cmd == 'pretty':
                    completions = ['jq', 'indent', 'off']
                elif cmd == 'histfile':
                    # spaces in paths are not supported for now.
                    completions = glob.glob(glob.escape(text) + '*')
                elif cmd == 'debug':
                    completions = ['on', 'off']
            completions = [x for x in completions if x.startswith(text)]
            if len(completions) == 1:
                completions = [completions[0] + ' ']
            self.completions = completions
        try:
            return self.completions[state]
        except IndexError:
            return None

    def wrap_exceptions(self, fn):
        # For debugging, any exception in the completion function is usually
        # silently ignored by readline.
        def wrapper(*args):
            try:
                return fn(*args)
            except Exception as e:
                _logger.exception(e)
                raise
        return wrapper

    def add_history(self, line):
        # Emulate HISTCONTROL=ignorespace to avoid adding to history.
        if line.startswith(' '):
            return
        # Emulate HISTCONTROL=ignoredups to avoid duplicate history entries.
        nitems = readline.get_current_history_length()
        lastline = readline.get_history_item(nitems)
        if lastline != line:
            readline.add_history(line)

    def parse_command(self, cmd):
        '''Converts a user-supplied command to a sharkd one.'''
        # Support 'foo {...}' as alias for '{"req": "foo", ...}'
        if cmd[0].isalpha():
            if ' ' in cmd:
                req, cmd = cmd.split(' ', 1)
            else:
                req, cmd = cmd, '{}'
        elif cmd[0] == '!':
            return self.parse_special_command(cmd[1:])
        else:
            req = None
        try:
            c = json.loads(cmd)
            if req is not None:
                c['req'] = req
        except json.JSONDecodeError as e:
            _logger.error('Invalid command: %s', e)
            return
        if type(c) != dict or not 'req' in c:
            _logger.error('Missing req key in request')
            return
        return c

    def parse_special_command(self, cmd):
        args = cmd.split()
        if not args:
            _logger.warning('Missing command')
            return
        if args[0] == 'pretty':
            choices = ['jq', 'indent']
            if len(args) >= 2:
                self.pretty = args[1] if args[1] in choices else None
            print('Pretty printing is now', self.pretty or 'disabled')
        elif args[0] == 'histfile':
            if len(args) >= 2:
                self.history_file = args[1] if args[1] != 'off' else None
            print('History is now', self.history_file or 'disabled')
        elif args[0] == 'debug':
            if len(args) >= 2 and args[1] in ('on', 'off'):
                _logger.setLevel(
                    logging.DEBUG if args[1] == 'on' else logging.INFO)
            print('Debug logging is now',
                  ['off', 'on'][_logger.level == logging.DEBUG])
        else:
            _logger.warning('Unsupported command %r', args[0])

    @contextlib.contextmanager
    def wrap_history(self):
        '''Loads history at startup and saves history on exit.'''
        readline.set_auto_history(False)
        try:
            if self.history_file:
                readline.read_history_file(self.history_file)
            h_len = readline.get_current_history_length()
        except FileNotFoundError:
            h_len = 0
        try:
            yield
        finally:
            new_items = readline.get_current_history_length() - h_len
            if new_items > 0 and self.history_file:
                open(self.history_file, 'a').close()
                readline.append_history_file(new_items, self.history_file)

    def shell_prompt(self):
        '''Sets up the interactive prompt.'''
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.wrap_exceptions(self.completer))
        readline.set_completer_delims(' ')
        return self.wrap_history()

    def read_command(self):
        while True:
            try:
                origline = input('# ')
            except EOFError:
                raise
            except KeyboardInterrupt:
                print('^C', file=sys.stderr)
                continue
            cmd = origline.strip()
            if not cmd:
                return
            self.add_history(origline)
            c = self.parse_command(cmd)
            if c:
                return json.dumps(c)

    def want_input(self):
        '''Request the prompt to be displayed.'''
        os.write(self.user_input_wr, b'x')

    def main_loop(self):
        sel = selectors.DefaultSelector()
        user_input_rd, self.user_input_wr = os.pipe()
        self.want_input()
        with self.sharkd_process() as proc, self.shell_prompt():
            self.process = proc
            sel.register(proc.stdout, selectors.EVENT_READ, self.handle_stdout)
            sel.register(proc.stderr, selectors.EVENT_READ, self.handle_stderr)
            sel.register(user_input_rd, selectors.EVENT_READ, self.handle_user)
            interrupts = 0
            while True:
                try:
                    events = sel.select()
                    _logger.debug('got events: %r', events)
                    if not events:
                        break
                    for key, mask in events:
                        key.data(key)
                    interrupts = 0
                except KeyboardInterrupt:
                    print('Interrupt again to abort immediately.', file=sys.stderr)
                    interrupts += 1
                    if interrupts >= 2:
                        break
                if self.want_command:
                    self.ask_for_command_and_run_it()
                # Process died? Stop the shell.
                if proc.poll() is not None:
                    break

    def handle_user(self, key):
        '''Received a notification that another prompt can be displayed.'''
        os.read(key.fileobj, 4096)
        self.want_command = True

    def ask_for_command_and_run_it(self):
        cmd = self.read_command()
        if not cmd:
            # Give a chance for the event loop to run again.
            self.want_input()
            return
        self.want_command = False
        _logger.debug('Running: %r', cmd)
        self.process.stdin.write((cmd + '\n').encode('utf8'))
        self.process.stdin.flush()

    def handle_stdout(self, key):
        resp = key.fileobj.readline().decode('utf8')
        _logger.debug('Response: %r', resp)
        if not resp:
            raise EOFError
        self.want_input()
        resp = resp.strip()
        if resp:
            try:
                if self.pretty == 'jq':
                    subprocess.run(['jq', '.'], input=resp,
                                   universal_newlines=True)
                elif self.pretty == 'indent':
                    r = json.loads(resp)
                    json.dump(r, sys.stdout, indent='  ')
                    print('')
                else:
                    print(resp)
            except Exception as e:
                _logger.warning('Dumping output as-is due to: %s', e)
                print(resp)

    def handle_stderr(self, key):
        data = key.fileobj.read1().decode('utf8')
        print(data, end="", file=sys.stderr)


parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true',
                    help='Enable verbose logging')
parser.add_argument('--pretty', choices=['jq', 'indent'],
                    help='Pretty print responses (one of: %(choices)s)')
parser.add_argument('--histfile',
                    help='Log shell history to this file')


def main(args):
    logging.basicConfig()
    _logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    shell = SharkdShell(args.pretty, args.histfile)
    try:
        shell.main_loop()
    except EOFError:
        print('')


if __name__ == '__main__':
    main(parser.parse_args())
