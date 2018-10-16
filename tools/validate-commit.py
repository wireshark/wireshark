#!/usr/bin/env python
# Verifies whether commit messages adhere to the standards.
# Checks the author name and email and invokes the tools/commit-msg script.
# Copy this into .git/hooks/post-commit
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import print_function

import argparse
import difflib
import os
import subprocess
import sys
import tempfile


parser = argparse.ArgumentParser()
parser.add_argument('commit', nargs='?', default='HEAD',
                    help='Commit ID to be checked (default %(default)s)')


def print_git_user_instructions():
    print('To configure your name and email for git, run:')
    print('')
    print('  git config --global user.name "Your Name"')
    print('  git config --global user.email "you@example.com"')
    print('')
    print('After that update the author of your latest commit with:')
    print('')
    print('  git commit --amend --reset-author --no-edit')
    print('')


def verify_name(name):
    name = name.lower().strip()
    forbidden_names = ('unknown', 'root', 'user', 'your name')
    if name in forbidden_names:
        return False
    # Warn about names without spaces. Sometimes it is a mistake where the
    # developer accidentally committed using the system username.
    if ' ' not in name:
        print("WARNING: name '%s' does not contain a space." % (name,))
        print_git_user_instructions()
    return True


def verify_email(email):
    email = email.lower().strip()
    try:
        user, host = email.split('@')
    except ValueError:
        # Lacks a '@' (e.g. a plain domain or "foo[AT]example.com")
        return False
    tld = host.split('.')[-1]

    # localhost, localhost.localdomain, my.local etc.
    if 'local' in tld:
        return False

    # Possibly an IP address
    if tld.isdigit():
        return False

    # forbid code.wireshark.org. Submissions could be submitted by other
    # addresses if one would like to remain anonymous.
    if host.endswith('.wireshark.org'):
        return False

    # For documentation purposes only.
    if host == 'example.com':
        return False

    # 'peter-ubuntu32.(none)'
    if '(none)' in host:
        return False

    return True


def tools_dir():
    if __file__.endswith('.py'):
        # Assume direct invocation from tools directory
        return os.path.dirname(__file__)
    # Otherwise it is a git hook. To support git worktrees, do not manually look
    # for the .git directory, but query the actual top level instead.
    cmd = ['git', 'rev-parse', '--show-toplevel']
    srcdir = subprocess.check_output(cmd, universal_newlines=True).strip()
    return os.path.join(srcdir, 'tools')


def verify_body(body):
    fd, filename = tempfile.mkstemp()
    try:
        os.close(fd)
        with open(filename, 'w') as f:
            f.write(body)

        hook_script = os.path.join(tools_dir(), 'commit-msg')
        cmd = ['sh', hook_script, filename]
        subprocess.check_output(cmd, universal_newlines=True)

        with open(filename, 'r') as f:
            newbody = f.read()
    except OSError as ex:
        print('Warning: unable to invoke commit-msg hook: %s' % (ex,))
        return True
    except subprocess.CalledProcessError as ex:
        print('Bad commit message (reported by tools/commit-msg):')
        print(ex.output.strip())
        return False
    finally:
        os.unlink(filename)
    if newbody != body:
        old_lines = body.splitlines(True)
        new_lines = newbody.splitlines(True)
        diff = difflib.unified_diff(old_lines, new_lines,
                                    fromfile='OLD/.git/COMMIT_EDITMSG',
                                    tofile='NEW/.git/COMMIT_EDITMSG')
        # Clearly mark trailing whitespace (GNU patch supports such comments).
        diff = [
            '# NOTE: trailing space on the next line\n%s' % (line,)
            if len(line) > 2 and line[-2].isspace() else line
            for line in diff
        ]
        print('The commit message does not follow our standards.')
        print('Please rewrite it (there are likely whitespace issues):')
        print('')
        print(''.join(diff))
        return False
    return True


def main():
    args = parser.parse_args()
    commit = args.commit
    cmd = ['git', 'show', '--no-patch',
           '--format=%h%n%an%n%ae%n%B', commit, '--']
    output = subprocess.check_output(cmd, universal_newlines=True)
    # For some reason there is always an additional LF in the output, drop it.
    if output.endswith('\n\n'):
        output = output[:-1]
    abbrev, author_name, author_email, body = output.split('\n', 3)
    subject = body.split('\n', 1)[0]

    # If called directly (from the tools directory), print the commit that was
    # being validated. If called from a git hook (without .py extension), try to
    # remain silent unless there are issues.
    if __file__.endswith('.py'):
        print('Checking commit: %s %s' % (abbrev, subject))

    exit_code = 0
    if not verify_name(author_name):
        print('Disallowed author name: {}'.format(author_name))
        exit_code = 1

    if not verify_email(author_email):
        print('Disallowed author email address: {}'.format(author_email))
        exit_code = 1

    if exit_code:
        print_git_user_instructions()

    if not verify_body(body):
        exit_code = 1

    return exit_code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as ex:
        print('\n%s' % ex)
        sys.exit(ex.returncode)
    except KeyboardInterrupt:
        sys.exit(130)
