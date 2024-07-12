#!/usr/bin/env python3
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
import json
import os
import subprocess
import sys
import urllib.request
import re


parser = argparse.ArgumentParser()
parser.add_argument('commit', nargs='?', default='HEAD',
                    help='Commit ID to be checked (default %(default)s)')
parser.add_argument('--commitmsg', help='commit-msg check', action='store')


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


def extract_subject(subject):
    '''Extracts the original subject (ignoring the Revert prefix).'''
    subject = subject.rstrip('\r\n')
    prefix = 'Revert "'
    suffix = '"'
    while subject.startswith(prefix) and subject.endswith(suffix):
        subject = subject[len(prefix):-len(suffix)]
    return subject


def verify_body(body):
    bodynocomments = re.sub('^#.*$', '', body, flags=re.MULTILINE)
    old_lines = bodynocomments.splitlines(True)
    is_good = True
    if len(old_lines) >= 2 and old_lines[1].strip():
        print('ERROR: missing blank line after the first subject line.')
        is_good = False
    cleaned_subject = extract_subject(old_lines[0])
    if len(cleaned_subject) > 80:
        # Note that this check is also invoked by the commit-msg hook.
        print('Warning: keep lines in the commit message under 80 characters.')
        is_good = False
    if not is_good:
        print('''
Please rewrite your commit message to our standards, matching this format:

    component: a very brief summary of the change

    A commit message should start with a brief summary, followed by a single
    blank line and an optional longer description. If the change is specific to
    a single protocol, start the summary line with the abbreviated name of the
    protocol and a colon.

    Use paragraphs to improve readability. Limit each line to 80 characters.

''')
    if any(line.startswith('Bug:') or line.startswith('Ping-Bug:') for line in old_lines):
        sys.stderr.write('''
To close an issue, use "Closes #1234" or "Fixes #1234" instead of "Bug: 1234".
To reference an issue, use "related to #1234" instead of "Ping-Bug: 1234". See
https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically
for details.
''')
        return False

    # Cherry-picking can add an extra newline, which we'll allow.
    cp_line = '\n(cherry picked from commit'
    body = body.replace('\n' + cp_line, cp_line)

    try:
        cmd = ['git', 'stripspace']
        newbody = subprocess.check_output(cmd, input=body, universal_newlines=True)
    except OSError as ex:
        print('Warning: unable to invoke git stripspace: %s' % (ex,))
        return is_good
    if newbody != body:
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
    return is_good



def verify_merge_request():
    # Not needed if/when https://gitlab.com/gitlab-org/gitlab/-/issues/23308 is fixed.
    gitlab_api_pfx = "https://gitlab.com/api/v4"
    # gitlab.com/wireshark/wireshark = 7898047
    project_id = os.getenv('CI_MERGE_REQUEST_PROJECT_ID')
    ansi_csi = '\x1b['
    ansi_codes = {
        'black_white': ansi_csi + '30;47m',
        'bold_red': ansi_csi + '31;1m', # gitlab-runner errors
        'reset': ansi_csi + '0m'
    }
    m_r_iid = os.getenv('CI_MERGE_REQUEST_IID')
    if project_id is None or m_r_iid is None:
        print("This doesn't appear to be a merge request. CI_MERGE_REQUEST_PROJECT_ID={}, CI_MERGE_REQUEST_IID={}".format(project_id, m_r_iid))
        return True

    m_r_sb_protected = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_PROTECTED')
    if m_r_sb_protected == 'true':
        print(f'''\
You're pushing from a protected branch ({os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')}). You will probably
have to close this merge request and push from a different branch.\n
''')
        # Assume that the "Allow commits" test is about to fail.

    m_r_url = '{}/projects/{}/merge_requests/{}'.format(gitlab_api_pfx, project_id, m_r_iid)
    req = urllib.request.Request(m_r_url)
    # print('req', repr(req), m_r_url)
    with urllib.request.urlopen(req) as resp:
        resp_json = resp.read().decode('utf-8')
        # print('resp', resp_json)
        m_r_attrs = json.loads(resp_json)
        try:
            if not m_r_attrs['allow_collaboration']:
                print('''\
{bold_red}ERROR:{reset} Please edit your merge request and make sure the setting
    {black_white}✅ Allow commits from members who can merge to the target branch{reset}
is checked so that maintainers can rebase your change and make minor edits.\
'''.format(**ansi_codes))
                return False
        except KeyError:
            sys.stderr.write('This appears to be a merge request, but we were not able to fetch the "Allow commits" status\n')
    return True


def main():
    args = parser.parse_args()
    commit = args.commit

    # If called from commit-msg script, just validate that part and return.
    if args.commitmsg:
        try:
            with open(args.commitmsg) as f:
                return 0 if verify_body(f.read()) else 1
        except Exception:
            print("Couldn't verify body of message from file '", + args.commitmsg + "'")
            return 1


    if(os.getenv('CI_MERGE_REQUEST_EVENT_TYPE') == 'merge_train'):
        print("If we were on the love train, people all over the world would be joining hands for this merge request.\nInstead, we're on a merge train so we're skipping commit validation checks. ")
        return 0

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

    if not verify_merge_request():
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
