#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import requests
import shutil
import subprocess
import argparse
import signal

# This utility scans the dissector code for URLs, then attempts to
# fetch the links.  The results are shown in stdout, but also, at
# the end of the run, written to files:
# - URLs that couldn't be loaded are written to failures.txt
# - working URLs are written to successes.txt
# - any previous failures.txt is also copied to failures_last_run.txt


# TODO:
# - option to write back to dissector file when there is a failure?
# - make requests in parallel (run takes around 35 minutes)?
# - optionally parse previous successes.txt and avoid fetching them again?
# - make sure URLs are really within comments in code?
# - use urllib.parse or similar to better check URLs?
# - improve regex to allow '+' in URL (like confluence uses)

# Try to exit soon after Ctrl-C is pressed.
should_exit = False


def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


class FailedLookup:

    def __init__(self):
        # Fake values that will be queried (for a requests.get() return value)
        self.status_code = 0
        self.headers = {}
        self.headers['content-type'] = '<NONE>'

    def __str__(self):
        s = ('FailedLookup: status_code=' + str(self.status_code) +
             ' content-type=' + self.headers['content-type'])
        return s


# Dictionary from url -> result
cached_lookups = {}


class Link(object):

    def __init__(self, file, line_number, url):
        self.file = file
        self.line_number = line_number
        self.url = url
        self.tested = False
        self.r = None
        self.success = False
        self.result_from_cache = False

    def __str__(self):
        epan_idx = self.file.find('epan')
        if epan_idx == -1:
            filename = self.file
        else:
            filename = self.file[epan_idx:]
        s = ('SUCCESS  ' if self.success else 'FAILED  ') + \
            filename + ':' + str(self.line_number) + '   ' + self.url
        if True:  # self.r:
            if self.r.status_code:
                s += "   status-code=" + str(self.r.status_code)
                if 'content-type' in self.r.headers:
                    s += (' content-type="' +
                          self.r.headers['content-type'] + '"')
            else:
                s += '    <No response Received>'
        return s

    def validate(self, session):
        # Fetch, but first look in cache
        global cached_lookups
        self.tested = True
        if self.url in cached_lookups:
            if args.verbose:
                print('[Using cached result for', self.url, ']')
            self.r = cached_lookups[self.url]
            self.result_from_cache = True
        else:

            try:
                # Try it.
                self.r = session.get(self.url, timeout=15)

                # Cache this result.
                cached_lookups[self.url] = self.r
            except (ValueError, ConnectionError, Exception):
                if args.verbose:
                    print(self.url, ': failed to make request')
                self.success = False
                # Add bad result to crashed_lookups.
                cached_lookups[self.url] = FailedLookup()
                self.r = cached_lookups[self.url]
                return

        # Check return value
        if self.r.status_code < 200 or self.r.status_code >= 300:
            self.success = False
            return

        # Assume its Ok.
        self.success = True


links = []
files = []


def findLinksInFile(filename):
    with open(filename, 'r') as f:
        for line_number, line in enumerate(f, start=1):
            # TODO: not matching
            # https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol
            urls = re.findall(
                r'https?://(?:[a-zA-Z0-9./_?&=-]+|%[0-9a-fA-F]{2})+', line)

            for url in urls:
                # Lop off any trailing chars that are not part of it
                url = url.rstrip(").',")

                # A url must have a period somewhere
                if '.' not in url:
                    continue
                if args.verbose:
                    print('Found URL:', url)
                global links
                links.append(Link(filename, line_number, url))


# Scan the given folder for links to test.
def findLinksInFolder(folder):
    # Look at files in sorted order, to give some idea of how far through it
    # is.
    for filename in sorted(os.listdir(folder)):
        if filename.endswith('.c'):
            global links
            findLinksInFile(os.path.join(folder, filename))


#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be scanned.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check URL links in dissectors')
parser.add_argument('--file', action='store', default='',
                    help='specify individual dissector file to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')
parser.add_argument('--verbose', action='store_true',
                    help='when enabled, show more output')

args = parser.parse_args()



def isDissectorFile(filename):
    p = re.compile('epan/dissectors/packet-.*\.c')
    return p.match(filename)

# Get files from wherever command-line args indicate.
if args.file:
    # Fetch links from single file.
    findLinksInFile(args.file)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Fetch links from files (dissectors files only)
    files = list(filter(lambda f : isDissectorFile(f), files))
    for f in files:
        findLinksInFile(f)
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    files = list(filter(lambda f : isDissectorFile(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    files_staged = list(filter(lambda f : isDissectorFile(f), files_staged))
    for f in files:
        findLinksInFile(f)
    for f in files_staged:
        if not f in files:
            findLinksInFile(f)
            files.append(f)
else:
    # Find links from dissector folder.
    findLinksInFolder(os.path.join(os.path.dirname(
        __file__), '..', 'epan', 'dissectors'))


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


# Prepare one session for all requests. For args, see
# https://requests.readthedocs.io/en/master/
session = requests.Session()
# N.B. Can set timeout here but doesn't get used.
# Default headers don't always get responses where proper browsers do.
session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'})

# Try out the links.
for checks, link in enumerate(links):
    if should_exit:
        # i.e. if Ctrl-C has been pressed.
        exit(0)
    link.validate(session)
    if args.verbose or not link.success:
        print(link)


# Write failures to a file.  Back up any previous first though.
if os.path.exists('failures.txt'):
    shutil.copyfile('failures.txt', 'failures_last_run.txt')
with open('failures.txt', 'w') as f_f:
    for l in links:
        if l.tested and not l.success:
            f_f.write(str(l) + '\n')
# And successes
with open('successes.txt', 'w') as f_s:
    for l in links:
        if l.tested and l.success:
            f_s.write(str(l) + '\n')


# Count and show overall stats.
passed, failed, cached = 0, 0, 0
for l in links:
    if not l.result_from_cache:
        if l.tested:
            if l.success:
                passed += 1
            else:
                failed += 1
    else:
        cached += 1

print('--------------------------------------------------------------------------------------------------')
print(len(links), 'links checked: ', passed, 'passed,',
      failed, 'failed (', cached, 'results from cache)')
