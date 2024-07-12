#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import aiohttp
import asyncio
import os
import re
import shutil
import signal
import subprocess

# This utility scans the dissector code for URLs, then attempts to
# fetch the links.  The results are shown in stdout, but also, at
# the end of the run, written to files:
# - URLs that couldn't be loaded are written to failures.txt
# - working URLs are written to successes.txt
# - any previous failures.txt is also copied to failures_last_run.txt
#
# N.B. preferred form of RFC link is e.g., https://tools.ietf.org/html/rfc4349


# TODO:
# - option to write back to dissector file when there is a failure?
# - optionally parse previous/recent successes.txt and avoid fetching them again?
# - make sure URLs are really within comments in code?
# - use urllib.parse or similar to better check URLs?
# - improve regex to allow '+' in URL (like confluence uses)

# Try to exit soon after Ctrl-C is pressed.
should_exit = False


def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')
    try:
        tasks = asyncio.all_tasks()
    except (RuntimeError):
        # we haven't yet started the async link checking, we can exit directly
        exit(1)
    # ignore further SIGINTs while we're cancelling the running tasks
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    for t in tasks:
        t.cancel()

signal.signal(signal.SIGINT, signal_handler)


class FailedLookup:

    def __init__(self):
        # Fake values that will be queried (for a requests.get() return value)
        self.status = 0
        self.headers = {}
        self.headers['content-type'] = '<NONE>'

    def __str__(self):
        s = ('FailedLookup: status=' + str(self.status) +
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

    def __str__(self):
        epan_idx = self.file.find('epan')
        if epan_idx == -1:
            filename = self.file
        else:
            filename = self.file[epan_idx:]
        s = ('SUCCESS  ' if self.success else 'FAILED  ') + \
            filename + ':' + str(self.line_number) + '   ' + self.url
        if True:  # self.r:
            if self.r.status:
                s += "   status-code=" + str(self.r.status)
                if 'content-type' in self.r.headers:
                    s += (' content-type="' +
                          self.r.headers['content-type'] + '"')
            else:
                s += '    <No response Received>'
        return s

    def validate(self):
        global cached_lookups
        global should_exit
        if should_exit:
            return
        self.tested = True
        if self.url in cached_lookups:
            self.r = cached_lookups[self.url]
        else:
            self.r = FailedLookup()

        if self.r.status < 200 or self.r.status >= 300:
            self.success = False
        else:
            self.success = True

        if (args.verbose or not self.success) and not should_exit:
            print(self)

links = []
files = []
all_urls = set()

def find_links_in_file(filename):
    if os.path.isdir(filename):
        return

    with open(filename, 'r', encoding="utf8") as f:
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
                global links, all_urls
                links.append(Link(filename, line_number, url))
                all_urls.add(url)


# Scan the given folder for links to test. Recurses.
def find_links_in_folder(folder):
    files_to_check = []
    for root,subfolders,files in os.walk(folder):
        for f in files:
            if should_exit:
                return
            file = os.path.join(root, f)
            if file.endswith('.c') or file.endswith('.adoc'):
                files_to_check.append(file)

    # Deal with files in sorted order.
    for file in sorted(files_to_check):
        find_links_in_file(file)



async def populate_cache(sem, session, url):
    global cached_lookups
    if should_exit:
        return
    async with sem:
        try:
            async with session.get(url) as r:
                cached_lookups[url] = r
                if args.verbose:
                    print('checking ', url, ': success', sep='')

        except (asyncio.CancelledError, ValueError, ConnectionError, Exception):
            cached_lookups[url] = FailedLookup()
            if args.verbose:
                print('checking ', url, ': failed', sep='')


async def check_all_links(links):
    sem = asyncio.Semaphore(50)
    timeout = aiohttp.ClientTimeout(total=25)
    connector = aiohttp.TCPConnector(limit=30)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
    async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout) as session:
        tasks = [populate_cache(sem, session, u) for u in all_urls]
        try:
            await asyncio.gather(*tasks)
        except (asyncio.CancelledError):
            await session.close()

    for link in links:
        link.validate()


#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be scanned.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check URL links in dissectors')
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')
parser.add_argument('--verbose', action='store_true',
                    help='when enabled, show more output')
parser.add_argument('--docs', action='store_true',
                    help='when enabled, also check document folders')


args = parser.parse_args()


def is_dissector_file(filename):
    p = re.compile(r'epan/dissectors/packet-.*\.c')
    return p.match(filename)


# Get files from wherever command-line args indicate.
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not os.path.isfile(f) and not f.startswith('epan'):
            f = os.path.join('epan', 'dissectors', f)
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
            find_links_in_file(f)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Fetch links from files (dissectors files only)
    files = list(filter(is_dissector_file, files))
    for f in files:
        find_links_in_file(f)
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    files = list(filter(is_dissector_file, files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    files_staged = list(filter(is_dissector_file, files_staged))
    for f in files:
        find_links_in_file(f)
    for f in files_staged:
        if f not in files:
            find_links_in_file(f)
            files.append(f)
elif args.docs:
    # Find links from doc folder(s)
    find_links_in_folder(os.path.join(os.path.dirname(__file__), '..', 'doc'))
    find_links_in_folder(os.path.join(os.path.dirname(__file__), '..', 'docbook'))

else:
    # Find links from dissector folder.
    find_links_in_folder(os.path.join(os.path.dirname(__file__), '..', 'epan', 'dissectors'))


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    if not args.docs:
        print('All dissector modules\n')
    else:
        print('Document sources')

asyncio.run(check_all_links(links))

# Write failures to a file.  Back up any previous first though.
if os.path.exists('failures.txt'):
    shutil.copyfile('failures.txt', 'failures_last_run.txt')
with open('failures.txt', 'w') as f_f:
    for link in links:
        if link.tested and not link.success:
            f_f.write(str(link) + '\n')
# And successes
with open('successes.txt', 'w') as f_s:
    for link in links:
        if link.tested and link.success:
            f_s.write(str(link) + '\n')


# Count and show overall stats.
passed, failed = 0, 0
for link in links:
    if link.tested:
        if link.success:
            passed += 1
        else:
            failed += 1

print('--------------------------------------------------------------------------------------------------')
print(len(links), 'links checked: ', passed, 'passed,', failed, 'failed')
