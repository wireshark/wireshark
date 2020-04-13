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

# This utility scans the dissector code for URLs, then attempts to
# fetch the links.  The results are shown in stdout, but also, at
# the end of the run, written to files:
# - URLs that couldn't be loaded are written to failures.txt
# - working URLs are written to successes.txt
# - any previous failures.txt is also copied to failures_last_run.txt


# TODO:
# - allow single dissector name to be given as a command-line arg.
# - option to write back to dissector file when there is a failure?
# - make requests in parallel (run takes around 35 minutes)?
# - optionally parse previous successes.txt and avoid fetching them again?
# - make sure URLs are really within comments in code?
# - use urllib.parse or similar to better check URLs?


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


# These are strings typically seen after redirecting to a page that won't have
# What we are looking for. Usually get a 404 for these anyway.
# TODO: likely more of these...
apology_strings = ["sorry, we cannot find the page",
                   "this page could not be found",
                   "the page you're looking for can't be found",
                   "the content you are looking for cannot be found...",
                   "the resource you are looking for has been removed"]


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
        s = (('SUCCESS  ' if self.success else 'FAILED  ') + self.file + ':' + str(self.line_number) +
             '   ' + self.url + "   status-code=" + str(self.r.status_code) +
             ' content-type="' + (self.r.headers['content-type'] if ('content-type' in self.r.headers) else 'NONE') + '"')
        return s

    def looksLikeApology(self):
        content = str(self.r.content)
        # N.B. invariably comes back as just one line...
        if any(needle in content for needle in apology_strings):
            print('Found apology!')
            return True
        return False

    def validate(self, session):
        # Fetch, but first look in cache
        global cached_lookups
        self.tested = True
        if self.url in cached_lookups:
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

        # Look for 'not really found' type strings in r.content
        if self.looksLikeApology():
            print('Got body, but it looks like content has moved?')
            self.success = False
            return

        # Assume its Ok.
        self.success = True

# Scan the given folder for links to test.


def findLinks(folder):
    links = []

    # Look at files in sorted order, to  give some idea of how far through it
    # is.
    for filename in sorted(os.listdir(folder)):
        if filename.endswith('.c'):
            with open(os.path.join(folder, filename), 'r') as f:
                for line_number, line in enumerate(f, start=1):
                    urls = re.findall(
                        r'https?://(?:[a-zA-Z0-9./_?&=-]+|%[0-9a-fA-F]{2})+', line)

                    for url in urls:
                        # Lop off any trailing chars that are not part of it
                        url = url.rstrip(").',")

                        # A url must have a period somewhere
                        if '.' not in url:
                            continue

                        print('Found URL:', url)
                        links.append(Link(filename, line_number, url))
    print('Found', len(links), 'links')
    return links


#################################################################
# Main logic.

# Find links from dissector folder.
links = findLinks(os.path.join(os.path.dirname(__file__), '..', 'epan', 'dissectors'))


# Prepare one session for all requests. For args, see
# https://requests.readthedocs.io/en/master/
session = requests.Session()
# N.B. Can set timeout here but doesn't get used.
# Default headers don't always get responses where proper browsers do.
session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'})

# Try out the links.
limit = 5000        # Control for debug
for checks, link in enumerate(links):
    link.validate(session)
    print(link)
    if checks > limit:
        break

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


# Show overall stats.
passed, failed, cached = 0, 0, 0
for l in links:
    if l.tested and not l.result_from_cache:
        if l.success:
            passed += 1
        else:
            failed += 1
    if l.result_from_cache:
        cached += 1
print('--------------------------------------------------------------------------------------------------')
print(len(links), 'links checked: , ', passed, 'passed,',
      failed, 'failed', cached, 'results from cache')
