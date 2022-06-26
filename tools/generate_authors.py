#!/usr/bin/env python3

#
# Generate the AUTHORS file combining existing AUTHORS file with
# git commit log.
#
# Usage: generate_authors.py AUTHORS.src

# Copyright 2022 Moshe Kaplan
# Based on generate_authors.pl by Michael Mann
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import io
import re
import subprocess
import sys


def get_git_authors():
    '''
    Sample line:
    #  4321	Navin R. Johnson <nrjohnson@example.com>
    '''
    GIT_LINE_REGEX = r"^\s*\d+\s+([^<]*)\s*<([^>]*)>"
    cmd = "git --no-pager shortlog --email --summary HEAD".split(' ')
    # check_output is used for Python 3.4 compatability
    git_cmd_output = subprocess.check_output(cmd, universal_newlines=True, encoding='utf-8')

    git_authors = []
    for line in git_cmd_output.splitlines():
        # Check if this is needed:
        line = line.strip()
        match = re.match(GIT_LINE_REGEX, line)
        name = match.group(1).strip()
        email = match.group(2).strip()
        # Try to lower how much spam people get:
        email = email.replace('@', '[AT]')
        git_authors.append((name, email))
    return git_authors


def extract_contributors(authors_content):
    # Extract names and email addresses from the AUTHORS file Contributors
    contributors_content = authors_content.split("= Contributors =", 1)[1]
    contributors_content = contributors_content.split("= Acknowledgements =", 1)[0]
    CONTRIBUTOR_LINE_REGEX = r"^([\w\.\-\'\x80-\xff]+(\s*[\w+\.\-\'\x80-\xff])*)\s+<([^>]*)>"
    contributors = []
    state = ""
    for line in contributors_content.splitlines():
        contributor_match = re.match(CONTRIBUTOR_LINE_REGEX, line)
        if re.search(r'([^\{]*)\{', line):
            if contributor_match:
                name = contributor_match.group(1)
                email = contributor_match.group(3)
                contributors.append((name, email))
            state = "s_in_bracket"
        elif state == "s_in_bracket":
            if re.search(r'([^\}]*)\}', line):
                state = ""
        elif re.search('<', line):
            if contributor_match:
                name = contributor_match.group(1)
                email = contributor_match.group(3)
                contributors.append((name, email))
        elif re.search(r"(e-mail address removed at contributor's request)", line):
            if contributor_match:
                name = contributor_match.group(1)
                email = contributor_match.group(3)
                contributors.append((name, email))
        else:
            pass
    return contributors


def generate_git_contributors_text(contributors_emails, git_authors_emails):
    # Track the email addresses seen to avoid including the same email address twice
    emails_addresses_seen = set()
    for name, email in contributors_emails:
        emails_addresses_seen.add(email.lower())

    output_lines = []
    for name, email in git_authors_emails:
        if email.lower() in emails_addresses_seen:
            continue

        # Skip Gerald, since he's part of the header:
        if email == "gerald[AT]wireshark.org":
            continue

        ntab = 3
        if len(name) >= 8*ntab:
            line = "{name} <{email}>".format(name=name, email=email)
        else:
            ntab -= len(name)/8
            if len(name) % 8:
                ntab += 1
            tabs = '\t'*int(ntab)
            line = "{name}{tabs}<{email}>".format(name=name, tabs=tabs, email=email)

        emails_addresses_seen.add(email.lower())
        output_lines += [line]
    return "\n".join(output_lines)


def main():
    stdoutu8 = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    parser = argparse.ArgumentParser(description="Generate the AUTHORS file combining existing AUTHORS file with git commit log.")
    parser.add_argument("authors", metavar='authors', nargs=1, help="path to AUTHORS file")
    parsed_args = parser.parse_args()

    with open(parsed_args.authors[0], encoding='utf-8') as fh:
        author_content = fh.read()

    # Collect the listed contributors emails so that we don't duplicate them
    # in the listing of git contributors
    contributors_emails = extract_contributors(author_content)
    git_authors_emails = get_git_authors()
    # Then generate the text output for git contributors
    git_contributors_text = generate_git_contributors_text(contributors_emails, git_authors_emails)

    # Now we can write our output:
    acknowledgements_start = author_content.find("\n\n= Acknowledgements =")
    before_acknowledgements = author_content[:acknowledgements_start]
    acknowledgements = author_content[acknowledgements_start:]
    git_contributor_header = '\n\n\n= From git log =\n\n'
    output = before_acknowledgements + git_contributor_header + git_contributors_text + '\n' + acknowledgements
    stdoutu8.write(output)


if __name__ == '__main__':
    main()
