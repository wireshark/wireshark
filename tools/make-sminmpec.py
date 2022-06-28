#!/usr/bin/env python3
# create the enterprises.tsv file from
# https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
# or an offline copy
#
# Copyright 2022 by Moshe Kaplan
# Based on make-sminmpec.pl by Gerald Combs
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2004 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import re
import urllib.request


ENTERPRISE_NUMBERS_URL = "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers"

ENTERPRISES_HEADER = """\
#
# generated from https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
# run "tools/make-sminmpec.py [infile] outfile" to regenerate
#
# The format used here is: <NUMERICAL_ID><SPACE><NAME>
# Where SPACE can be any sequence of spaces and tabs.
#
"""

DECIMAL_PATTERN = r"^(\d+)"
# up to three spaces because of formatting errors in the source
ORGANIZATION_PATTERN = r"^   ?(\S.*)"
FORMERLY_PATTERN = r" \((formerly .*)\)"


def generate_enterprise_files(file_content):
    # We only care about the "Decimal" and "Organization",
    # not the contact or email
    org_lines = []
    last_updated = ""
    end_seen = False
    for line in file_content.splitlines():
        decimal_match = re.match(DECIMAL_PATTERN, line)
        if decimal_match:
            decimal = decimal_match.group(0)
        elif re.match(ORGANIZATION_PATTERN, line):
            organization = line.strip()
            if organization.lower() == "unassigned":
                continue
            organization = re.sub(FORMERLY_PATTERN, r"\t# \1", organization)
            org_lines += [decimal + "\t" + organization]
        elif "last updated" in line.lower():
            last_updated = line
        elif "end of document" in line.lower():
            end_seen = True

    if not end_seen:
        raise Exception('"End of Document" not found. Truncated source file?')

    last_updated_line = "# " + last_updated + "\n\n"
    output = ENTERPRISES_HEADER + last_updated_line + "\n".join(org_lines) + "\n"
    return output


def main():
    parser = argparse.ArgumentParser(description="Create the enterprises.tsv file.")
    parser.add_argument('infile', nargs='?')
    parser.add_argument('outfile', nargs=1)
    parsed_args = parser.parse_args()

    if parsed_args.infile:
        with open(parsed_args.infile, encoding='utf-8') as fh:
            data = fh.read()
    else:
        with urllib.request.urlopen(ENTERPRISE_NUMBERS_URL) as f:
            if f.status != 200:
                raise Exception("request for " + ENTERPRISE_NUMBERS_URL + " failed with result code " + f.status)
            data = f.read().decode('utf-8')

    enterprises_content = generate_enterprise_files(data)
    with open(parsed_args.outfile[0], encoding='utf-8', mode='w') as fh:
        fh.write(enterprises_content)


if __name__ == "__main__":
    main()
