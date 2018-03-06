#!/usr/bin/env python
"""
Check the sanity of field definitions in Wireshark.
"""
#
# Gilbert Ramirez <gram [AT] alumni.rice.edu>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys

from optparse import OptionParser
import subprocess


errors = 0

class Proto:
    """Data for a protocol."""
    def __init__(self, line):
        data = line.split("\t")
        assert len(data) == 3, "expected 3 columns in %s" % data
        assert data[0] == "P"
        self.name = data[1]
        self.abbrev = data[2]

class Field:
    """Data for a field."""
    def __init__(self, line):
        data = line.split("\t")
        assert len(data) == 8, "expected 8 columns in %s" % data
        assert data[0] == "F"
        self.name = data[1]
        self.abbrev = data[2]
        self.ftype = data[3]
        self.parent = data[4]
        self.base = data[5]
        self.bitmask = int(data[6],0)
        self.blurb = data[7]


def gather_data(tshark):
    """Calls tshark and gathers data."""
    proc = subprocess.Popen([tshark, "-G", "fields"],
        stdout=subprocess.PIPE)
    output, error = proc.communicate()

    if proc.returncode != 0:
        sys.exit("Failed: tshark -G fields")

    if sys.version_info[0] >= 3:
        output = output.decode('utf-8')

    lines = output.splitlines()
    protos = [Proto(x) for x in lines if x[0] == "P"]
    fields = [Field(x) for x in lines if x[0] == "F"]

    return protos, fields


def check_fields(fields):
    """Looks for problems in field definitions."""
    global errors
    for field in fields:
        if field.bitmask != 0:
            if field.ftype.find("FT_UINT") != 0 and \
                    field.ftype.find("FT_INT") != 0 and \
                    field.ftype != "FT_BOOLEAN" and \
                    field.ftype != "FT_CHAR":
                print("%s has a bitmask 0x%x but is type %s" % \
                        (field.abbrev, field.bitmask, field.ftype))
                errors += 1

def run(tshark):
    """Run the tests."""
    global errors
    protos, fields = gather_data(tshark)

    check_fields(fields)

    if errors > 0:
        sys.exit("%d errors found" % (errors,))
    else:
        print("Success.")

def main():
    """Parse the command-line."""
    usage = "%prog tshark"
    parser = OptionParser(usage=usage)

    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("Need location of tshark.")

    run(args[0])

if __name__ == "__main__":
    main()
