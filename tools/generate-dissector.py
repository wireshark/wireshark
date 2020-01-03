#!/usr/bin/env python
#
# Copyright 2019, Dario Lombardo <lomato@gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This script generates a Wireshark skeleton dissector, based on the example in the doc/ directory.
#
# Example usage:
#
# generate-dissector.py --name "My Self" --email "myself@example.com" --protoname "The dumb protocol"
#   --protoshortname DUMB --protoabbrev dumb --license GPL-2.0-or-later --years "2019-2020"
#

import os
import argparse
from datetime import datetime

parser = argparse.ArgumentParser(description='The Wireshark Dissector Generator')
parser.add_argument("--name", help="The author of the dissector", required=True)
parser.add_argument("--email", help="The email address of the author", required=True)
parser.add_argument("--protoname", help="The name of the protocol", required=True)
parser.add_argument("--protoshortname", help="The protocol short name", required=True)
parser.add_argument("--protoabbrev", help="The protocol abbreviation", required=True)
parser.add_argument("--license", help="The license for this dissector (please use a SPDX-License-Identifier). If omitted, GPL-2.0-or-later will be used")
parser.add_argument("--years", help="Years of validity for the license. If omitted, the current year will be used")
parser.add_argument("-f", "--force", action='store_true', help="Force overwriting the dissector file if it already exists")

def wsdir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def output_file(args):
    return os.path.join(wsdir(), "epan/dissectors/packet-" + args.protoabbrev + ".c")

def read_skeleton():
    skeletonfile = os.path.join(wsdir(), "doc/packet-PROTOABBREV.c")
    print("Reading skeleton file: " + skeletonfile)
    return open(skeletonfile).read()

def replace_fields(buffer, args):
    print("Replacing fields in skeleton")
    output = buffer\
        .replace("YOUR_NAME", args.name)\
        .replace("YOUR_EMAIL_ADDRESS", args.email)\
        .replace("PROTONAME", args.protoname)\
        .replace("PROTOSHORTNAME", args.protoshortname)\
        .replace("PROTOABBREV", args.protoabbrev)\
        .replace("FIELDNAME", "Sample Field")\
        .replace("FIELDABBREV", "sample_field")\
        .replace("FT_FIELDTYPE", "FT_STRING")\
        .replace("FIELDDISPLAY", "BASE_NONE")\
        .replace("FIELDCONVERT", "NULL")\
        .replace("BITMASK", "0x0")\
        .replace("FIELDDESCR", "NULL")\
        .replace("MAX_NEEDED_FOR_HEURISTICS", "1")\
        .replace("TEST_HEURISTICS_FAIL", "0")\
        .replace("ENC_xxx", "ENC_NA")\
        .replace("EXPERTABBREV", "expert")\
        .replace("PI_GROUP", "PI_PROTOCOL")\
        .replace("PI_SEVERITY", "PI_ERROR")\
        .replace("TEST_EXPERT_condition", "0")\
        .replace("const char *subtree", "\"\"")

    if args.license:
        output = output.replace("LICENSE", args.license)
    else:
        output = output.replace("LICENSE", "GPL-2.0-or-later")

    if args.years:
        output = output.replace("YEARS", args.years)
    else:
        output = output.replace("YEARS", str(datetime.now().year))

    return output

def write_dissector(buffer, args):
    ofile = output_file(args)
    if os.path.isfile(ofile) and not args.force:
        raise Exception("The file " + ofile + " already exists. You're likely overwriting an existing dissector.")
    print("Writing output file: " + ofile)
    return open(ofile, "w").write(buffer)

def patch_makefile(args):
    cmakefile = os.path.join(wsdir(), "epan/dissectors/CMakeLists.txt")
    print("Patching makefile: " + cmakefile)
    output = ""
    patchline = "${CMAKE_CURRENT_SOURCE_DIR}/packet-" + args.protoabbrev + ".c"
    in_group = False
    patched = False
    for line in open(cmakefile):
        line_strip = line.strip()
        if in_group and line_strip == ")":
            in_group = False
        if in_group and not patched and line_strip > patchline:
            output += "\t" + patchline + "\n"
            patched = True
        if line_strip == "set(DISSECTOR_SRC":
            in_group = True
        if line_strip != patchline:
            output += line
    open(cmakefile, "w").write(output)

def print_header():
    print("")
    print("**************************************************")
    print("*   Wireshark skeleton dissector generator       *")
    print("*                                                *")
    print("*   Generate a new dissector for your protocol   *")
    print("*   starting from the skeleton provided in the   *")
    print("*   doc directory.                               *")
    print("*                                                *")
    print("*   Copyright 2019 Dario Lombardo                *")
    print("**************************************************")
    print("")

def print_trailer(args):
    print("")
    print("The skeleton for the dissector of the " + args.protoshortname + " protocol has been generated.")
    print("Please review/extend it to match your specific criterias.")
    print("")

if __name__ == '__main__':
    print_header()
    args = parser.parse_args()
    buffer = replace_fields(read_skeleton(), args)
    write_dissector(buffer, args)
    patch_makefile(args)
    print_trailer(args)
