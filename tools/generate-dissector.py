#!/usr/bin/env python3
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

import argparse
from datetime import datetime
import os


parser = argparse.ArgumentParser(description='The Wireshark Dissector Generator')
parser.add_argument("--name", help="The author of the dissector", required=True)
parser.add_argument("--email", help="The email address of the author", required=True)
parser.add_argument("--protoname", help="The name of the protocol", required=True)
parser.add_argument("--protoshortname", help="The protocol short name", required=True)
parser.add_argument("--protoabbrev", help="The protocol abbreviation", required=True)
parser.add_argument("--license", help="The license for this dissector (please use a SPDX-License-Identifier). If omitted, %(default)s will be used", default="GPL-2.0-or-later")
parser.add_argument("--years", help="Years of validity for the license. If omitted, the current year will be used", default=str(datetime.now().year))
parser.add_argument("-f", "--force", action='store_true', help="Force overwriting the dissector file if it already exists")
parser.add_argument("-p", "--plugin", action='store_true', help="Create as a plugin. Default is to create in epan")


def wsdir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def output_dir(args):
    if args.plugin:
        os.makedirs(os.path.join(wsdir(), "plugins/epan/" + args.protoabbrev), exist_ok=True)
        return os.path.join(wsdir(), "plugins/epan/" + args.protoabbrev)
    return os.path.join(wsdir(), "epan/dissectors")


def output_file(args):
    return os.path.join(output_dir(args), "packet-" + args.protoabbrev + ".c")


def read_skeleton(filename):
    skeletonfile = os.path.join(wsdir(), "doc/" + filename)
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
        .replace("const char *subtree", "\"\"")\
        .replace("LICENSE", args.license)\
        .replace("YEARS", args.years)

    return output


def write_dissector(buffer, args):
    ofile = output_file(args)
    if os.path.isfile(ofile) and not args.force:
        raise Exception("The file " + ofile + " already exists. You're likely overwriting an existing dissector.")
    print("Writing output file: " + ofile)
    return open(ofile, "w").write(buffer)


def patch_makefile(args):
    if args.plugin:
        cmakefile = os.path.join(wsdir(), "CMakeLists.txt")
        patchline = "\t\tplugins/epan/" + args.protoabbrev
        groupstart = "set(PLUGIN_SRC_DIRS"
    else:
        cmakefile = os.path.join(wsdir(), "epan/dissectors/CMakeLists.txt")
        patchline = "\t${CMAKE_CURRENT_SOURCE_DIR}/packet-" + args.protoabbrev + ".c"
        groupstart = "set(DISSECTOR_SRC"
    print("Patching makefile: " + cmakefile)
    output = ""
    in_group = False
    patched = False
    for line in open(cmakefile):
        line_strip = line.strip()
        if in_group and line_strip == ")":
            in_group = False
        if in_group and not patched and line_strip > patchline:
            output += patchline + "\n"
            patched = True
        if line_strip == groupstart:
            in_group = True
        if line_strip != patchline:
            output += line
    open(cmakefile, "w").write(output)


def write_plugin_makefile(args):
    if not args.plugin:
        return True
    buffer = replace_fields(read_skeleton("CMakeLists-PROTOABBREV.txt"), args)
    ofile = os.path.join(output_dir(args), "CMakeLists.txt")
    print("Writing output file: " + ofile)
    return open(ofile, "w").write(buffer)


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
    print("Please review/extend it to match your specific criteria.")
    print("")


if __name__ == '__main__':
    print_header()
    args = parser.parse_args()
    buffer = replace_fields(read_skeleton("packet-PROTOABBREV.c"), args)
    write_dissector(buffer, args)
    patch_makefile(args)
    write_plugin_makefile(args)
    print_trailer(args)
